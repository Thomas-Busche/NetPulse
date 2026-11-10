//! Push-Nachrichten an die installierte NetPulse-App (Web Push, RFC 8030/8291/8292).
//!
//! Der Browser (Android: Chrome/Firefox, iPhone: als App auf dem Home-Bildschirm) meldet sich mit einer
//! Adresse seines Push-Dienstes an. NetPulse verschlüsselt jede Nachricht Ende-zu-Ende für genau dieses
//! Gerät (ECDH P-256 + AES-128-GCM) – der Push-Dienst von Google/Apple/Mozilla sieht nur Chiffretext.
//! Der eigene Absenderschlüssel (VAPID) liegt in `/data/vapid.key`.

use std::{fs, path::Path, time::Duration};

use aes_gcm::{aead::Aead, Aes128Gcm, KeyInit, Nonce};
use anyhow::{anyhow, Context, Result};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use hkdf::Hkdf;
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::sec1::ToEncodedPoint,
    PublicKey, SecretKey,
};
use serde::Serialize;
use serde_json::json;
use sha2::Sha256;

use crate::AppState;

/// Absenderschlüssel (VAPID) des Servers
pub struct Vapid {
    key: SigningKey,
    public_b64: String,
    subject: String,
}

impl Vapid {
    pub fn load_or_create(dir: &Path, subject: String) -> Result<Self> {
        let path = dir.join("vapid.key");
        let key = match fs::read_to_string(&path) {
            Ok(hex_key) => SigningKey::from_slice(&hex::decode(hex_key.trim())?).context("vapid.key ist beschädigt")?,
            // Nur wenn die Datei fehlt – andere Lesefehler dürfen den Schlüssel nicht überschreiben
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                use std::io::Write;
                let key = SigningKey::random(&mut OsRng);
                let mut options = fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                options.open(&path)?.write_all(hex::encode(key.to_bytes()).as_bytes())?;
                key
            }
            Err(e) => return Err(e).context("vapid.key nicht lesbar"),
        };
        let public_b64 = B64.encode(key.verifying_key().to_encoded_point(false).as_bytes());
        Ok(Self { key, public_b64, subject })
    }

    pub fn public_key(&self) -> &str {
        &self.public_b64
    }

    /// Signiertes Token (ES256) für den Push-Dienst
    fn authorization(&self, endpoint: &str) -> Result<String> {
        let url = reqwest::Url::parse(endpoint)?;
        let audience = format!("{}://{}", url.scheme(), url.host_str().ok_or_else(|| anyhow!("Push-Adresse ohne Host"))?);
        let exp = chrono::Utc::now().timestamp() + 12 * 3600;
        let header = B64.encode(r#"{"typ":"JWT","alg":"ES256"}"#);
        let claims = B64.encode(json!({ "aud": audience, "exp": exp, "sub": self.subject }).to_string());
        let input = format!("{header}.{claims}");
        let signature: Signature = self.key.sign(input.as_bytes());
        Ok(format!("vapid t={input}.{}, k={}", B64.encode(signature.to_bytes()), self.public_b64))
    }
}

fn decode(value: &str) -> Result<Vec<u8>> {
    B64.decode(value.trim().trim_end_matches('=').replace('+', "-").replace('/', "_")).context("ungültige Base64-Angabe")
}

/// Verschlüsselt eine Nachricht nach RFC 8291 (Inhaltskodierung „aes128gcm“)
pub fn encrypt(p256dh: &str, auth: &str, payload: &[u8]) -> Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    encrypt_with(&SecretKey::random(&mut OsRng), salt, p256dh, auth, payload)
}

fn encrypt_with(as_secret: &SecretKey, salt: [u8; 16], p256dh: &str, auth: &str, payload: &[u8]) -> Result<Vec<u8>> {
    let ua_public_bytes = decode(p256dh)?;
    let ua_public = PublicKey::from_sec1_bytes(&ua_public_bytes).map_err(|_| anyhow!("ungültiger Geräteschlüssel"))?;
    let auth_secret = decode(auth)?;
    let as_public = as_secret.public_key().to_encoded_point(false);
    let shared = p256::ecdh::diffie_hellman(as_secret.to_nonzero_scalar(), ua_public.as_affine());

    // key_info = "WebPush: info" || 0x00 || ua_public || as_public
    let mut key_info = b"WebPush: info\0".to_vec();
    key_info.extend_from_slice(&ua_public_bytes);
    key_info.extend_from_slice(as_public.as_bytes());
    let mut ikm = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&auth_secret), shared.raw_secret_bytes())
        .expand(&key_info, &mut ikm)
        .map_err(|_| anyhow!("HKDF"))?;

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut cek = [0u8; 16];
    let mut nonce = [0u8; 12];
    hk.expand(b"Content-Encoding: aes128gcm\0", &mut cek).map_err(|_| anyhow!("HKDF"))?;
    hk.expand(b"Content-Encoding: nonce\0", &mut nonce).map_err(|_| anyhow!("HKDF"))?;

    // Ein einziger Datensatz: Nachricht + Trennzeichen 0x02
    let mut plain = payload.to_vec();
    plain.push(2);
    let cipher = Aes128Gcm::new_from_slice(&cek)
        .map_err(|_| anyhow!("AES"))?
        .encrypt(Nonce::from_slice(&nonce), plain.as_ref())
        .map_err(|_| anyhow!("Verschlüsselung fehlgeschlagen"))?;

    let mut body = salt.to_vec();
    body.extend_from_slice(&4096u32.to_be_bytes());
    body.push(65);
    body.extend_from_slice(as_public.as_bytes());
    body.extend_from_slice(&cipher);
    Ok(body)
}

#[derive(Serialize)]
pub struct PushMessage<'a> {
    pub title: &'a str,
    pub body: &'a str,
    /// critical | warning | info | resolved
    pub severity: &'a str,
    /// Wird beim Antippen geöffnet (relativer Pfad in der App)
    pub url: &'a str,
    /// Gleiche Kennung ersetzt eine ältere Nachricht auf dem Gerät
    pub tag: &'a str,
}

#[derive(sqlx::FromRow)]
struct Subscription {
    id: i64,
    endpoint: String,
    p256dh: String,
    auth: String,
}

fn client() -> reqwest::Client {
    reqwest::Client::builder().timeout(Duration::from_secs(15)).user_agent("NetPulse").build().expect("HTTP-Client")
}

/// Ergebnis eines Push-Versands
#[derive(Default, Debug)]
pub struct PushResult {
    pub ok: usize,
    pub failed: usize,
    /// Gründe der Fehlschläge (verständlich, je Gerät)
    pub errors: Vec<String>,
    /// Anzahl der Geräte, an die gesendet werden sollte
    pub devices: usize,
}

impl PushResult {
    /// Zusammenfassung als Fehler, wenn nichts ankam
    pub fn into_result(self) -> Result<usize> {
        if self.devices == 0 {
            anyhow::bail!("Auf keinem Gerät ist Push aktiviert – in der App (Handy) unter „Mein Konto“ auf „Push auf diesem Gerät aktivieren“ tippen");
        }
        if self.ok == 0 {
            anyhow::bail!("an kein Gerät zugestellt: {}", self.errors.join("; "));
        }
        Ok(self.ok)
    }
}

/// Antwort des Push-Dienstes in einen verständlichen Grund übersetzen
fn explain(status: reqwest::StatusCode, body: &str, endpoint: &str) -> String {
    let service = if endpoint.contains("apple.com") {
        "Apple"
    } else if endpoint.contains("googleapis.com") {
        "Google"
    } else if endpoint.contains("mozilla") {
        "Mozilla"
    } else if endpoint.contains("windows.com") || endpoint.contains("microsoft") {
        "Microsoft"
    } else {
        "Push-Dienst"
    };
    let body: String = body.chars().filter(|c| !c.is_control()).take(160).collect();
    let hint = match status.as_u16() {
        400 if body.contains("BadJwtToken") || body.contains("VAPID") => " – Absenderschlüssel abgelehnt (PUBLIC_URL muss mit https:// beginnen)",
        403 => " – Absenderschlüssel passt nicht zu dieser Anmeldung: Push auf dem Handy aus- und wieder einschalten",
        413 => " – Nachricht zu groß",
        429 => " – zu viele Nachrichten, später erneut",
        _ => "",
    };
    format!("{service} antwortete {status}{hint}{}", if body.is_empty() { String::new() } else { format!(" ({body})") })
}

/// An alle angemeldeten Geräte senden (oder nur an die der genannten Benutzer).
/// Abgelaufene Anmeldungen werden gelöscht, Fehler je Gerät gespeichert.
pub async fn send(state: &AppState, users: Option<&[i64]>, message: &PushMessage<'_>) -> Result<PushResult> {
    let subs: Vec<Subscription> =
        sqlx::query_as("SELECT id, endpoint, p256dh, auth FROM push_subscriptions WHERE $1::bigint[] IS NULL OR user_id = ANY($1)")
            .bind(users)
            .fetch_all(&state.db)
            .await?;
    let payload = serde_json::to_vec(message)?;
    let http = client();
    let mut out = PushResult { devices: subs.len(), ..Default::default() };
    for sub in subs {
        let result = async {
            let body = encrypt(&sub.p256dh, &sub.auth, &payload)?;
            let response = http
                .post(&sub.endpoint)
                .header("TTL", "86400")
                // „high“ = sofort zustellen, auch wenn das Handy im Energiesparmodus (Doze) ist
                .header("Urgency", if matches!(message.severity, "critical" | "warning") { "high" } else { "normal" })
                .header("Topic", message.tag.chars().filter(char::is_ascii_alphanumeric).take(32).collect::<String>())
                .header("Content-Encoding", "aes128gcm")
                .header("Content-Type", "application/octet-stream")
                .header("Authorization", state.vapid.authorization(&sub.endpoint)?)
                .body(body)
                .send()
                .await?;
            let status = response.status();
            let body = if status.is_success() { String::new() } else { response.text().await.unwrap_or_default() };
            Ok::<_, anyhow::Error>((status, body))
        }
        .await;
        let error = match result {
            Ok((status, _)) if status.is_success() => {
                out.ok += 1;
                let _ = sqlx::query("UPDATE push_subscriptions SET last_ok_at = now(), last_error = NULL WHERE id = $1")
                    .bind(sub.id)
                    .execute(&state.db)
                    .await;
                continue;
            }
            // 404/410: Gerät hat sich abgemeldet oder App wurde entfernt
            Ok((status, _)) if status.as_u16() == 404 || status.as_u16() == 410 => {
                tracing::info!("Push-Anmeldung {} ist abgelaufen und wird entfernt", sub.id);
                let _ = sqlx::query("DELETE FROM push_subscriptions WHERE id = $1").bind(sub.id).execute(&state.db).await;
                "Anmeldung abgelaufen (App entfernt oder Browserdaten gelöscht) – Push auf dem Handy neu aktivieren".to_string()
            }
            Ok((status, body)) => explain(status, &body, &sub.endpoint),
            Err(e) => format!("Push-Dienst nicht erreichbar: {e:#}"),
        };
        out.failed += 1;
        tracing::warn!("Push an Gerät {}: {error}", sub.id);
        let _ = sqlx::query("UPDATE push_subscriptions SET last_error = $2, last_error_at = now() WHERE id = $1")
            .bind(sub.id)
            .bind(&error)
            .execute(&state.db)
            .await;
        out.errors.push(error);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Beispiel aus RFC 8291, Anhang A – muss Byte für Byte übereinstimmen
    #[test]
    fn rfc8291_beispiel() {
        let as_secret = SecretKey::from_slice(&decode("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw").unwrap()).unwrap();
        let salt: [u8; 16] = decode("DGv6ra1nlYgDCS1FRnbzlw").unwrap().try_into().unwrap();
        let body = encrypt_with(
            &as_secret,
            salt,
            "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
            "BTBZMqHH6r4Tts7J_aSIgg",
            b"When I grow up, I want to be a watermelon",
        )
        .unwrap();
        assert_eq!(
            B64.encode(body),
            "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
        );
    }

    #[test]
    fn vapid_token() {
        let dir = std::env::temp_dir().join(format!("np-vapid-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let v = Vapid::load_or_create(&dir, "mailto:test@example.org".into()).unwrap();
        let again = Vapid::load_or_create(&dir, "mailto:test@example.org".into()).unwrap();
        assert_eq!(v.public_key(), again.public_key());
        assert_eq!(decode(v.public_key()).unwrap().len(), 65);
        let auth = v.authorization("https://fcm.googleapis.com/fcm/send/abc").unwrap();
        assert!(auth.starts_with("vapid t=") && auth.contains(", k="));
        let _ = fs::remove_dir_all(dir);
    }
}
