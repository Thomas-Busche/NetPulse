//! Tresor für Geheimnisse (Passwörter, SNMP-Communities, SSH-Schlüssel, Webhook-Tokens).
//!
//! Verschlüsselt wird mit AES-256-GCM (authentifizierte Verschlüsselung: Manipulationen fallen auf).
//! Der Schlüssel liegt **nicht** in der Datenbank, sondern in `DATA_DIR/secret.key`
//! oder in der Umgebungsvariable `SECRET_KEY`. Ein Datenbank-Backup allein verrät also nichts.
//!
//! Schlüsseltausch (`rotate`): neuer Schlüssel, alle Geheimnisse in einer Transaktion neu verschlüsseln,
//! alter Schlüssel bleibt als `secret.key.old-<Zeit>` liegen. Nur mit Schlüsseldatei (nicht mit `SECRET_KEY`).

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        RwLock,
    },
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{de::DeserializeOwned, Serialize};

pub struct Vault {
    cipher: RwLock<Aes256Gcm>,
    /// Schlüsseldatei; `None`, wenn der Schlüssel aus `SECRET_KEY` kommt (dann kein Tausch möglich)
    key_path: Option<PathBuf>,
    /// Während des Tauschs nichts neu verschlüsseln (sonst wäre es mit dem alten Schlüssel gesichert)
    rotating: AtomicBool,
}

/// Spalten mit verschlüsselten Werten: (Tabelle, Spalte)
const SEALED_COLUMNS: &[(&str, &str)] = &[("credentials", "secret"), ("notification_channels", "config"), ("users", "totp_secret")];
/// Einstellungen mit verschlüsselten Feldern: (Schlüssel, Feld im JSON)
const SEALED_SETTINGS: &[(&str, &str)] = &[("smtp", "sealed"), ("backup_auto", "password_sealed"), ("oidc", "client_secret_sealed")];

fn seal_with<T: Serialize>(cipher: &Aes256Gcm, value: &T) -> Result<String> {
    let plain = serde_json::to_vec(value)?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let sealed = cipher
        .encrypt(Nonce::from_slice(&nonce), plain.as_slice())
        .map_err(|_| anyhow!("Verschlüsselung fehlgeschlagen"))?;
    let mut out = nonce.to_vec();
    out.extend(sealed);
    Ok(B64.encode(out))
}

fn open_with<T: DeserializeOwned>(cipher: &Aes256Gcm, sealed: &str) -> Result<T> {
    let raw = B64.decode(sealed).context("Tresor-Eintrag beschädigt")?;
    if raw.len() < 13 {
        bail!("Tresor-Eintrag beschädigt");
    }
    let (nonce, data) = raw.split_at(12);
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce), data)
        .map_err(|_| anyhow!("Entschlüsselung fehlgeschlagen – wurde der Tresor-Schlüssel (secret.key) ausgetauscht?"))?;
    Ok(serde_json::from_slice(&plain)?)
}

/// Datei nur für den Besitzer lesbar anlegen
fn write_private(path: &Path, content: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).with_context(|| format!("{} nicht schreibbar", path.display()))?;
    file.write_all(content)?;
    file.sync_all()?;
    Ok(())
}

impl Vault {
    /// Lädt den Schlüssel aus `SECRET_KEY` oder `data_dir/secret.key`; legt ihn beim ersten Start an.
    pub fn open(data_dir: &str, secret_key: Option<&str>) -> Result<Self> {
        let (key_bytes, key_path) = match secret_key {
            Some(hex_key) => (hex::decode(hex_key.trim()).context("SECRET_KEY muss aus 64 Hex-Zeichen bestehen")?, None),
            None => (load_or_create_key_file(Path::new(data_dir))?, Some(Path::new(data_dir).join("secret.key"))),
        };
        if key_bytes.len() != 32 {
            bail!("Der Tresor-Schlüssel muss 32 Byte (64 Hex-Zeichen) lang sein");
        }
        Ok(Self {
            cipher: RwLock::new(Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes))),
            key_path,
            rotating: AtomicBool::new(false),
        })
    }

    /// Verschlüsselt einen beliebigen serialisierbaren Wert → Base64(Nonce ‖ Chiffrat)
    pub fn seal<T: Serialize>(&self, value: &T) -> Result<String> {
        if self.rotating.load(Ordering::SeqCst) {
            bail!("Der Tresor-Schlüssel wird gerade getauscht – bitte gleich noch einmal versuchen");
        }
        seal_with(&self.cipher.read().unwrap(), value)
    }

    pub fn open_value<T: DeserializeOwned>(&self, sealed: &str) -> Result<T> {
        open_with(&self.cipher.read().unwrap(), sealed)
    }

    /// Kann der Schlüssel in der Oberfläche getauscht werden?
    pub fn can_rotate(&self) -> bool {
        self.key_path.is_some()
    }

    /// Neuen Schlüssel erzeugen und alle Geheimnisse damit neu verschlüsseln. Liefert die Zahl der
    /// umgeschlüsselten Einträge und den Pfad, unter dem der alte Schlüssel aufbewahrt wird.
    pub async fn rotate(&self, db: &sqlx::PgPool) -> Result<(usize, PathBuf)> {
        let Some(path) = self.key_path.clone() else {
            bail!("Der Schlüssel kommt aus SECRET_KEY – bitte dort tauschen (alter Schlüssel nötig, um die Daten umzuschlüsseln)");
        };
        if self.rotating.swap(true, Ordering::SeqCst) {
            bail!("Ein Schlüsseltausch läuft bereits");
        }
        let result = self.rotate_inner(db, &path).await;
        self.rotating.store(false, Ordering::SeqCst);
        result
    }

    async fn rotate_inner(&self, db: &sqlx::PgPool, path: &Path) -> Result<(usize, PathBuf)> {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        let new_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let old_cipher = self.cipher.read().unwrap().clone();
        let reseal = |sealed: &str| -> Result<String> { seal_with(&new_cipher, &open_with::<serde_json::Value>(&old_cipher, sealed)?) };

        let mut tx = db.begin().await?;
        let mut count = 0;
        for (table, column) in SEALED_COLUMNS {
            // Tabellen- und Spaltennamen stammen aus der festen Liste oben
            let rows: Vec<(i64, String)> = sqlx::query_as(&format!("SELECT id, {column} FROM {table} WHERE {column} IS NOT NULL FOR UPDATE"))
                .fetch_all(&mut *tx)
                .await?;
            for (id, sealed) in rows {
                let fresh = reseal(&sealed).with_context(|| format!("{table} #{id} ist mit dem jetzigen Schlüssel nicht lesbar – Tausch abgebrochen"))?;
                sqlx::query(&format!("UPDATE {table} SET {column} = $2 WHERE id = $1")).bind(id).bind(fresh).execute(&mut *tx).await?;
                count += 1;
            }
        }
        for (key_name, field) in SEALED_SETTINGS {
            let row: Option<(serde_json::Value,)> = sqlx::query_as("SELECT value FROM settings WHERE key = $1 FOR UPDATE")
                .bind(key_name)
                .fetch_optional(&mut *tx)
                .await?;
            let Some((mut value,)) = row else { continue };
            let Some(sealed) = value[*field].as_str().map(str::to_string) else { continue };
            value[*field] = serde_json::Value::String(reseal(&sealed).with_context(|| format!("Einstellung „{key_name}“ ist nicht lesbar – Tausch abgebrochen"))?);
            sqlx::query("UPDATE settings SET value = $2 WHERE key = $1").bind(key_name).bind(&value).execute(&mut *tx).await?;
            count += 1;
        }

        // Erst die Dateien vorbereiten, dann festschreiben, dann umbenennen (atomar im selben Verzeichnis)
        let staged = path.with_extension("key.new");
        write_private(&staged, hex::encode(key).as_bytes())?;
        let backup = path.with_extension(format!("key.old-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S")));
        fs::copy(path, &backup).with_context(|| format!("Alter Schlüssel konnte nicht nach {} gesichert werden", backup.display()))?;
        if let Err(e) = tx.commit().await {
            let _ = fs::remove_file(&staged);
            return Err(e.into());
        }
        fs::rename(&staged, path).with_context(|| {
            format!("Neuer Schlüssel liegt in {}, konnte aber nicht nach {} verschoben werden – bitte von Hand umbenennen!", staged.display(), path.display())
        })?;
        *self.cipher.write().unwrap() = new_cipher;
        tracing::warn!("Tresor-Schlüssel getauscht ({count} Einträge). Alter Schlüssel: {} – neue secret.key mitsichern!", backup.display());
        Ok((count, backup))
    }
}

fn load_or_create_key_file(dir: &Path) -> Result<Vec<u8>> {
    let path = dir.join("secret.key");
    if path.exists() {
        let text = fs::read_to_string(&path).with_context(|| format!("{} nicht lesbar", path.display()))?;
        return hex::decode(text.trim()).with_context(|| format!("{} ist ungültig", path.display()));
    }
    fs::create_dir_all(dir).with_context(|| format!("Verzeichnis {} nicht anlegbar", dir.display()))?;
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .with_context(|| format!("{} nicht anlegbar – ist DATA_DIR als Volume eingebunden?", path.display()))?;
    file.write_all(hex::encode(key).as_bytes())?;
    tracing::warn!(
        "Neuer Tresor-Schlüssel erzeugt: {}. Diese Datei unbedingt mitsichern – ohne sie sind gespeicherte Zugangsdaten nicht mehr lesbar.",
        path.display()
    );
    Ok(key.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verschluesseln_und_entschluesseln() {
        let vault = Vault::open("/nicht/benutzt", Some(&"ab".repeat(32))).unwrap();
        let sealed = vault.seal(&serde_json::json!({ "password": "geheim" })).unwrap();
        assert!(!sealed.contains("geheim"));
        let value: serde_json::Value = vault.open_value(&sealed).unwrap();
        assert_eq!(value["password"], "geheim");

        let other = Vault::open("/nicht/benutzt", Some(&"cd".repeat(32))).unwrap();
        assert!(other.open_value::<serde_json::Value>(&sealed).is_err());
        assert!(!vault.can_rotate());
    }

    #[test]
    fn umschluesseln() {
        let a = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&[1u8; 32]));
        let b = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&[2u8; 32]));
        let sealed = seal_with(&a, &"geheim").unwrap();
        let fresh = seal_with(&b, &open_with::<String>(&a, &sealed).unwrap()).unwrap();
        assert_eq!(open_with::<String>(&b, &fresh).unwrap(), "geheim");
        assert!(open_with::<String>(&a, &fresh).is_err());
    }
}
