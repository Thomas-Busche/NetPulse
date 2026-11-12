//! NetPulse – agentenloses Netzwerk-Monitoring.
//!
//! Aufbau:
//! - `api`     : REST-API für die Weboberfläche (axum)
//! - `auth`    : Login, Sitzungen, Passwort-Hashing, Rollen
//! - `scanner` : Geräteerkennung (Discovery) und Statusprüfung (Monitor)
//! - `collect` : tiefe Abfragen über SNMP und SSH (Inventar, Auslastung)
//! - `alerts`  : Alarmregeln und Benachrichtigungen
//! - `classify`: Gerätetyp-Erkennung, `oui`: Hersteller aus der MAC-Adresse
//! - `vault`   : verschlüsselte Ablage für Zugangsdaten
//! - `audit`   : Protokoll, wer wann was getan hat
//! - `config`  : Einstellungen aus Umgebungsvariablen

mod alerts;
mod api;
mod audit;
mod auth;
mod backup;
mod checks;
mod classify;
mod collect;
mod config;
mod energy;
mod error;
mod integration;
mod logbuf;
mod maintenance;
mod mib;
mod oui;
mod perf;
mod probe;
mod push;
mod routers;
mod scanner;
mod sites;
mod syslog;
mod totp;
mod vault;

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::sync::mpsc;
use tracing_subscriber::{prelude::*, EnvFilter};

use crate::{config::Config, scanner::ScanRequest, vault::Vault};

/// Gemeinsamer Zustand, den jeder Request-Handler und jeder Hintergrund-Task bekommt.
/// `Clone` ist billig: Alles darin ist ein Zeiger mit Referenzzählung (`Arc`, `PgPool`).
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Arc<Config>,
    /// Aufträge an die Discovery („Jetzt scannen“, neues Netz)
    pub scan_tx: mpsc::UnboundedSender<ScanRequest>,
    pub scan_progress: Arc<scanner::ScanProgress>,
    /// Geräte-IDs für eine sofortige tiefe Abfrage
    pub poll_tx: mpsc::UnboundedSender<i64>,
    pub vault: Arc<Vault>,
    /// Letzte Zählerstände für die Live-Ansicht
    pub live: Arc<collect::live::LiveCache>,
    /// Laufende Suchläufe für Zugangsdaten
    pub cred_jobs: Arc<collect::check::Jobs>,
    pub login_limiter: Arc<auth::LoginLimiter>,
    /// Live-Meldungen an die Browser (Server-Sent Events)
    pub hub: Arc<collect::fast::Hub>,
    /// Absenderschlüssel für Push-Nachrichten an die App
    pub vapid: Arc<push::Vapid>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Log: auf die Konsole (Container-Log) und zusätzlich in den Speicher für die Seite „System-Log“.
    // Ein gemeinsamer Filter; die einzelnen Abfrageschritte („debug“) landen nur im Speicher.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn,tower_http=warn"))
        .add_directive("netpulse::inventar=debug".parse().expect("Log-Filter"));
    let console_only_info = tracing_subscriber::filter::filter_fn(|meta| meta.target() != "netpulse::inventar" || *meta.level() <= tracing::Level::INFO);
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_filter(console_only_info))
        .with(logbuf::BufferLayer)
        .init();

    // Probe-Betrieb: „netpulse probe“ – ohne Datenbank, meldet an einen NetPulse-Server
    if std::env::args().nth(1).as_deref() == Some("probe") {
        return probe::run().await;
    }

    let config = Arc::new(Config::from_env()?);
    let db = connect_db(&config.database_url, config.db_max_connections).await?;
    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .context("Datenbank-Migration fehlgeschlagen")?;
    // Notfall: „netpulse reset-password <benutzer> [--2fa]“ (nur mit Zugriff auf den Docker-Host möglich)
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("reset-password") {
        return reset_password_cli(&db, &args[2..]).await;
    }
    apply_retention(&db, &config).await?;
    bootstrap(&db, &config).await?;

    let vault = Vault::open(&config.data_dir, config.secret_key.as_deref())
        .context("Tresor für Zugangsdaten konnte nicht geöffnet werden")?;
    let vapid_subject = config
        .public_url
        .clone()
        .filter(|u| u.starts_with("https://"))
        .unwrap_or_else(|| "https://github.com/Sirbuschi2003/NetPulse".into());
    let vapid = push::Vapid::load_or_create(std::path::Path::new(&config.data_dir), vapid_subject)
        .context("Push-Schlüssel (vapid.key) konnte nicht angelegt werden")?;
    let (scan_tx, scan_rx) = mpsc::unbounded_channel();
    let (poll_tx, poll_rx) = mpsc::unbounded_channel();
    let state = AppState {
        db: db.clone(),
        config: config.clone(),
        scan_tx,
        scan_progress: Arc::new(scanner::ScanProgress::default()),
        poll_tx,
        vault: Arc::new(vault),
        live: Arc::new(collect::live::LiveCache::default()),
        cred_jobs: Arc::new(collect::check::Jobs::default()),
        login_limiter: Arc::new(auth::LoginLimiter::new(db.clone())),
        hub: Arc::new(collect::fast::Hub::default()),
        vapid: Arc::new(vapid),
    };

    // Hintergrund-Tasks: laufen parallel zum Webserver
    let pinger = Arc::new(scanner::net::Pinger::new());
    tokio::spawn(scanner::discovery::run(state.clone(), pinger.clone(), scan_rx));
    tokio::spawn(scanner::monitor::run(state.clone(), pinger));
    tokio::spawn(collect::run(state.clone(), poll_rx));
    tokio::spawn(collect::fast::run(state.clone()));
    tokio::spawn(collect::unifi_loop(state.clone()));
    tokio::spawn(alerts::run(state.clone()));
    tokio::spawn(alerts::deliver::run(state.clone()));
    tokio::spawn(checks::run(state.clone()));
    tokio::spawn(energy::run(state.clone()));
    tokio::spawn(backup::run(state.clone()));
    tokio::spawn(integration::run(state.clone()));
    syslog::start(&state);
    tokio::spawn(mib::load(state.db.clone()));
    tokio::spawn(maintenance(state.clone()));

    let listener = tokio::net::TcpListener::bind(&config.listen_addr)
        .await
        .with_context(|| {
            format!(
                "Kann {} nicht öffnen – ist der Port schon von einem anderen Dienst belegt? \
                 Dann in der Konfiguration APP_PORT auf einen freien Port setzen.",
                config.listen_addr
            )
        })?;
    tracing::info!("NetPulse läuft auf http://{}", config.listen_addr);
    axum::serve(listener, api::router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Verbindet sich mit PostgreSQL. Beim Start des Containers ist die DB evtl. noch nicht bereit,
/// deshalb wird es eine Minute lang wiederholt.
async fn connect_db(url: &str, max_connections: u32) -> Result<PgPool> {
    let mut attempt = 0;
    loop {
        let result = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(Duration::from_secs(10))
            .connect(url)
            .await;
        match result {
            Ok(pool) => return Ok(pool),
            Err(e) if attempt < 30 => {
                attempt += 1;
                tracing::warn!("Datenbank noch nicht erreichbar ({e}), neuer Versuch in 2 s …");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(e) => return Err(e).context("Keine Verbindung zur Datenbank"),
        }
    }
}

/// Aufbewahrungsfrist der Messwerte setzen (Datensparsamkeit, DSGVO Art. 5).
/// TimescaleDB löscht ältere Daten dann selbstständig.
async fn apply_retention(db: &PgPool, config: &Config) -> Result<()> {
    sqlx::query("SELECT remove_retention_policy('device_metrics', if_exists => true)")
        .execute(db)
        .await?;
    sqlx::query("SELECT add_retention_policy('device_metrics', make_interval(days => $1))")
        .bind(config.metrics_retention_days)
        .execute(db)
        .await?;
    sqlx::query("SELECT remove_retention_policy('interface_stats', if_exists => true)")
        .execute(db)
        .await?;
    sqlx::query("SELECT add_retention_policy('interface_stats', make_interval(days => $1))")
        .bind(config.metrics_retention_days)
        .execute(db)
        .await?;
    sqlx::query("SELECT remove_retention_policy('check_results', if_exists => true)")
        .execute(db)
        .await?;
    sqlx::query("SELECT add_retention_policy('check_results', make_interval(days => $1))")
        .bind(config.metrics_retention_days)
        .execute(db)
        .await?;
    sqlx::query("SELECT remove_retention_policy('syslog_messages', if_exists => true)")
        .execute(db)
        .await?;
    sqlx::query("SELECT add_retention_policy('syslog_messages', make_interval(days => $1))")
        .bind(config.syslog_retention_days)
        .execute(db)
        .await?;
    sqlx::query("SELECT remove_retention_policy('device_stats', if_exists => true)")
        .execute(db)
        .await?;
    sqlx::query("SELECT add_retention_policy('device_stats', make_interval(days => $1))")
        .bind(config.metrics_retention_days)
        .execute(db)
        .await?;
    Ok(())
}

/// Erster Start: Admin-Konto und ggf. Netze aus der Konfiguration anlegen.
/// Neues zufälliges Passwort für einen Benutzer setzen, alle seine Sitzungen beenden; mit `--2fa` auch die
/// Zwei-Faktor-Anmeldung zurücksetzen. Aufruf: `docker exec -it netpulse-app netpulse reset-password admin`
async fn reset_password_cli(db: &PgPool, args: &[String]) -> Result<()> {
    let Some(username) = args.iter().find(|a| !a.starts_with("--")) else {
        let names: Vec<(String, String)> = sqlx::query_as(
            "SELECT u.username, coalesce(string_agg(DISTINCT r.name, ', '), 'ohne Rolle')
               FROM users u
               LEFT JOIN role_assignments a ON a.user_id = u.id
               LEFT JOIN roles r ON r.id = a.role_id
              GROUP BY u.username ORDER BY u.username",
        )
        .fetch_all(db)
        .await?;
        eprintln!("Aufruf: netpulse reset-password <benutzer> [--2fa]");
        eprintln!("Vorhandene Benutzer:");
        for (name, role) in names {
            eprintln!("  {name} ({role})");
        }
        return Ok(());
    };
    let reset_2fa = args.iter().any(|a| a == "--2fa");
    let password = auth::random_token(12);
    let hash = auth::hash_password(password.clone()).await?;
    let updated = sqlx::query(
        "UPDATE users SET password_hash = $2, must_change_password = true,
                totp_enabled = CASE WHEN $3 THEN false ELSE totp_enabled END,
                totp_secret = CASE WHEN $3 THEN NULL ELSE totp_secret END,
                totp_last_step = CASE WHEN $3 THEN NULL ELSE totp_last_step END
          WHERE username = lower($1)",
    )
    .bind(username)
    .bind(&hash)
    .bind(reset_2fa)
    .execute(db)
    .await?;
    if updated.rows_affected() == 0 {
        anyhow::bail!("Benutzer „{username}“ gibt es nicht");
    }
    sqlx::query("DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = lower($1))").bind(username).execute(db).await?;
    // Notfall: auch die Anmeldesperre nach Fehlversuchen aufheben, sonst hilft das neue Passwort erst nach 15 Minuten
    sqlx::query("DELETE FROM login_attempts").execute(db).await?;
    audit::log(db, None, Some(username), "password_reset_cli", serde_json::json!({ "reset_2fa": reset_2fa })).await;
    eprintln!("Neues Passwort für „{username}“: {password} (Anmeldesperre aufgehoben)");
    if reset_2fa {
        eprintln!("Zwei-Faktor-Anmeldung wurde zurückgesetzt – bitte nach der Anmeldung neu einrichten.");
    }
    eprintln!("Nach der Anmeldung muss unter „Mein Konto“ ein eigenes Passwort gesetzt werden.");
    Ok(())
}

async fn bootstrap(db: &PgPool, config: &Config) -> Result<()> {
    let (users,): (i64,) = sqlx::query_as("SELECT count(*) FROM users").fetch_one(db).await?;
    if users == 0 {
        // Feste Erst-Anmeldung (steht im Handbuch); das Passwort muss danach geändert werden
        let username = auth::DEFAULT_ADMIN_USER;
        let hash = auth::hash_password(auth::DEFAULT_ADMIN_PASSWORD.to_string()).await?;
        let (user_id,): (i64,) = sqlx::query_as(
            "INSERT INTO users (username, password_hash, must_change_password) VALUES ($1, $2, $3) RETURNING id",
        )
        .bind(username)
        .bind(hash)
        .bind(true)
        .fetch_one(db)
        .await?;
        sqlx::query(
            "INSERT INTO role_assignments (role_id, user_id, site_id)
             SELECT id, $1, NULL FROM roles WHERE all_permissions ORDER BY id LIMIT 1",
        )
        .bind(user_id)
        .execute(db)
        .await?;
        tracing::info!("Erster Admin '{username}' mit dem Standardkennwort angelegt (siehe Handbuch) – muss nach der ersten Anmeldung geändert werden");
    }

    let (networks,): (i64,) = sqlx::query_as("SELECT count(*) FROM networks").fetch_one(db).await?;
    if networks == 0 {
        // Leer oder „auto“: direkt angeschlossene Netze des Hosts übernehmen; „off“/„none“: nichts freigeben
        let wanted = &config.initial_networks;
        let disabled = wanted.iter().any(|n| matches!(n.to_lowercase().as_str(), "off" | "none" | "aus"));
        if !disabled && (wanted.is_empty() || wanted.iter().any(|n| n.eq_ignore_ascii_case("auto"))) {
            let found = scanner::local::detect();
            if found.is_empty() {
                tracing::warn!("Keine eigenen Netze erkannt (läuft der Container mit network_mode: host?) – bitte unter „Netzwerke“ eintragen");
            }
            for n in found {
                sqlx::query(
                    "INSERT INTO networks (cidr, name, gateway, description) VALUES ($1::cidr, $2, $3::inet, $4) ON CONFLICT DO NOTHING",
                )
                .bind(&n.cidr)
                .bind(format!("Automatisch erkannt ({})", n.interface))
                .bind(n.gateway.as_deref())
                .bind(if n.narrowed { "Größeres Netz – nur das /24 um die eigene Adresse übernommen" } else { "" })
                .execute(db)
                .await?;
                tracing::info!("Netz {} an {} automatisch erkannt und zum Scannen freigegeben", n.cidr, n.interface);
            }
        }
        for cidr in wanted.iter().filter(|n| !matches!(n.to_lowercase().as_str(), "auto" | "off" | "none" | "aus")) {
            // Ein ungültiger Eintrag soll den Start nicht verhindern – das Netz kann
            // danach in der Oberfläche korrekt angelegt werden.
            let (addr, prefix) = match scanner::net::parse_cidr(cidr) {
                Ok(net) => net,
                Err(e) => {
                    tracing::warn!("SCAN_NETWORKS: '{cidr}' übersprungen – {e}");
                    continue;
                }
            };
            sqlx::query("INSERT INTO networks (cidr, name) VALUES ($1::cidr, $2) ON CONFLICT DO NOTHING")
                .bind(format!("{addr}/{prefix}"))
                .bind("Aus Konfiguration")
                .execute(db)
                .await?;
            tracing::info!("Netz {addr}/{prefix} zum Scannen freigegeben");
        }
    }
    Ok(())
}

/// Stündliche Aufräumarbeiten: abgelaufene Sitzungen, alte Ereignisse und Audit-Einträge löschen.
async fn maintenance(state: AppState) {
    let mut tick = tokio::time::interval(Duration::from_secs(3600));
    loop {
        tick.tick().await;
        let config = &state.config;
        let result = async {
            sqlx::query("DELETE FROM sessions WHERE expires_at < now()")
                .execute(&state.db)
                .await?;
            sqlx::query("DELETE FROM events WHERE time < now() - make_interval(days => $1)")
                .bind(config.events_retention_days)
                .execute(&state.db)
                .await?;
            sqlx::query("DELETE FROM alerts WHERE resolved_at < now() - make_interval(days => $1)")
                .bind(config.events_retention_days)
                .execute(&state.db)
                .await?;
            sqlx::query("DELETE FROM audit_log WHERE time < now() - make_interval(days => $1)")
                .bind(config.audit_retention_days)
                .execute(&state.db)
                .await?;
            auth::LoginLimiter::cleanup(&state.db).await;
            sqlx::query("DELETE FROM oidc_states WHERE created_at < now() - interval '1 hour'")
                .execute(&state.db)
                .await?;
            Ok::<_, sqlx::Error>(())
        }
        .await;
        if let Err(e) = result {
            tracing::error!("Wartung fehlgeschlagen: {e}");
        }
    }
}

/// Wartet auf Strg+C oder SIGTERM (wird von `docker stop` gesendet).
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut s) = signal(SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("Beende NetPulse …");
}
