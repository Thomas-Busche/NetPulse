//! REST-API unter `/api/…` und Auslieferung der Weboberfläche.

mod admin;
mod alerts;
mod backup;
mod checks;
mod credentials;
mod dashboard;
mod devices;
mod energy;
mod integrations;
mod oidc;
mod probes;
mod public;
mod session;
mod sites;
mod stream;
mod users;

use axum::{
    extract::State,
    http::{header, HeaderValue, StatusCode},
    middleware,
    routing::{delete, get, post, put},
    Router,
};
use tower_http::{services::ServeDir, set_header::SetResponseHeaderLayer, trace::TraceLayer};

use crate::{auth, AppState};

pub fn router(state: AppState) -> Router {
    let api = Router::new()
        // Anmeldung
        .route("/login", post(session::login))
        .route("/oidc/info", get(oidc::info))
        .route("/settings/oidc", get(oidc::get_settings).put(oidc::put_settings))
        .route("/logout", post(session::logout))
        .route("/me", get(session::me))
        .route("/me/password", post(session::change_password))
        .route("/me/totp", get(session::totp_status))
        .route("/me/sessions", get(session::sessions))
        .route("/me/sessions/others", delete(session::end_other_sessions))
        .route("/me/sessions/{id}", delete(session::end_session))
        .route("/me/totp/setup", post(session::totp_setup))
        .route("/me/totp/enable", post(session::totp_enable))
        .route("/me/totp/disable", post(session::totp_disable))
        .route("/me/reauth", post(session::reauth))
        .route("/me/tokens", get(users::list_tokens).post(users::create_token))
        .route("/me/tokens/{id}", delete(users::delete_token))
        .route("/push/key", get(session::push_key))
        .route("/push/subscribe", post(session::push_subscribe))
        .route("/push/unsubscribe", post(session::push_unsubscribe))
        .route("/push/devices", get(session::push_devices))
        .route("/push/test", post(session::push_test))
        .route("/push/ack", post(session::push_ack))
        // Geräte & Status
        .route("/summary", get(devices::summary))
        .route("/devices", get(devices::list).post(devices::create))
        .route("/devices/tags", get(devices::tags))
        .route("/devices/{id}", get(devices::detail).patch(devices::update).delete(devices::remove))
        .route("/devices/{id}/credentials", put(devices::set_credentials))
        .route("/devices/{id}/poll", post(devices::poll_now))
        .route("/devices/{id}/diagnose", get(devices::diagnose).post(devices::diagnose_now))
        .route("/devices/{id}/ssh-key", delete(devices::reset_ssh_key))
        .route("/devices/{id}/live", get(devices::live))
        .route("/devices/{id}/interfaces/history", get(devices::interface_history))
        .route("/devices/{id}/snmp", get(devices::snmp_explorer))
        .route("/events", get(devices::events))
        .route("/clients", get(devices::unifi_clients))
        .route("/clients/import", post(devices::unifi_import))
        .route("/clients/import/preview", get(devices::import_preview))
        .route("/devices/imported", get(devices::imported))
        .route("/devices/bulk-delete", post(devices::bulk_delete))
        .route("/unifi/clients", get(devices::unifi_clients))
        .route("/energy", get(energy::report))
        .route("/energy/settings", get(energy::get_settings).put(energy::set_settings))
        .route("/topology", get(public::topology))
        .route("/public/status", get(public::public_status))
        .route("/settings/status-page", get(public::get_config).put(public::set_config))
        .route("/checks", get(checks::list).post(checks::create))
        .route("/checks/{id}", axum::routing::patch(checks::update).delete(checks::remove))
        .route("/checks/{id}/run", post(checks::run_now))
        .route("/checks/{id}/history", get(checks::history))
        .route("/alerts", get(alerts::list_alerts))
        .route("/alerts/{id}/ack", post(alerts::acknowledge))
        // Sektoren & Leitstand
        .route("/sites", get(sites::list).post(sites::create))
        .route("/sites/status", get(sites::status))
        .route("/sites/{id}", axum::routing::patch(sites::update).delete(sites::remove))
        .route("/sites/{id}/devices", post(sites::move_devices))
        .route("/problems", get(sites::problems))
        // Dashboard (pro Benutzer)
        .route("/dashboard", get(dashboard::load).put(dashboard::save))
        .route("/pulse", get(dashboard::pulse))
        .route("/dashboards", get(dashboard::list_views).post(dashboard::create_view))
        .route("/dashboards/{id}", put(dashboard::update_view).delete(dashboard::delete_view))
        // Netze & Scans
        .route("/networks", get(admin::list_networks).post(admin::add_network))
        .route("/networks/detect", get(admin::detect_networks))
        .route("/networks/{id}", axum::routing::patch(admin::update_network).delete(admin::delete_network))
        .route("/networks/{id}/scan", post(admin::scan_network))
        .route("/probes", get(probes::list).post(probes::create))
        .route("/probes/{id}", axum::routing::patch(probes::update).delete(probes::remove))
        .route("/probes/{id}/token", post(probes::new_key))
        .route("/scan", post(admin::trigger_scan))
        .route("/scan/status", get(admin::scan_status))
        .route("/settings/discovery", get(admin::get_discovery).put(admin::set_discovery))
        .route("/settings/live", get(admin::get_live).put(admin::set_live))
        .route("/settings/security", get(admin::get_security).put(admin::set_security))
        .route("/stream", get(stream::events))
        // Zugangsdaten
        .route("/credentials", get(credentials::list).post(credentials::create))
        .route("/credentials/{id}", axum::routing::patch(credentials::update).delete(credentials::remove))
        .route("/credentials/{id}/test", post(credentials::test))
        .route("/credentials/{id}/scan", post(credentials::scan).get(credentials::scan_status))
        .route("/credentials/{id}/devices", get(credentials::devices).put(credentials::set_devices))
        // Alarmierung
        .route("/channels", get(alerts::list_channels).post(alerts::create_channel))
        .route("/channels/{id}", axum::routing::patch(alerts::update_channel).delete(alerts::delete_channel))
        .route("/channels/{id}/test", post(alerts::test_channel))
        .route("/settings/smtp", get(alerts::get_smtp).put(alerts::set_smtp))
        .route("/settings/smtp/test", post(alerts::test_smtp))
        .route("/alert-rules", get(alerts::list_rules).post(alerts::create_rule))
        .route("/alert-rules/{id}", axum::routing::patch(alerts::update_rule).delete(alerts::delete_rule))
        // Verwaltung
        .route("/users", get(users::list_users).post(users::add_user))
        .route("/users/{id}", axum::routing::patch(users::update_user).delete(users::delete_user))
        .route("/users/{id}/totp", delete(users::reset_totp))
        .route("/users/{id}/password", axum::routing::put(users::reset_user_password))
        .route("/users/{id}/sessions", delete(users::end_user_sessions))
        .route("/permissions", get(users::permissions))
        .route("/roles", get(users::list_roles).post(users::create_role))
        .route("/roles/{id}", axum::routing::patch(users::update_role).delete(users::delete_role))
        .route("/groups", get(users::list_groups).post(users::create_group))
        .route("/groups/{id}", axum::routing::patch(users::update_group).delete(users::delete_group))
        .route("/audit", get(admin::audit_log))
        .route("/logs", get(admin::system_log))
        .route("/system", get(admin::system))
        .route("/remote-logs", get(admin::remote_logs))
        .route("/remote-logs/test", post(admin::remote_logs_test))
        // Sicherung
        .route("/backup/export", post(backup::export))
        .route("/backup/restore", post(backup::restore).layer(axum::extract::DefaultBodyLimit::max(64 * 1024 * 1024)))
        .route("/backup/auto", get(backup::get_auto).put(backup::set_auto))
        .route("/backup/auto/run", post(backup::run_auto))
        .route("/backup/files/{name}", get(backup::get_file).delete(backup::delete_file))
        .route("/vault", get(backup::vault_info))
        .route("/vault/rotate", post(backup::rotate_key))
        .route("/maintenance", get(admin::list_maintenance).post(admin::create_maintenance))
        .route("/maintenance/{id}", axum::routing::patch(admin::update_maintenance).delete(admin::delete_maintenance))
        // Verbundene Programme (Verwaltung)
        .route("/integrations", get(integrations::list).post(integrations::create))
        .route("/integrations/{id}", axum::routing::patch(integrations::update).delete(integrations::remove))
        .route("/integrations/{id}/token", post(integrations::new_token))
        .route("/integrations/{id}/links", put(integrations::set_link))
        .route("/pauses", get(integrations::active_pauses))
        .route("/pauses/{id}/end", post(integrations::stop_pause))
        .layer(middleware::from_fn(auth::csrf_guard))
        // Leitstand-Bildschirm: meldet sich mit einem API-Schlüssel an und bekommt eine Kiosk-Sitzung
        .route("/kiosk/login", post(users::kiosk_login))
        // Zentrale Anmeldung: Weiterleitungen des Browsers (GET, ohne CSRF-Header)
        .route("/oidc/start", get(oidc::start))
        .route("/oidc/callback", get(oidc::callback))
        // Schnittstelle für verbundene Programme: Anmeldung per Schlüssel im Authorization-Header
        // (kein Cookie – deshalb ohne CSRF-Header; fremde Webseiten kennen den Schlüssel nicht)
        .route("/integration/v1/hello", get(integrations::hello))
        .route("/integration/v1/inventory", put(integrations::put_inventory))
        .route("/integration/v1/pause", post(integrations::pause))
        .route("/integration/v1/pause/{id}/end", post(integrations::end_pause))
        .route("/integration/v1/report", post(integrations::report))
        // Probes in entfernten Sektoren: Anmeldung per eigenem Schlüssel (npp_…), ebenfalls ohne Cookie
        .route("/probe/v1/config", get(probes::config))
        .route("/probe/v1/results", post(probes::results))
        .route("/probe/v1/discovery", post(probes::discovery));

    Router::new()
        .nest("/api", api)
        .route("/healthz", get(health))
        // no-cache: Der Browser fragt bei jedem Aufruf kurz nach, ob sich die Datei geändert hat –
        // so ist nach einem Update sofort die neue Oberfläche aktiv (sonst meist nur „304 Not Modified“)
        .fallback_service(ServeDir::new(&state.config.web_dir))
        .layer(SetResponseHeaderLayer::if_not_present(header::CACHE_CONTROL, HeaderValue::from_static("no-cache")))
        // Sicherheits-Header auch dann, wenn jemand die App ohne den Caddy-Proxy erreicht
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; \
                 worker-src 'self'; manifest-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            ),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")))
        .layer(SetResponseHeaderLayer::if_not_present(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY")))
        .layer(SetResponseHeaderLayer::if_not_present(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer")))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Für Docker-Healthchecks: 200, wenn die Datenbank erreichbar ist
async fn health(State(state): State<AppState>) -> StatusCode {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}
