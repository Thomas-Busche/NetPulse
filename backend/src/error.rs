//! Einheitliche Fehlerantworten der API: immer JSON `{ "error": "…" }`.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

pub enum ApiError {
    BadRequest(String),
    Unauthorized,
    InvalidCredentials,
    Forbidden,
    NotFound,
    TooManyRequests,
    /// 2FA ist Pflicht, aber für diesen Benutzer noch nicht eingerichtet
    TotpSetupRequired,
    PasswordChangeRequired,
    /// Kritische Aktion: Passwort (und ggf. Code) muss kurz vorher erneut bestätigt worden sein
    ReauthRequired,
    /// Interne Fehler werden geloggt, der Browser bekommt aber keine Details zu sehen.
    Internal(anyhow::Error),
}

pub type ApiResult<T> = Result<T, ApiError>;

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if matches!(self, ApiError::TotpSetupRequired) {
            let body = json!({
                "error": "Zwei-Faktor-Anmeldung ist Pflicht – bitte zuerst unter „Mein Konto“ einrichten",
                "totp_setup_required": true,
            });
            return (StatusCode::FORBIDDEN, Json(body)).into_response();
        }
        if matches!(self, ApiError::PasswordChangeRequired) {
            let body = json!({
                "error": "Bitte zuerst unter „Mein Konto“ ein eigenes Passwort setzen",
                "password_change_required": true,
            });
            return (StatusCode::FORBIDDEN, Json(body)).into_response();
        }
        if matches!(self, ApiError::ReauthRequired) {
            let body = json!({
                "error": "Bitte zur Sicherheit das Passwort erneut eingeben",
                "reauth_required": true,
            });
            return (StatusCode::FORBIDDEN, Json(body)).into_response();
        }
        let (status, message) = match self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "Nicht angemeldet".into()),
            ApiError::InvalidCredentials => {
                (StatusCode::UNAUTHORIZED, "Benutzername oder Passwort falsch".into())
            }
            ApiError::Forbidden => (StatusCode::FORBIDDEN, "Keine Berechtigung".into()),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "Nicht gefunden".into()),
            ApiError::TooManyRequests => (
                StatusCode::TOO_MANY_REQUESTS,
                "Zu viele Fehlversuche – bitte in einigen Minuten erneut versuchen".into(),
            ),
            ApiError::TotpSetupRequired | ApiError::PasswordChangeRequired | ApiError::ReauthRequired => unreachable!(),
            ApiError::Internal(e) => {
                tracing::error!("{e:#}");
                (StatusCode::INTERNAL_SERVER_ERROR, "Interner Fehler".into())
            }
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

// Damit `?` Datenbank- und sonstige Fehler automatisch in ApiError umwandelt
impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        ApiError::Internal(e.into())
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError::Internal(e)
    }
}
