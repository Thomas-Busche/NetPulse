//! Gerätekategorien: frei definierbar (Name, Symbol, Farbe, Reihenfolge). Geräte bekommen ihre Kategorie
//! automatisch über den Gerätetyp (`auto_types`) oder von Hand; der Leitstand gruppiert danach.

use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    audit,
    auth::{perm, Need},
    classify,
    error::{ApiError, ApiResult},
    AppState,
};

#[derive(Serialize, sqlx::FromRow)]
pub struct Category {
    id: i64,
    name: String,
    icon: String,
    color: String,
    position: i32,
    auto_types: Vec<String>,
    /// Geräte, die gerade in dieser Kategorie sind (von Hand oder automatisch)
    device_count: i64,
}

#[derive(Deserialize, Serialize)]
pub struct CategoryInput {
    name: String,
    #[serde(default = "default_icon")]
    icon: String,
    #[serde(default = "default_color")]
    color: String,
    #[serde(default)]
    position: i32,
    #[serde(default)]
    auto_types: Vec<String>,
}

fn default_icon() -> String {
    "category".into()
}

fn default_color() -> String {
    "#64748b".into()
}

/// Wirksame Kategorie je Gerät – dieselbe Regel wie in der Geräteliste
const EFFECTIVE: &str = "CASE WHEN d.category_manual THEN d.category_id ELSE
                           (SELECT c2.id FROM device_categories c2 WHERE COALESCE(d.device_type, 'unknown') = ANY(c2.auto_types)
                             ORDER BY c2.position, c2.id LIMIT 1) END";

pub async fn list(State(st): State<AppState>, user: Need<perm::View>) -> ApiResult<Json<Vec<Category>>> {
    let sites = user.site_filter("view");
    let sql = format!(
        "WITH eff AS (SELECT {EFFECTIVE} AS cat FROM devices d WHERE $1::bigint[] IS NULL OR d.site_id = ANY($1))
         SELECT c.id, c.name, c.icon, c.color, c.position, c.auto_types,
                (SELECT count(*) FROM eff WHERE eff.cat = c.id) AS device_count
           FROM device_categories c ORDER BY c.position, c.name"
    );
    Ok(Json(sqlx::query_as::<_, Category>(&sql).bind(&sites).fetch_all(&st.db).await?))
}

/// Eingaben prüfen und vereinheitlichen
fn clean(mut c: CategoryInput) -> ApiResult<CategoryInput> {
    c.name = c.name.trim().to_string();
    if c.name.is_empty() || c.name.chars().count() > 60 {
        return Err(ApiError::BadRequest("Name fehlt oder ist länger als 60 Zeichen".into()));
    }
    c.icon = c.icon.trim().to_string();
    if c.icon.is_empty() || c.icon.len() > 40 || !c.icon.chars().all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-') {
        return Err(ApiError::BadRequest("Ungültiges Symbol".into()));
    }
    if !is_hex_color(&c.color) {
        return Err(ApiError::BadRequest("Farbe bitte als #rrggbb angeben".into()));
    }
    c.auto_types.sort();
    c.auto_types.dedup();
    if let Some(bad) = c.auto_types.iter().find(|t| !classify::TYPES.contains(&t.as_str())) {
        return Err(ApiError::BadRequest(format!("Unbekannter Gerätetyp: {bad}")));
    }
    Ok(c)
}

fn is_hex_color(s: &str) -> bool {
    s.len() == 7 && s.starts_with('#') && s[1..].chars().all(|c| c.is_ascii_hexdigit())
}

fn map_unique(e: sqlx::Error) -> ApiError {
    match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => ApiError::BadRequest("Eine Kategorie mit diesem Namen gibt es schon".into()),
        _ => e.into(),
    }
}

/// Ein Gerätetyp gehört automatisch zu höchstens einer Kategorie: bei anderen Kategorien entfernen
async fn take_types(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, id: i64, types: &[String]) -> sqlx::Result<()> {
    if !types.is_empty() {
        sqlx::query(
            "UPDATE device_categories SET auto_types = ARRAY(SELECT t FROM unnest(auto_types) t WHERE NOT t = ANY($2))
              WHERE id <> $1 AND auto_types && $2",
        )
        .bind(id)
        .bind(types)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

pub async fn create(State(st): State<AppState>, Need(user, _): Need<perm::SettingsManage>, Json(c): Json<CategoryInput>) -> ApiResult<Json<Value>> {
    let c = clean(c)?;
    let mut tx = st.db.begin().await?;
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO device_categories (name, icon, color, position, auto_types) VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(&c.name)
    .bind(&c.icon)
    .bind(&c.color)
    .bind(c.position)
    .bind(&c.auto_types)
    .fetch_one(&mut *tx)
    .await
    .map_err(map_unique)?;
    take_types(&mut tx, id, &c.auto_types).await?;
    tx.commit().await?;
    audit::by(&st.db, &user, "category_create", json!({ "id": id, "category": c })).await;
    Ok(Json(json!({ "id": id })))
}

pub async fn update(
    State(st): State<AppState>,
    Need(user, _): Need<perm::SettingsManage>,
    Path(id): Path<i64>,
    Json(c): Json<CategoryInput>,
) -> ApiResult<Json<Value>> {
    let c = clean(c)?;
    let mut tx = st.db.begin().await?;
    let done = sqlx::query("UPDATE device_categories SET name = $2, icon = $3, color = $4, position = $5, auto_types = $6 WHERE id = $1")
        .bind(id)
        .bind(&c.name)
        .bind(&c.icon)
        .bind(&c.color)
        .bind(c.position)
        .bind(&c.auto_types)
        .execute(&mut *tx)
        .await
        .map_err(map_unique)?;
    if done.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    take_types(&mut tx, id, &c.auto_types).await?;
    tx.commit().await?;
    audit::by(&st.db, &user, "category_update", json!({ "id": id, "category": c })).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct Order {
    ids: Vec<i64>,
}

/// Reihenfolge festlegen (Liste der IDs von oben nach unten)
pub async fn reorder(State(st): State<AppState>, Need(user, _): Need<perm::SettingsManage>, Json(o): Json<Order>) -> ApiResult<Json<Value>> {
    if o.ids.len() > 500 {
        return Err(ApiError::BadRequest("Zu viele Kategorien".into()));
    }
    sqlx::query(
        "UPDATE device_categories c SET position = o.pos * 10
           FROM unnest($1::bigint[]) WITH ORDINALITY AS o(id, pos) WHERE c.id = o.id",
    )
    .bind(&o.ids)
    .execute(&st.db)
    .await?;
    audit::by(&st.db, &user, "category_reorder", json!({ "ids": o.ids })).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn remove(State(st): State<AppState>, Need(user, _): Need<perm::SettingsManage>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let deleted: Option<(String,)> = sqlx::query_as("DELETE FROM device_categories WHERE id = $1 RETURNING name")
        .bind(id)
        .fetch_optional(&st.db)
        .await?;
    let (name,) = deleted.ok_or(ApiError::NotFound)?;
    audit::by(&st.db, &user, "category_delete", json!({ "id": id, "name": name })).await;
    Ok(Json(json!({ "ok": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(name: &str, icon: &str, color: &str, types: &[&str]) -> CategoryInput {
        CategoryInput {
            name: name.into(),
            icon: icon.into(),
            color: color.into(),
            position: 0,
            auto_types: types.iter().map(|t| t.to_string()).collect(),
        }
    }

    #[test]
    fn accepts_valid_input_and_dedups_types() {
        let Ok(c) = clean(input("  Server ", "server", "#2563eb", &["nas", "server", "nas"])) else { panic!("gültige Eingabe abgelehnt") };
        assert_eq!(c.name, "Server");
        assert_eq!(c.auto_types, vec!["nas", "server"]);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(clean(input("", "server", "#2563eb", &[])).is_err());
        assert!(clean(input("X", "Server<", "#2563eb", &[])).is_err());
        assert!(clean(input("X", "server", "blue", &[])).is_err());
        assert!(clean(input("X", "server", "#12345g", &[])).is_err());
        assert!(clean(input("X", "server", "#2563eb", &["toaster"])).is_err());
    }
}
