//! Sektoren (Standorte/Bereiche): Baum, Zuordnung von Adressen, Filter nach Rechten.

use sqlx::PgPool;

use crate::auth::{self, CurrentUser};

/// Standard-Sektor (wird bei der Migration angelegt und kann nicht gelöscht werden)
pub const DEFAULT_SITE: i64 = 1;

pub async fn tree(db: &PgPool) -> sqlx::Result<Vec<(i64, Option<i64>)>> {
    sqlx::query_as("SELECT id, parent_id FROM sites").fetch_all(db).await
}

/// Welche Sektoren darf der Benutzer mit diesem Recht sehen – optional eingeschränkt auf einen gewählten
/// Sektor (inkl. Unter-Sektoren). `None` = keine Einschränkung.
pub async fn filter(db: &PgPool, user: &CurrentUser, perm: &str, requested: Option<i64>) -> sqlx::Result<Option<Vec<i64>>> {
    let allowed = user.site_filter(perm);
    let Some(site) = requested.filter(|s| *s > 0) else { return Ok(allowed) };
    let wanted = auth::descendants(site, &tree(db).await?);
    Ok(Some(match allowed {
        None => wanted,
        Some(allowed) => wanted.into_iter().filter(|s| allowed.contains(s)).collect(),
    }))
}

/// Sektor einer Adresse: das kleinste eingetragene Netz, das sie enthält, sonst der Standard-Sektor.
/// Gibt es das Netz in mehreren Sektoren, gewinnt ein Sektor ohne Probe (den erreicht der Server selbst).
pub async fn site_for_ip(db: &PgPool, ip: &str) -> sqlx::Result<i64> {
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT n.site_id FROM networks n
          WHERE $1::inet << n.cidr OR $1::inet = host(n.cidr)::inet
          ORDER BY EXISTS (SELECT 1 FROM probes p WHERE p.site_id = n.site_id AND p.enabled), masklen(n.cidr) DESC
          LIMIT 1",
    )
    .bind(ip)
    .fetch_optional(db)
    .await?;
    Ok(row.map_or(DEFAULT_SITE, |r| r.0))
}

/// SQL-Bedingung für „Sektor wird vom Server selbst geprüft“ (nicht von einer Probe)
pub const SITE_LOCAL: &str = "NOT EXISTS (SELECT 1 FROM probes p WHERE p.site_id = devices.site_id AND p.enabled)";
