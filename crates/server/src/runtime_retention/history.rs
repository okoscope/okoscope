use crate::repository::runtime_retention::RuntimeRetentionRepository;
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(Clone, Debug, Default, Serialize, FromRow)]
pub struct Coverage {
    pub closed_before: Option<DateTime<Utc>>,
    pub history_expired_before: Option<DateTime<Utc>>,
    #[sqlx(skip)]
    pub detail_scope: &'static str,
}

pub async fn coverage(pool: &PgPool, org: Uuid, project: Uuid) -> Result<Coverage, sqlx::Error> {
    let mut result: Coverage = RuntimeRetentionRepository::coverage(pool, org, project).await?;
    result.detail_scope = "raw";
    Ok(result)
}

#[derive(Debug, Serialize, FromRow)]
pub struct Snapshot {
    pub id: Uuid,
    pub group_id: Uuid,
    pub release_id: Option<Uuid>,
    pub day: NaiveDate,
    pub format_version: i16,
    pub occurrence_count: i64,
    pub first_observed_at: DateTime<Utc>,
    pub last_observed_at: DateTime<Utc>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub day_from: Option<NaiveDate>,
    pub day_to: Option<NaiveDate>,
    pub release_id: Option<Uuid>,
    pub cursor: Option<Uuid>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct Page {
    pub items: Vec<Snapshot>,
    pub next_cursor: Option<Uuid>,
    pub coverage: Coverage,
    pub granularity: &'static str,
}

pub async fn page(
    pool: &PgPool,
    org: Uuid,
    project: Uuid,
    group: Uuid,
    query: Query,
) -> Result<Page, sqlx::Error> {
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let mut items: Vec<Snapshot> = RuntimeRetentionRepository::snapshot_page(
        pool,
        org,
        group,
        query.day_from,
        query.day_to,
        query.release_id,
        query.cursor,
        limit + 1,
    )
    .await?;
    let next_cursor = if items.len() > usize::try_from(limit).unwrap_or(100) {
        items.truncate(usize::try_from(limit).unwrap_or(100));
        items.last().map(|item| item.id)
    } else {
        None
    };
    Ok(Page {
        items,
        next_cursor,
        coverage: coverage(pool, org, project).await?,
        granularity: "utc_day",
    })
}
