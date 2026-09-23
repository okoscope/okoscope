use crate::error_code::ErrorCode;
use crate::repository::ReleaseRepository;
use crate::repository::transaction::TransactionRepository;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use event_model::BaselineSelectionSource;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::repository::{ApplicationRepository, ProjectRepository};
use crate::{
    access_control::resolve_project_access,
    auth::{IdentityPrincipal, UserSessionAuthenticator},
};

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 200;

#[derive(Clone, Debug)]
struct ReleaseState {
    pool: PgPool,
    authenticator: UserSessionAuthenticator,
}

pub fn router(pool: PgPool) -> Router {
    let state = ReleaseState {
        authenticator: UserSessionAuthenticator::new(pool.clone()),
        pool,
    };
    Router::new()
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/releases",
            post(create_release).get(list_releases),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/releases/{release_id}",
            get(get_release),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/releases/{release_id}/episodes",
            get(list_episodes),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/releases/{target_id}/runtime-diff",
            get(runtime_diff),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/releases/{target_id}/runtime-diff/summary",
            get(runtime_diff_summary),
        )
        .with_state(state)
}

#[derive(Debug)]
enum ReleaseError {
    Unauthorized,
    Invalid(String),
    NotFound,
    Conflict,
    Database(sqlx::Error),
}

impl From<sqlx::Error> for ReleaseError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

impl IntoResponse for ReleaseError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                ErrorCode::UNAUTHORIZED,
                "invalid or missing bearer credential".to_owned(),
            ),
            Self::Invalid(message) => {
                (StatusCode::BAD_REQUEST, ErrorCode::INVALID_REQUEST, message)
            }
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                ErrorCode::NOT_FOUND,
                "release or application not found".to_owned(),
            ),
            Self::Conflict => (
                StatusCode::CONFLICT,
                ErrorCode::RELEASE_EXISTS,
                "release version already exists".to_owned(),
            ),
            Self::Database(error) => {
                tracing::error!(error=%error, "release API database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorCode::INTERNAL_ERROR,
                    "internal server error".to_owned(),
                )
            }
        };
        crate::web_api::uncorrelated_error_response(status, code, message)
    }
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct Release {
    pub id: Uuid,
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub version: String,
    pub display_name: String,
    pub description: Option<String>,
    pub deployed_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub source: String,
    pub identity_version: Option<i16>,
    pub identity_digest: Option<String>,
    pub identity_components: Option<sqlx::types::Json<Vec<ReleaseIdentityComponent>>>,
    pub revision_count: i64,
    pub active_episode_count: i64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReleaseIdentityComponent {
    pub name: String,
    pub image: String,
    pub category: String,
    #[serde(deserialize_with = "deserialize_component_digest")]
    pub digest: String,
}

fn deserialize_component_digest<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes = <Vec<u8>>::deserialize(deserializer)?;
    if bytes.len() != 32 {
        return Err(serde::de::Error::invalid_length(
            bytes.len(),
            &"exactly 32 digest bytes",
        ));
    }
    Ok(hex::encode(bytes))
}

#[derive(Clone, Debug, FromRow, Serialize)]
struct DeploymentEpisode {
    id: Uuid,
    release_id: Uuid,
    release_display_name: String,
    revision_id: Uuid,
    cluster_id: Uuid,
    occurrence_number: i64,
    state: String,
    transition_kind: String,
    first_observed_at: DateTime<Utc>,
    first_ready_at: Option<DateTime<Utc>>,
    last_observed_at: DateTime<Utc>,
    ended_at: Option<DateTime<Utc>>,
    pod_count: i32,
    ready_pod_count: i32,
    workload_ready_pod_count: i32,
    ready_pod_share: Option<f64>,
    snapshot_observed_at: Option<DateTime<Utc>>,
    predecessors: Value,
}

#[derive(Debug, Serialize)]
struct EpisodeList {
    items: Vec<DeploymentEpisode>,
    next_cursor: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
struct CreateRelease {
    version: String,
    description: Option<String>,
    deployed_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    cursor: Option<Uuid>,
    limit: Option<i64>,
}

#[derive(Debug, Serialize)]
struct ReleaseList {
    items: Vec<Release>,
    next_cursor: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
struct DiffQuery {
    baseline_id: Option<Uuid>,
    cursor: Option<Uuid>,
    limit: Option<i64>,
}

#[derive(Clone, Debug, FromRow, Serialize)]
struct DiffEntry {
    group_id: Uuid,
    classification: String,
    event_kind: String,
    semantic_summary: Value,
    baseline_occurrence_count: Option<i64>,
    baseline_first_seen_at: Option<DateTime<Utc>>,
    baseline_last_seen_at: Option<DateTime<Utc>>,
    target_occurrence_count: Option<i64>,
    target_first_seen_at: Option<DateTime<Utc>>,
    target_last_seen_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
struct RuntimeDiff {
    coverage: crate::runtime_retention::history::Coverage,
    baseline: Option<Release>,
    target: Release,
    items: Vec<DiffEntry>,
    next_cursor: Option<Uuid>,
    baseline_selection_source: BaselineSelectionSource,
}

#[derive(Debug, Deserialize)]
struct DiffSummaryQuery {
    baseline_id: Option<Uuid>,
    limit: Option<i64>,
}

#[derive(Clone, Debug, FromRow, Serialize)]
struct DiffClassificationCount {
    classification: String,
    item_count: i64,
}

#[derive(Clone, Debug, FromRow, Serialize)]
struct DiffChangeEntry {
    group_id: Uuid,
    classification: String,
    event_kind: String,
    semantic_summary: Value,
    baseline_occurrence_count: i64,
    target_occurrence_count: i64,
    occurrence_delta: i64,
}

#[derive(Debug, Serialize)]
struct RuntimeDiffSummary {
    coverage: crate::runtime_retention::history::Coverage,
    baseline: Option<Release>,
    target: Release,
    total_item_count: i64,
    classifications: Vec<DiffClassificationCount>,
    largest_changes: Vec<DiffChangeEntry>,
    baseline_selection_source: BaselineSelectionSource,
}

async fn principal(
    headers: &HeaderMap,
    state: &ReleaseState,
) -> Result<IdentityPrincipal, ReleaseError> {
    state
        .authenticator
        .authenticate_identity_headers(headers)
        .await?
        .ok_or(ReleaseError::Unauthorized)
}

async fn project_organization(
    state: &ReleaseState,
    principal: IdentityPrincipal,
    project_id: Uuid,
) -> Result<Uuid, ReleaseError> {
    let organization_id: Uuid = ProjectRepository::organization_of(&state.pool, project_id)
        .await?
        .ok_or(ReleaseError::NotFound)?;
    resolve_project_access(&state.pool, principal, organization_id, project_id)
        .await?
        .ok_or(ReleaseError::NotFound)?;
    Ok(organization_id)
}

fn limit(value: Option<i64>) -> Result<i64, ReleaseError> {
    let value = value.unwrap_or(DEFAULT_LIMIT);
    if (1..=MAX_LIMIT).contains(&value) {
        Ok(value)
    } else {
        Err(ReleaseError::Invalid(
            "limit must be between 1 and 200".into(),
        ))
    }
}

fn summary_limit(value: Option<i64>) -> Result<i64, ReleaseError> {
    let value = value.unwrap_or(5);
    if (1..=10).contains(&value) {
        Ok(value)
    } else {
        Err(ReleaseError::Invalid(
            "limit must be between 1 and 10".into(),
        ))
    }
}

async fn application_owned(
    pool: &PgPool,
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
) -> Result<bool, sqlx::Error> {
    ApplicationRepository::exists(pool, organization_id, project_id, application_id).await
}

async fn create_release(
    State(state): State<ReleaseState>,
    headers: HeaderMap,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    Json(input): Json<CreateRelease>,
) -> Result<(StatusCode, Json<Release>), ReleaseError> {
    crate::metrics::record_api_request();
    let principal = principal(&headers, &state).await?;
    let organization_id = project_organization(&state, principal, project_id).await?;
    if !application_owned(&state.pool, organization_id, project_id, application_id).await? {
        return Err(ReleaseError::NotFound);
    }
    let version = input.version.trim();
    if version.is_empty() || version.len() > 200 {
        return Err(ReleaseError::Invalid(
            "version must contain 1..=200 bytes after trimming".into(),
        ));
    }
    if input
        .description
        .as_ref()
        .is_some_and(|value| value.len() > 2000)
    {
        return Err(ReleaseError::Invalid(
            "description must not exceed 2000 bytes".into(),
        ));
    }
    let result = ReleaseRepository::create_manual::<_, Release>(
        &state.pool,
        Uuid::new_v4(),
        organization_id,
        project_id,
        application_id,
        version,
        input.description,
        input.deployed_at,
    )
    .await;
    match result {
        Ok(release) => Ok((StatusCode::CREATED, Json(release))),
        Err(error)
            if error
                .as_database_error()
                .is_some_and(sqlx::error::DatabaseError::is_unique_violation) =>
        {
            Err(ReleaseError::Conflict)
        }
        Err(error) => Err(error.into()),
    }
}

async fn list_releases(
    State(state): State<ReleaseState>,
    headers: HeaderMap,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ReleaseList>, ReleaseError> {
    crate::metrics::record_api_request();
    let principal = principal(&headers, &state).await?;
    let organization_id = project_organization(&state, principal, project_id).await?;
    let limit = limit(query.limit)?;
    if !application_owned(&state.pool, organization_id, project_id, application_id).await? {
        return Err(ReleaseError::NotFound);
    }
    let cursor = if let Some(id) = query.cursor {
        Some(
            crate::repository::ReleaseRepository::cursor(
                &state.pool,
                crate::repository::ApplicationScope {
                    organization_id,
                    project_id,
                    application_id,
                },
                id,
            )
            .await?
            .ok_or_else(|| ReleaseError::Invalid("cursor does not exist in this scope".into()))?,
        )
    } else {
        None
    };
    let (cursor_time, cursor_id) = cursor.unzip();
    let mut items = ReleaseRepository::page::<_, Release>(
        &state.pool,
        organization_id,
        project_id,
        application_id,
        cursor_time,
        cursor_id,
        limit + 1,
    )
    .await?;
    let next_cursor = if i64::try_from(items.len()).unwrap_or(i64::MAX) > limit {
        items.pop();
        items.last().map(|item| item.id)
    } else {
        None
    };
    Ok(Json(ReleaseList { items, next_cursor }))
}

async fn get_release(
    State(state): State<ReleaseState>,
    headers: HeaderMap,
    Path((project_id, application_id, release_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<Json<Release>, ReleaseError> {
    let principal = principal(&headers, &state).await?;
    let organization_id = project_organization(&state, principal, project_id).await?;
    Ok(Json(
        fetch_release(
            &state.pool,
            organization_id,
            project_id,
            application_id,
            release_id,
        )
        .await?
        .ok_or(ReleaseError::NotFound)?,
    ))
}

async fn list_episodes(
    State(state): State<ReleaseState>,
    headers: HeaderMap,
    Path((project_id, application_id, release_id)): Path<(Uuid, Uuid, Uuid)>,
    Query(query): Query<ListQuery>,
) -> Result<Json<EpisodeList>, ReleaseError> {
    let principal = principal(&headers, &state).await?;
    let organization_id = project_organization(&state, principal, project_id).await?;
    fetch_release(
        &state.pool,
        organization_id,
        project_id,
        application_id,
        release_id,
    )
    .await?
    .ok_or(ReleaseError::NotFound)?;
    let limit = limit(query.limit)?;
    let mut items = ReleaseRepository::deployment_episode_page::<_, DeploymentEpisode>(
        &state.pool,
        organization_id,
        project_id,
        application_id,
        release_id,
        query.cursor,
        limit + 1,
    )
    .await?;
    let next_cursor = if i64::try_from(items.len()).unwrap_or(i64::MAX) > limit {
        items.pop();
        items.last().map(|item| item.id)
    } else {
        None
    };
    Ok(Json(EpisodeList { items, next_cursor }))
}

async fn fetch_release(
    pool: &PgPool,
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    release_id: Uuid,
) -> Result<Option<Release>, sqlx::Error> {
    ReleaseRepository::get(
        pool,
        organization_id,
        project_id,
        application_id,
        release_id,
    )
    .await
}

async fn resolve_diff_releases(
    pool: &PgPool,
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    target_id: Uuid,
    baseline_id: Option<Uuid>,
) -> Result<(Release, Option<Release>, BaselineSelectionSource), ReleaseError> {
    let target = fetch_release(pool, organization_id, project_id, application_id, target_id)
        .await?
        .ok_or(ReleaseError::NotFound)?;
    let (baseline, source) = if let Some(id) = baseline_id {
        (
            Some(
                fetch_release(pool, organization_id, project_id, application_id, id)
                    .await?
                    .ok_or(ReleaseError::NotFound)?,
            ),
            BaselineSelectionSource::Explicit,
        )
    } else {
        let predecessors: Vec<Uuid> = ReleaseRepository::transition_predecessors(
            pool,
            organization_id,
            project_id,
            application_id,
            target.id,
        )
        .await?;
        if let Some(id) = predecessors.first() {
            let source = if predecessors.len() == 1 {
                BaselineSelectionSource::Transition
            } else {
                BaselineSelectionSource::ConcurrentTransitionFallback
            };
            (
                fetch_release(pool, organization_id, project_id, application_id, *id).await?,
                source,
            )
        } else {
            let legacy = ReleaseRepository::legacy_predecessor::<_, Release>(
                pool,
                organization_id,
                project_id,
                application_id,
                target.deployed_at,
                target.id,
            )
            .await?;
            let source = if legacy.is_some() {
                BaselineSelectionSource::LegacyDeploymentOrder
            } else {
                BaselineSelectionSource::None
            };
            (legacy, source)
        }
    };
    Ok((target, baseline, source))
}

async fn runtime_diff(
    State(state): State<ReleaseState>,
    headers: HeaderMap,
    Path((project_id, application_id, target_id)): Path<(Uuid, Uuid, Uuid)>,
    Query(query): Query<DiffQuery>,
) -> Result<Json<RuntimeDiff>, ReleaseError> {
    crate::metrics::record_api_request();
    let principal = principal(&headers, &state).await?;
    let organization_id = project_organization(&state, principal, project_id).await?;
    let limit = limit(query.limit)?;
    let (target, baseline, baseline_selection_source) = resolve_diff_releases(
        &state.pool,
        organization_id,
        project_id,
        application_id,
        target_id,
        query.baseline_id,
    )
    .await?;
    let baseline_id = baseline.as_ref().map(|release| release.id);
    let mut items = ReleaseRepository::diff_page::<_, DiffEntry>(
        &state.pool,
        baseline_id,
        target.id,
        organization_id,
        project_id,
        application_id,
        query.cursor,
        limit + 1,
    )
    .await?;
    let next_cursor = if i64::try_from(items.len()).unwrap_or(i64::MAX) > limit {
        items.pop();
        items.last().map(|item| item.group_id)
    } else {
        None
    };
    crate::metrics::record_release_diff();
    Ok(Json(RuntimeDiff {
        coverage: crate::runtime_retention::history::coverage(
            &state.pool,
            organization_id,
            project_id,
        )
        .await?,
        baseline,
        target,
        items,
        next_cursor,
        baseline_selection_source,
    }))
}

async fn runtime_diff_summary(
    State(state): State<ReleaseState>,
    headers: HeaderMap,
    Path((project_id, application_id, target_id)): Path<(Uuid, Uuid, Uuid)>,
    Query(query): Query<DiffSummaryQuery>,
) -> Result<Json<RuntimeDiffSummary>, ReleaseError> {
    let started = std::time::Instant::now();
    crate::metrics::record_api_request();
    let principal = principal(&headers, &state).await?;
    let organization_id = project_organization(&state, principal, project_id).await?;
    let limit = summary_limit(query.limit)?;
    let (target, baseline, baseline_selection_source) = resolve_diff_releases(
        &state.pool,
        organization_id,
        project_id,
        application_id,
        target_id,
        query.baseline_id,
    )
    .await?;
    let Some(baseline_id) = baseline.as_ref().map(|release| release.id) else {
        crate::metrics::record_release_diff_summary(
            u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
        return Ok(Json(RuntimeDiffSummary {
            coverage: crate::runtime_retention::history::coverage(
                &state.pool,
                organization_id,
                project_id,
            )
            .await?,
            baseline: None,
            target,
            total_item_count: 0,
            classifications: Vec::new(),
            largest_changes: Vec::new(),
            baseline_selection_source,
        }));
    };
    let mut transaction = state.pool.begin().await?;
    TransactionRepository::begin_consistent_read(&mut *transaction).await?;
    let classifications = ReleaseRepository::diff_classifications::<_, DiffClassificationCount>(
        &mut *transaction,
        baseline_id,
        target.id,
        organization_id,
        project_id,
        application_id,
    )
    .await?;
    let largest_changes = ReleaseRepository::diff_largest_changes::<_, DiffChangeEntry>(
        &mut *transaction,
        baseline_id,
        target.id,
        organization_id,
        project_id,
        application_id,
        limit,
    )
    .await?;
    transaction.commit().await?;
    let total_item_count = classifications.iter().map(|row| row.item_count).sum();
    crate::metrics::record_release_diff_summary(
        u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
    );
    Ok(Json(RuntimeDiffSummary {
        coverage: crate::runtime_retention::history::coverage(
            &state.pool,
            organization_id,
            project_id,
        )
        .await?,
        baseline,
        target,
        total_item_count,
        classifications,
        largest_changes,
        baseline_selection_source,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_digest_serializes_as_fixed_width_lowercase_hex() {
        let mut bytes = vec![0_u8, 1, 10, 15];
        bytes.extend(std::iter::repeat_n(255, 28));
        let component: ReleaseIdentityComponent = serde_json::from_value(serde_json::json!({
            "name": "file-activity",
            "image": "busybox:1.37",
            "category": "application",
            "digest": bytes,
        }))
        .unwrap();

        let value = serde_json::to_value(component).unwrap();
        let digest = value["digest"].as_str().unwrap();
        assert_eq!(digest.len(), 64);
        assert_eq!(digest, format!("00010a0f{}", "ff".repeat(28)));
        assert!(
            digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }

    #[test]
    fn component_digest_rejects_non_sha256_byte_lengths() {
        let result = serde_json::from_value::<ReleaseIdentityComponent>(serde_json::json!({
            "name": "app",
            "image": "app:latest",
            "category": "application",
            "digest": [0, 1],
        }));
        assert!(result.is_err());
    }

    #[test]
    fn diff_summary_limit_is_bounded() {
        assert_eq!(summary_limit(None).unwrap(), 5);
        for valid in [1, 5, 10] {
            assert_eq!(summary_limit(Some(valid)).unwrap(), valid);
        }
        for invalid in [0, 11] {
            assert!(summary_limit(Some(invalid)).is_err());
        }
    }
}
