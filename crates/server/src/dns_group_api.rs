use crate::error_code::ErrorCode;
use std::sync::{Arc, OnceLock};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::repository::dns_groups::{DnsGroupFilter, DnsGroupRepository};
use crate::repository::{ApplicationRepository, ProjectRepository};
use crate::{
    access_control::resolve_project_access,
    auth::{IdentityPrincipal, UserSessionAuthenticator},
};

type HmacSha256 = Hmac<Sha256>;
const TOKEN_MAX_LENGTH: usize = 4_096;

#[derive(Clone, Debug)]
struct DnsGroupState {
    pool: PgPool,
    auth: UserSessionAuthenticator,
    tokens: GroupTokenCodec,
}

#[derive(Clone, Debug)]
struct GroupTokenCodec {
    key: Arc<[u8; 32]>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct GroupTokenPayload {
    format_version: u8,
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    process_command: String,
    display_name: String,
}

impl GroupTokenCodec {
    fn process_default() -> Self {
        static KEY: OnceLock<[u8; 32]> = OnceLock::new();
        let key = KEY.get_or_init(|| {
            std::env::var("OKOSCOPE_IDENTITY_TOKEN_KEY").map_or_else(
                |_| rand::random(),
                |value| {
                    assert!(
                        value.len() >= 32,
                        "OKOSCOPE_IDENTITY_TOKEN_KEY must contain at least 32 bytes"
                    );
                    Sha256::digest(value).into()
                },
            )
        });
        Self {
            key: Arc::new(*key),
        }
    }

    fn encode<T: Serialize>(&self, value: &T) -> Result<String, DnsGroupError> {
        let encoded = hex::encode(
            serde_json::to_vec(value)
                .map_err(|_| DnsGroupError::Invalid("token cannot be encoded".into()))?,
        );
        let mut mac = HmacSha256::new_from_slice(self.key.as_ref())
            .map_err(|_| DnsGroupError::Invalid("token cannot be encoded".into()))?;
        mac.update(encoded.as_bytes());
        Ok(format!(
            "{encoded}.{}",
            hex::encode(mac.finalize().into_bytes())
        ))
    }

    fn decode<T: DeserializeOwned>(&self, token: &str) -> Result<T, DnsGroupError> {
        if token.is_empty() || token.len() > TOKEN_MAX_LENGTH {
            return Err(DnsGroupError::Invalid("token is invalid".into()));
        }
        let (encoded, signature) = token
            .split_once('.')
            .ok_or_else(|| DnsGroupError::Invalid("token is invalid".into()))?;
        let signature = hex::decode(signature)
            .map_err(|_| DnsGroupError::Invalid("token is invalid".into()))?;
        let mut mac = HmacSha256::new_from_slice(self.key.as_ref())
            .map_err(|_| DnsGroupError::Invalid("token is invalid".into()))?;
        mac.update(encoded.as_bytes());
        mac.verify_slice(&signature)
            .map_err(|_| DnsGroupError::Invalid("token is invalid".into()))?;
        let bytes =
            hex::decode(encoded).map_err(|_| DnsGroupError::Invalid("token is invalid".into()))?;
        serde_json::from_slice(&bytes)
            .map_err(|_| DnsGroupError::Invalid("token is invalid".into()))
    }
}

pub fn router(pool: PgPool) -> Router {
    let state = DnsGroupState {
        auth: UserSessionAuthenticator::new(pool.clone()),
        tokens: GroupTokenCodec::process_default(),
        pool,
    };
    Router::new()
        .route("/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/dns-groups", get(list_groups))
        .route("/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/dns-groups/distribution", get(distribution))
        .route("/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/dns-groups/{group_token}/variants", get(variants))
        .with_state(state)
}

#[derive(Debug)]
enum DnsGroupError {
    Unauthorized,
    Invalid(String),
    NotFound,
    Database(sqlx::Error),
}

impl From<sqlx::Error> for DnsGroupError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value)
    }
}

impl IntoResponse for DnsGroupError {
    fn into_response(self) -> Response {
        let (status, error, message) = match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                ErrorCode::UNAUTHORIZED,
                "invalid or missing bearer credential".into(),
            ),
            Self::Invalid(message) => {
                (StatusCode::BAD_REQUEST, ErrorCode::INVALID_REQUEST, message)
            }
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                ErrorCode::NOT_FOUND,
                "logical DNS group not found".into(),
            ),
            Self::Database(error) => {
                tracing::error!(%error, "logical DNS group API database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorCode::INTERNAL_ERROR,
                    "internal server error".into(),
                )
            }
        };
        crate::web_api::uncorrelated_error_response(status, error, message)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct DnsGroupScope {
    release_id: Option<Uuid>,
    cluster_id: Option<Uuid>,
    namespace: Option<String>,
    workload_kind: Option<String>,
    workload_name: Option<String>,
    container_name: Option<String>,
    observed_from: Option<DateTime<Utc>>,
    observed_to: Option<DateTime<Utc>>,
    search: Option<String>,
    verdict: Option<String>,
    suppressed: Option<bool>,
    evaluation_pending: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct GroupQuery {
    #[serde(flatten)]
    scope: DnsGroupScope,
    cursor: Option<String>,
    limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct DistributionQuery {
    #[serde(flatten)]
    scope: DnsGroupScope,
    limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct VariantQuery {
    #[serde(flatten)]
    scope: DnsGroupScope,
    cursor: Option<String>,
    limit: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct GroupCursor {
    scope: String,
    last_seen_at: DateTime<Utc>,
    display_name: String,
    process_command: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct VariantCursor {
    item_id: Uuid,
}

#[derive(Debug, FromRow)]
struct GroupRow {
    display_name: String,
    process_command: String,
    grouping_reason: String,
    confidence: String,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    observation_count: i64,
    variant_count: i64,
    query_types: Vec<String>,
    release_count: i64,
    cluster_count: i64,
    namespace_count: i64,
    workload_count: i64,
    pod_count: i64,
    container_count: i64,
    total_group_count: i64,
    total_observation_count: i64,
}

#[derive(Debug, Serialize)]
struct DnsGroup {
    group_token: String,
    display_name: String,
    process_command: String,
    grouping_reason: String,
    confidence: String,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    observation_count: i64,
    variant_count: i64,
    query_types: Vec<String>,
    release_count: i64,
    cluster_count: i64,
    namespace_count: i64,
    workload_count: i64,
    pod_count: i64,
    container_count: i64,
}

#[derive(Debug, Serialize)]
struct GroupPage {
    coverage: crate::runtime_retention::history::Coverage,
    items: Vec<DnsGroup>,
    next_cursor: Option<String>,
    total_group_count: i64,
    total_observation_count: i64,
}

#[derive(Debug, FromRow, Serialize)]
struct VariantRow {
    item_id: Uuid,
    name: String,
    query_type: String,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    observation_count: i64,
}

#[derive(Debug, Serialize)]
struct VariantPage {
    items: Vec<VariantRow>,
    next_cursor: Option<String>,
}

#[derive(Debug, Serialize)]
struct DistributionEntry {
    group: DnsGroup,
}

#[derive(Debug, Serialize)]
struct DistributionOther {
    group_count: i64,
    observation_count: i64,
}

#[derive(Debug, Serialize)]
struct DnsDistribution {
    coverage: crate::runtime_retention::history::Coverage,
    total_group_count: i64,
    total_observation_count: i64,
    entries: Vec<DistributionEntry>,
    other: Option<DistributionOther>,
}

#[derive(Clone, Copy)]
struct Principal {
    organization_id: Uuid,
}

async fn project_principal(
    headers: &HeaderMap,
    state: &DnsGroupState,
    project_id: Uuid,
) -> Result<Principal, DnsGroupError> {
    let identity: IdentityPrincipal = state
        .auth
        .authenticate_identity_headers(headers)
        .await?
        .ok_or(DnsGroupError::Unauthorized)?;
    let organization_id = ProjectRepository::organization_of(&state.pool, project_id)
        .await?
        .ok_or(DnsGroupError::NotFound)?;
    resolve_project_access(&state.pool, identity, organization_id, project_id)
        .await?
        .ok_or(DnsGroupError::NotFound)?;
    Ok(Principal { organization_id })
}

async fn authorize_scope(
    headers: &HeaderMap,
    state: &DnsGroupState,
    project_id: Uuid,
    application_id: Uuid,
) -> Result<Principal, DnsGroupError> {
    let principal = project_principal(headers, state, project_id).await?;
    let exists = ApplicationRepository::exists(
        &state.pool,
        principal.organization_id,
        project_id,
        application_id,
    )
    .await?;
    exists.then_some(principal).ok_or(DnsGroupError::NotFound)
}

impl DnsGroupScope {
    /// The repository filter for this scope within a tenant path.
    fn filter(
        &self,
        principal: Principal,
        project_id: Uuid,
        application_id: Uuid,
    ) -> DnsGroupFilter<'_> {
        DnsGroupFilter {
            organization_id: principal.organization_id,
            project_id,
            application_id,
            release_id: self.release_id,
            cluster_id: self.cluster_id,
            namespace: self.namespace.as_deref(),
            workload_kind: self.workload_kind.as_deref(),
            workload_name: self.workload_name.as_deref(),
            container_name: self.container_name.as_deref(),
            observed_from: self.observed_from,
            observed_to: self.observed_to,
            verdict: self.verdict.as_deref(),
            suppressed: self.suppressed,
            evaluation_pending: self.evaluation_pending,
        }
    }

    fn normalize(mut self) -> Result<Self, DnsGroupError> {
        for text in [
            &mut self.namespace,
            &mut self.workload_kind,
            &mut self.workload_name,
            &mut self.container_name,
            &mut self.search,
        ]
        .into_iter()
        .flatten()
        {
            *text = text.trim().to_owned();
            if text.is_empty() {
                return Err(DnsGroupError::Invalid(
                    "filter values cannot be empty".into(),
                ));
            }
        }
        if self
            .search
            .as_ref()
            .is_some_and(|value| value.chars().count() > 200)
        {
            return Err(DnsGroupError::Invalid(
                "search cannot exceed 200 characters".into(),
            ));
        }
        if self
            .observed_from
            .zip(self.observed_to)
            .is_some_and(|(from, to)| from > to)
        {
            return Err(DnsGroupError::Invalid(
                "observed_from must not be after observed_to".into(),
            ));
        }
        if self.verdict.as_deref().is_some_and(|value| {
            !matches!(
                value,
                "unclassified" | "expected" | "requires_review" | "policy_conflict"
            )
        }) {
            return Err(DnsGroupError::Invalid("verdict is invalid".into()));
        }
        Ok(self)
    }

    fn fingerprint(&self, ids: (Uuid, Uuid, Uuid)) -> String {
        let bytes = serde_json::to_vec(&(ids, self)).expect("scope is serializable");
        hex::encode(Sha256::digest(bytes))
    }
}

fn page_limit(value: Option<i64>, default: i64, max: i64) -> Result<i64, DnsGroupError> {
    let value = value.unwrap_or(default);
    (1..=max)
        .contains(&value)
        .then_some(value)
        .ok_or_else(|| DnsGroupError::Invalid(format!("limit must be between 1 and {max}")))
}

fn group_from_row(
    state: &DnsGroupState,
    principal: Principal,
    project_id: Uuid,
    application_id: Uuid,
    row: &GroupRow,
) -> Result<DnsGroup, DnsGroupError> {
    let group_token = state.tokens.encode(&GroupTokenPayload {
        format_version: 1,
        organization_id: principal.organization_id,
        project_id,
        application_id,
        process_command: row.process_command.clone(),
        display_name: row.display_name.clone(),
    })?;
    Ok(DnsGroup {
        group_token,
        display_name: row.display_name.clone(),
        process_command: row.process_command.clone(),
        grouping_reason: row.grouping_reason.clone(),
        confidence: row.confidence.clone(),
        first_seen_at: row.first_seen_at,
        last_seen_at: row.last_seen_at,
        observation_count: row.observation_count,
        variant_count: row.variant_count,
        query_types: row.query_types.clone(),
        release_count: row.release_count,
        cluster_count: row.cluster_count,
        namespace_count: row.namespace_count,
        workload_count: row.workload_count,
        pod_count: row.pod_count,
        container_count: row.container_count,
    })
}

async fn list_groups(
    State(state): State<DnsGroupState>,
    headers: HeaderMap,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<GroupQuery>,
) -> Result<Json<GroupPage>, DnsGroupError> {
    let principal = authorize_scope(&headers, &state, project_id, application_id).await?;
    let scope = query.scope.normalize()?;
    let fingerprint = scope.fingerprint((principal.organization_id, project_id, application_id));
    let cursor: Option<GroupCursor> = query
        .cursor
        .as_deref()
        .map(|value| state.tokens.decode(value))
        .transpose()?;
    if cursor
        .as_ref()
        .is_some_and(|value| value.scope != fingerprint)
    {
        return Err(DnsGroupError::Invalid(
            "cursor is invalid for this scope".into(),
        ));
    }
    let limit = page_limit(query.limit, 50, 200)?;
    let pattern = scope.search.as_ref().map(|value| format!("%{value}%"));
    let mut rows: Vec<GroupRow> = DnsGroupRepository::groups(
        &state.pool,
        scope.filter(principal, project_id, application_id),
        pattern,
        cursor.as_ref().map(|v| v.last_seen_at),
        cursor.as_ref().map(|v| v.display_name.as_str()),
        cursor.as_ref().map(|v| v.process_command.as_str()),
        limit + 1,
    )
    .await?;
    let total_group_count = rows.first().map_or(0, |row| row.total_group_count);
    let total_observation_count = rows.first().map_or(0, |row| row.total_observation_count);
    let has_more = rows.len() > usize::try_from(limit).unwrap_or(usize::MAX);
    if has_more {
        rows.pop();
    }
    let next_cursor = if has_more {
        rows.last()
            .map(|row| {
                state.tokens.encode(&GroupCursor {
                    scope: fingerprint,
                    last_seen_at: row.last_seen_at,
                    display_name: row.display_name.clone(),
                    process_command: row.process_command.clone(),
                })
            })
            .transpose()?
    } else {
        None
    };
    let items = rows
        .iter()
        .map(|row| group_from_row(&state, principal, project_id, application_id, row))
        .collect::<Result<_, _>>()?;
    let coverage = crate::runtime_retention::history::coverage(
        &state.pool,
        principal.organization_id,
        project_id,
    )
    .await?;
    Ok(Json(GroupPage {
        coverage,
        items,
        next_cursor,
        total_group_count,
        total_observation_count,
    }))
}

async fn distribution(
    State(state): State<DnsGroupState>,
    headers: HeaderMap,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<DistributionQuery>,
) -> Result<Json<DnsDistribution>, DnsGroupError> {
    let principal = authorize_scope(&headers, &state, project_id, application_id).await?;
    let scope = query.scope.normalize()?;
    let limit = page_limit(query.limit, 5, 10)?;
    let pattern = scope.search.as_ref().map(|value| format!("%{value}%"));
    let rows: Vec<GroupRow> = DnsGroupRepository::distribution(
        &state.pool,
        scope.filter(principal, project_id, application_id),
        pattern,
        limit,
    )
    .await?;
    let total_group_count = rows.first().map_or(0, |row| row.total_group_count);
    let total_observation_count = rows.first().map_or(0, |row| row.total_observation_count);
    let shown_observations: i64 = rows.iter().map(|row| row.observation_count).sum();
    let shown_groups = i64::try_from(rows.len()).unwrap_or(i64::MAX);
    let entries = rows
        .iter()
        .map(|row| {
            group_from_row(&state, principal, project_id, application_id, row)
                .map(|group| DistributionEntry { group })
        })
        .collect::<Result<_, _>>()?;
    let other = (shown_groups < total_group_count).then_some(DistributionOther {
        group_count: total_group_count - shown_groups,
        observation_count: total_observation_count - shown_observations,
    });
    let coverage = crate::runtime_retention::history::coverage(
        &state.pool,
        principal.organization_id,
        project_id,
    )
    .await?;
    Ok(Json(DnsDistribution {
        coverage,
        total_group_count,
        total_observation_count,
        entries,
        other,
    }))
}

async fn variants(
    State(state): State<DnsGroupState>,
    headers: HeaderMap,
    Path((project_id, application_id, group_token)): Path<(Uuid, Uuid, String)>,
    Query(query): Query<VariantQuery>,
) -> Result<Json<VariantPage>, DnsGroupError> {
    let principal = authorize_scope(&headers, &state, project_id, application_id).await?;
    let token: GroupTokenPayload = state.tokens.decode(&group_token)?;
    if token.format_version != 1
        || token.organization_id != principal.organization_id
        || token.project_id != project_id
        || token.application_id != application_id
    {
        return Err(DnsGroupError::NotFound);
    }
    let scope = query.scope.normalize()?;
    let limit = page_limit(query.limit, 50, 200)?;
    let cursor: Option<VariantCursor> = query
        .cursor
        .as_deref()
        .map(|value| state.tokens.decode(value))
        .transpose()?;
    let mut items: Vec<VariantRow> = DnsGroupRepository::variants(
        &state.pool,
        scope.filter(principal, project_id, application_id),
        &token.display_name,
        &token.process_command,
        cursor.as_ref().map(|v| v.item_id),
        limit + 1,
    )
    .await?;
    if items.is_empty() {
        return Err(DnsGroupError::NotFound);
    }
    let has_more = items.len() > usize::try_from(limit).unwrap_or(usize::MAX);
    if has_more {
        items.pop();
    }
    let next_cursor = if has_more {
        items
            .last()
            .map(|item| {
                state.tokens.encode(&VariantCursor {
                    item_id: item.item_id,
                })
            })
            .transpose()?
    } else {
        None
    };
    Ok(Json(VariantPage { items, next_cursor }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_deterministic_tenant_bound_and_tamper_evident() {
        let codec = GroupTokenCodec {
            key: Arc::new([9; 32]),
        };
        let payload = GroupTokenPayload {
            format_version: 1,
            organization_id: Uuid::from_u128(1),
            project_id: Uuid::from_u128(2),
            application_id: Uuid::from_u128(3),
            process_command: "/app".into(),
            display_name: "s3.example.com".into(),
        };
        let first = codec.encode(&payload).unwrap();
        assert_eq!(first, codec.encode(&payload).unwrap());
        let decoded: GroupTokenPayload = codec.decode(&first).unwrap();
        assert_eq!(decoded.organization_id, payload.organization_id);
        let mut tampered = first.into_bytes();
        tampered[0] = if tampered[0] == b'0' { b'1' } else { b'0' };
        assert!(
            codec
                .decode::<GroupTokenPayload>(std::str::from_utf8(&tampered).unwrap())
                .is_err()
        );
    }

    #[test]
    fn scope_validation_rejects_ambiguous_inputs() {
        assert!(
            DnsGroupScope {
                search: Some(" ".into()),
                ..Default::default()
            }
            .normalize()
            .is_err()
        );
        assert!(
            DnsGroupScope {
                verdict: Some("maybe".into()),
                ..Default::default()
            }
            .normalize()
            .is_err()
        );
        assert!(page_limit(Some(11), 5, 10).is_err());
    }
}
