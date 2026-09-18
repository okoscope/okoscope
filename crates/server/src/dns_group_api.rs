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

use crate::{
    access_control::resolve_project_access,
    auth::{IdentityPrincipal, UserSessionAuthenticator},
    inventory::CURRENT_INVENTORY_IDENTITY_VERSION,
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
                "unauthorized",
                "invalid or missing bearer credential".into(),
            ),
            Self::Invalid(message) => (StatusCode::BAD_REQUEST, "invalid_request", message),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "logical DNS group not found".into(),
            ),
            Self::Database(error) => {
                tracing::error!(%error, "logical DNS group API database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "internal server error".into(),
                )
            }
        };
        (status, Json(ErrorBody { error, message })).into_response()
    }
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
    message: String,
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
    let organization_id = sqlx::query_scalar("SELECT organization_id FROM projects WHERE id=$1")
        .bind(project_id)
        .fetch_optional(&state.pool)
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
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM applications WHERE organization_id=$1 AND project_id=$2 AND id=$3)").bind(principal.organization_id).bind(project_id).bind(application_id).fetch_one(&state.pool).await?;
    exists.then_some(principal).ok_or(DnsGroupError::NotFound)
}

impl DnsGroupScope {
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

const GROUP_CTE: &str = r#"
WITH scoped AS MATERIALIZED (
 SELECT e.id occurrence_id,i.id item_id,lower(trim(trailing '.' from i.semantic_summary->>'name')) canonical_name,
        upper(i.semantic_summary->>'query_type') query_type,e.process_command,e.observed_at,e.release_id,e.cluster_id,
        e.namespace,e.workload_kind,e.workload_name,e.pod_uid,e.container_name
 FROM runtime_inventory_event_memberships m JOIN runtime_inventory_items i ON i.id=m.item_id
 JOIN runtime_events e ON e.id=m.event_id
 WHERE i.organization_id=$1 AND i.project_id=$2 AND i.application_id=$3 AND i.identity_version=$4
 AND i.inventory_kind='domain' AND i.occurrence_count>0
 AND ($5::uuid IS NULL OR e.release_id=$5) AND ($6::uuid IS NULL OR e.cluster_id=$6)
 AND ($7::text IS NULL OR e.namespace=$7) AND ($8::text IS NULL OR e.workload_kind=$8)
 AND ($9::text IS NULL OR e.workload_name=$9) AND ($10::text IS NULL OR e.container_name=$10)
 AND ($11::timestamptz IS NULL OR e.observed_at >= $11) AND ($12::timestamptz IS NULL OR e.observed_at <= $12)
 AND ($13::text IS NULL OR EXISTS(SELECT 1 FROM runtime_sighting_policy_evaluations p JOIN runtime_policy_states ps ON ps.organization_id=p.organization_id AND ps.project_id=p.project_id AND ps.application_id=p.application_id WHERE p.item_id=i.id AND p.cluster_id=e.cluster_id AND p.namespace=e.namespace AND p.workload_kind=e.workload_kind AND p.workload_name=e.workload_name AND p.pod_uid=e.pod_uid AND p.container_name=e.container_name AND p.policy_state_version=ps.state_version AND p.evaluator_version=$16 AND p.verdict=$13))
 AND ($14::bool IS NULL OR $14=EXISTS(SELECT 1 FROM runtime_policy_suppressions z WHERE z.organization_id=i.organization_id AND z.project_id=i.project_id AND z.application_id=i.application_id AND z.identity_version=i.identity_version AND z.identity_digest=i.identity_digest AND z.cancelled_at IS NULL AND z.expires_at>now() AND (cardinality(z.cluster_ids)=0 OR e.cluster_id=ANY(z.cluster_ids)) AND (cardinality(z.namespaces)=0 OR e.namespace=ANY(z.namespaces)) AND (cardinality(z.workload_kinds)=0 OR e.workload_kind=ANY(z.workload_kinds)) AND (cardinality(z.workload_names)=0 OR e.workload_name=ANY(z.workload_names))))
 AND ($15::bool IS NULL OR $15=EXISTS(SELECT 1 FROM runtime_inventory_sightings s LEFT JOIN runtime_sighting_policy_evaluations p ON p.item_id=s.item_id AND p.cluster_id=s.cluster_id AND p.namespace=s.namespace AND p.workload_kind=s.workload_kind AND p.workload_name=s.workload_name AND p.pod_uid=s.pod_uid AND p.container_name=s.container_name LEFT JOIN runtime_policy_states ps ON ps.organization_id=s.organization_id AND ps.project_id=s.project_id AND ps.application_id=s.application_id WHERE s.item_id=i.id AND s.cluster_id=e.cluster_id AND s.namespace=e.namespace AND s.workload_kind=e.workload_kind AND s.workload_name=e.workload_name AND s.pod_uid=e.pod_uid AND s.container_name=e.container_name AND (p.item_id IS NULL OR p.policy_state_version<>COALESCE(ps.state_version,0) OR p.evaluator_version<>$16)))
), candidates AS MATERIALIZED (
 SELECT s.*,candidate.candidate_name,candidate.suffix_kind
 FROM scoped s
 CROSS JOIN LATERAL (
  VALUES
   (left(s.canonical_name,-length('.'||lower(s.namespace)||'.svc.cluster.local')),'namespace'),
   (left(s.canonical_name,-length('.svc.cluster.local')),'service'),
   (left(s.canonical_name,-length('.cluster.local')),'cluster')
 ) candidate(candidate_name,suffix_kind)
 WHERE (candidate.suffix_kind='namespace' AND s.canonical_name LIKE ('%.'||lower(s.namespace)||'.svc.cluster.local'))
    OR (candidate.suffix_kind='service' AND s.canonical_name LIKE '%.svc.cluster.local')
    OR (candidate.suffix_kind='cluster' AND s.canonical_name LIKE '%.cluster.local')
), candidate_evidence AS MATERIALIZED (
 SELECT candidate_name,process_command,cluster_id,namespace,pod_uid,container_name,
        count(DISTINCT canonical_name) exact_name_count,count(DISTINCT suffix_kind) suffix_kind_count
 FROM candidates
 GROUP BY candidate_name,process_command,cluster_id,namespace,pod_uid,container_name
), normalized AS MATERIALIZED (
 SELECT s.*,COALESCE(selected.candidate_name,s.canonical_name) display_name
 FROM scoped s
 LEFT JOIN LATERAL (
  SELECT c.candidate_name
  FROM candidates c
  JOIN candidate_evidence evidence ON evidence.candidate_name=c.candidate_name
   AND evidence.process_command=c.process_command AND evidence.cluster_id=c.cluster_id
   AND evidence.namespace=c.namespace AND evidence.pod_uid IS NOT DISTINCT FROM c.pod_uid
   AND evidence.container_name=c.container_name
  WHERE c.occurrence_id=s.occurrence_id AND c.item_id=s.item_id
   AND (EXISTS(
    SELECT 1 FROM scoped corroborating
    WHERE corroborating.process_command=c.process_command AND corroborating.canonical_name=c.candidate_name
     AND corroborating.cluster_id=c.cluster_id AND corroborating.namespace=c.namespace
     AND corroborating.pod_uid IS NOT DISTINCT FROM c.pod_uid
     AND corroborating.container_name=c.container_name
   ) OR (evidence.exact_name_count>=2 AND evidence.suffix_kind_count>=2))
  ORDER BY length(c.candidate_name) DESC,c.candidate_name
  LIMIT 1
 ) selected ON true
), groups AS MATERIALIZED (
 SELECT display_name,process_command,CASE WHEN bool_or(display_name<>canonical_name) THEN 'kubernetes_search_expansion' ELSE 'canonical_name' END grouping_reason,
 CASE WHEN bool_or(display_name<>canonical_name) THEN 'high' ELSE 'exact' END confidence,
 min(observed_at) first_seen_at,max(observed_at) last_seen_at,count(DISTINCT occurrence_id)::bigint observation_count,
 count(DISTINCT (item_id,canonical_name,query_type))::bigint variant_count,array_agg(DISTINCT query_type ORDER BY query_type) query_types,
 count(DISTINCT release_id)::bigint release_count,count(DISTINCT cluster_id)::bigint cluster_count,
 count(DISTINCT (cluster_id,namespace))::bigint namespace_count,count(DISTINCT (cluster_id,namespace,workload_kind,workload_name))::bigint workload_count,
 count(DISTINCT (cluster_id,pod_uid))::bigint pod_count,count(DISTINCT container_name)::bigint container_count,
 array_agg(DISTINCT canonical_name) exact_names
 FROM normalized GROUP BY display_name,process_command
)"#;

fn bind_scope<'q>(
    query: sqlx::query::QueryAs<'q, sqlx::Postgres, GroupRow, sqlx::postgres::PgArguments>,
    principal: Principal,
    project_id: Uuid,
    application_id: Uuid,
    scope: &'q DnsGroupScope,
) -> sqlx::query::QueryAs<'q, sqlx::Postgres, GroupRow, sqlx::postgres::PgArguments> {
    query
        .bind(principal.organization_id)
        .bind(project_id)
        .bind(application_id)
        .bind(CURRENT_INVENTORY_IDENTITY_VERSION.get())
        .bind(scope.release_id)
        .bind(scope.cluster_id)
        .bind(scope.namespace.as_deref())
        .bind(scope.workload_kind.as_deref())
        .bind(scope.workload_name.as_deref())
        .bind(scope.container_name.as_deref())
        .bind(scope.observed_from)
        .bind(scope.observed_to)
        .bind(scope.verdict.as_deref())
        .bind(scope.suppressed)
        .bind(scope.evaluation_pending)
        .bind(crate::policy::POLICY_EVALUATOR_VERSION)
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
    let sql = format!(
        "{GROUP_CTE}, filtered AS (SELECT *,count(*) OVER()::bigint total_group_count,sum(observation_count) OVER()::bigint total_observation_count FROM groups WHERE ($17::text IS NULL OR display_name ILIKE $17 OR EXISTS(SELECT 1 FROM unnest(exact_names) n WHERE n ILIKE $17))) SELECT display_name,process_command,grouping_reason,confidence,first_seen_at,last_seen_at,observation_count,variant_count,query_types,release_count,cluster_count,namespace_count,workload_count,pod_count,container_count,total_group_count,total_observation_count FROM filtered WHERE ($18::timestamptz IS NULL OR (last_seen_at,display_name,process_command)<($18,$19,$20)) ORDER BY last_seen_at DESC,display_name DESC,process_command DESC LIMIT $21"
    );
    let pattern = scope.search.as_ref().map(|value| format!("%{value}%"));
    let mut rows = bind_scope(
        sqlx::query_as(&sql),
        principal,
        project_id,
        application_id,
        &scope,
    )
    .bind(pattern)
    .bind(cursor.as_ref().map(|v| v.last_seen_at))
    .bind(cursor.as_ref().map(|v| v.display_name.as_str()))
    .bind(cursor.as_ref().map(|v| v.process_command.as_str()))
    .bind(limit + 1)
    .fetch_all(&state.pool)
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
    let sql = format!(
        "{GROUP_CTE}, filtered AS (SELECT *,count(*) OVER()::bigint total_group_count,sum(observation_count) OVER()::bigint total_observation_count FROM groups WHERE ($17::text IS NULL OR display_name ILIKE $17 OR EXISTS(SELECT 1 FROM unnest(exact_names) n WHERE n ILIKE $17))) SELECT display_name,process_command,grouping_reason,confidence,first_seen_at,last_seen_at,observation_count,variant_count,query_types,release_count,cluster_count,namespace_count,workload_count,pod_count,container_count,total_group_count,total_observation_count FROM filtered ORDER BY observation_count DESC,display_name ASC,process_command ASC LIMIT $18"
    );
    let pattern = scope.search.as_ref().map(|value| format!("%{value}%"));
    let rows = bind_scope(
        sqlx::query_as(&sql),
        principal,
        project_id,
        application_id,
        &scope,
    )
    .bind(pattern)
    .bind(limit)
    .fetch_all(&state.pool)
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
    let sql = format!(
        "{GROUP_CTE}, selected AS (SELECT n.item_id,n.canonical_name name,n.query_type,min(n.observed_at) first_seen_at,max(n.observed_at) last_seen_at,count(DISTINCT n.occurrence_id)::bigint observation_count FROM normalized n WHERE n.display_name=$17 AND n.process_command=$18 GROUP BY n.item_id,n.canonical_name,n.query_type) SELECT item_id,name,query_type,first_seen_at,last_seen_at,observation_count FROM selected WHERE ($19::uuid IS NULL OR item_id>$19) ORDER BY item_id ASC LIMIT $20"
    );
    let mut items: Vec<VariantRow> = bind_variant_scope(
        sqlx::query_as(&sql),
        principal,
        project_id,
        application_id,
        &scope,
    )
    .bind(&token.display_name)
    .bind(&token.process_command)
    .bind(cursor.as_ref().map(|v| v.item_id))
    .bind(limit + 1)
    .fetch_all(&state.pool)
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

fn bind_variant_scope<'q>(
    query: sqlx::query::QueryAs<'q, sqlx::Postgres, VariantRow, sqlx::postgres::PgArguments>,
    principal: Principal,
    project_id: Uuid,
    application_id: Uuid,
    scope: &'q DnsGroupScope,
) -> sqlx::query::QueryAs<'q, sqlx::Postgres, VariantRow, sqlx::postgres::PgArguments> {
    query
        .bind(principal.organization_id)
        .bind(project_id)
        .bind(application_id)
        .bind(CURRENT_INVENTORY_IDENTITY_VERSION.get())
        .bind(scope.release_id)
        .bind(scope.cluster_id)
        .bind(scope.namespace.as_deref())
        .bind(scope.workload_kind.as_deref())
        .bind(scope.workload_name.as_deref())
        .bind(scope.container_name.as_deref())
        .bind(scope.observed_from)
        .bind(scope.observed_to)
        .bind(scope.verdict.as_deref())
        .bind(scope.suppressed)
        .bind(scope.evaluation_pending)
        .bind(crate::policy::POLICY_EVALUATOR_VERSION)
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
