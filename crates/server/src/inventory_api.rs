use std::{
    sync::{Arc, OnceLock},
    time::Instant,
};

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
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::{
    auth::{UserPrincipal, UserSessionAuthenticator},
    inventory::CURRENT_INVENTORY_IDENTITY_VERSION,
};

#[derive(Clone, Debug)]
struct InventoryApiState {
    pool: PgPool,
    auth: UserSessionAuthenticator,
    identity_tokens: IdentityTokenCodec,
}

type HmacSha256 = Hmac<Sha256>;
const IDENTITY_TOKEN_TTL_SECONDS: i64 = 86_400;

#[derive(Clone, Debug)]
struct IdentityTokenCodec {
    key: Arc<[u8; 32]>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct IdentityTokenPayload {
    format_version: u8,
    identity_version: i16,
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    kind: String,
    item_id: Uuid,
    identity_digest: String,
    issued_at: i64,
    expires_at: i64,
}

impl IdentityTokenCodec {
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

    fn issue(&self, mut payload: IdentityTokenPayload) -> Result<String, InventoryApiError> {
        let now = Utc::now().timestamp();
        payload.issued_at = now - now.rem_euclid(IDENTITY_TOKEN_TTL_SECONDS);
        payload.expires_at = payload.issued_at + IDENTITY_TOKEN_TTL_SECONDS * 2;
        self.encode(&payload)
    }

    fn encode(&self, payload: &IdentityTokenPayload) -> Result<String, InventoryApiError> {
        let encoded = hex::encode(
            serde_json::to_vec(payload)
                .map_err(|_| InventoryApiError::IdentityToken("invalid_identity_token"))?,
        );
        let mut mac = HmacSha256::new_from_slice(self.key.as_ref())
            .map_err(|_| InventoryApiError::IdentityToken("invalid_identity_token"))?;
        mac.update(encoded.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());
        Ok(format!(
            "{}.{}.{}",
            payload.identity_digest, encoded, signature
        ))
    }

    fn validate(
        &self,
        token: &str,
        expected: (Uuid, Uuid, Uuid, Option<&str>),
    ) -> Result<IdentityTokenPayload, InventoryApiError> {
        if token.is_empty() || token.len() > 1000 {
            return Err(InventoryApiError::IdentityToken("invalid_identity_token"));
        }
        let mut parts = token.split('.');
        let digest_prefix = parts.next().unwrap_or_default();
        let encoded = parts.next().unwrap_or_default();
        let signature = parts.next().unwrap_or_default();
        if parts.next().is_some() || digest_prefix.len() != 64 {
            return Err(InventoryApiError::IdentityToken("invalid_identity_token"));
        }
        let signature = hex::decode(signature)
            .map_err(|_| InventoryApiError::IdentityToken("invalid_identity_token"))?;
        let mut mac = HmacSha256::new_from_slice(self.key.as_ref())
            .map_err(|_| InventoryApiError::IdentityToken("invalid_identity_token"))?;
        mac.update(encoded.as_bytes());
        mac.verify_slice(&signature)
            .map_err(|_| InventoryApiError::IdentityToken("invalid_identity_token"))?;
        let payload: IdentityTokenPayload = serde_json::from_slice(
            &hex::decode(encoded)
                .map_err(|_| InventoryApiError::IdentityToken("invalid_identity_token"))?,
        )
        .map_err(|_| InventoryApiError::IdentityToken("invalid_identity_token"))?;
        if payload.identity_digest != digest_prefix || hex::decode(digest_prefix).is_err() {
            return Err(InventoryApiError::IdentityToken("invalid_identity_token"));
        }
        if Utc::now().timestamp() >= payload.expires_at {
            return Err(InventoryApiError::IdentityToken("expired_identity_token"));
        }
        if payload.format_version != 1
            || payload.identity_version != CURRENT_INVENTORY_IDENTITY_VERSION.get()
            || payload.organization_id != expected.0
            || payload.project_id != expected.1
            || payload.application_id != expected.2
            || expected.3.is_some_and(|kind| payload.kind != kind)
        {
            return Err(InventoryApiError::IdentityToken(
                "identity_token_scope_mismatch",
            ));
        }
        Ok(payload)
    }
}

pub fn router(pool: PgPool) -> Router {
    let state = InventoryApiState {
        auth: UserSessionAuthenticator::new(pool.clone()),
        identity_tokens: IdentityTokenCodec::process_default(),
        pool,
    };
    Router::new()
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory",
            get(list_items),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/summary",
            get(summary),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/distribution",
            get(distribution),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/facets/{facet}",
            get(facets),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/{item_id}",
            get(item_detail),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/{item_id}/releases",
            get(item_releases),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/{item_id}/sightings",
            get(item_sightings),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/{item_id}/groups",
            get(item_groups),
        )
        .route(
            "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/{item_id}/occurrences",
            get(item_occurrences),
        )
        .with_state(state)
}

#[derive(Debug)]
enum InventoryApiError {
    Unauthorized,
    Invalid(String),
    IdentityToken(&'static str),
    NotFound,
    Database(sqlx::Error),
}

impl From<sqlx::Error> for InventoryApiError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

impl IntoResponse for InventoryApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "invalid or missing bearer credential".to_owned(),
            ),
            Self::Invalid(message) => (StatusCode::BAD_REQUEST, "invalid_request", message),
            Self::IdentityToken(code) => (
                StatusCode::BAD_REQUEST,
                code,
                "identity token is invalid for this request".to_owned(),
            ),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "runtime inventory resource not found".to_owned(),
            ),
            Self::Database(error) => {
                tracing::error!(error=%error, "runtime inventory API database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "internal server error".to_owned(),
                )
            }
        };
        (
            status,
            Json(ErrorBody {
                error: code,
                message,
            }),
        )
            .into_response()
    }
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
    message: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct InventoryScope {
    operation: Option<String>,
    release_id: Option<Uuid>,
    cluster_id: Option<Uuid>,
    namespace: Option<String>,
    workload_kind: Option<String>,
    workload_name: Option<String>,
    container_name: Option<String>,
    observed_from: Option<DateTime<Utc>>,
    observed_to: Option<DateTime<Utc>>,
    search: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct InventoryQuery {
    #[serde(flatten)]
    scope: InventoryScope,
    kind: Option<String>,
    identity_token: Option<String>,
    verdict: Option<String>,
    suppressed: Option<bool>,
    evaluation_pending: Option<bool>,
    cursor: Option<Uuid>,
    limit: Option<i64>,
}

#[derive(Clone, Debug, Deserialize)]
struct SummaryQuery {
    #[serde(flatten)]
    scope: InventoryScope,
}

#[derive(Clone, Debug, Deserialize)]
struct DistributionQuery {
    #[serde(flatten)]
    scope: InventoryScope,
    kind: String,
    limit: Option<i64>,
}

#[derive(Clone, Debug, FromRow)]
struct DistributionRow {
    id: Uuid,
    identity_digest: Vec<u8>,
    semantic_summary: Value,
    occurrence_count: i64,
    total_item_count: i64,
    total_occurrence_count: i64,
}

#[derive(Debug, Serialize)]
struct DistributionEntry {
    identity_token: String,
    semantic_summary: Value,
    item_count: i64,
    occurrence_count: i64,
}

#[derive(Debug, Serialize)]
struct DistributionOther {
    item_count: i64,
    occurrence_count: i64,
}

#[derive(Debug, Serialize)]
struct InventoryDistribution {
    coverage: crate::runtime_retention::history::Coverage,
    identity_version: i16,
    kind: String,
    total_item_count: i64,
    total_occurrence_count: i64,
    entries: Vec<DistributionEntry>,
    other: Option<DistributionOther>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum InventoryFacet {
    Cluster,
    Namespace,
    WorkloadKind,
    WorkloadName,
    ContainerName,
}

impl InventoryFacet {
    fn clear_selected_filter(self, scope: &mut InventoryScope) {
        match self {
            Self::Cluster => scope.cluster_id = None,
            Self::Namespace => scope.namespace = None,
            Self::WorkloadKind => scope.workload_kind = None,
            Self::WorkloadName => scope.workload_name = None,
            Self::ContainerName => scope.container_name = None,
        }
    }

    fn parse(value: &str) -> Result<Self, InventoryApiError> {
        match value {
            "cluster" => Ok(Self::Cluster),
            "namespace" => Ok(Self::Namespace),
            "workload_kind" => Ok(Self::WorkloadKind),
            "workload_name" => Ok(Self::WorkloadName),
            "container_name" => Ok(Self::ContainerName),
            _ => Err(InventoryApiError::Invalid(
                "unsupported inventory facet".into(),
            )),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Cluster => "cluster",
            Self::Namespace => "namespace",
            Self::WorkloadKind => "workload_kind",
            Self::WorkloadName => "workload_name",
            Self::ContainerName => "container_name",
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct FacetQuery {
    #[serde(flatten)]
    scope: InventoryScope,
    kind: Option<String>,
    facet_search: Option<String>,
    cursor: Option<String>,
    limit: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct FacetCursor {
    facet: String,
    scope: String,
    item_count: i64,
    label: String,
    value: String,
}

#[derive(Clone, Debug, FromRow, Serialize)]
struct FacetOption {
    value: String,
    label: String,
    item_count: i64,
    occurrence_count: i64,
}

#[derive(Debug, Serialize)]
struct FacetPage {
    coverage: crate::runtime_retention::history::Coverage,
    items: Vec<FacetOption>,
    next_cursor: Option<String>,
}

struct FacetLoad {
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    facet: InventoryFacet,
    kind: Option<String>,
    scope: InventoryScope,
    facet_search: Option<String>,
    cursor: Option<FacetCursor>,
    limit: i64,
}

#[derive(Clone, Debug, Deserialize)]
struct PageQuery {
    cursor: Option<Uuid>,
    limit: Option<i64>,
}

#[derive(Clone, Debug, Deserialize)]
struct StringCursorPageQuery {
    cursor: Option<String>,
    limit: Option<i64>,
}

#[derive(Clone, Debug, FromRow, Serialize)]
struct InventoryItem {
    id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    inventory_kind: String,
    identity_version: i16,
    semantic_summary: Value,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    occurrence_count: i64,
    release_count: i64,
    cluster_count: i64,
    namespace_count: i64,
    workload_count: i64,
    pod_count: i64,
    container_count: i64,
    group_count: i64,
}

#[derive(Debug, Serialize)]
struct InventoryItemPage {
    coverage: crate::runtime_retention::history::Coverage,
    items: Vec<InventoryItem>,
    next_cursor: Option<Uuid>,
}

#[derive(Clone, Debug, FromRow, Serialize)]
struct KindCount {
    kind: String,
    item_count: i64,
    occurrence_count: i64,
}

#[derive(Debug, FromRow)]
struct KindAggregate {
    kind: String,
    item_count: i64,
    occurrence_count: i64,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct InventorySummary {
    coverage: crate::runtime_retention::history::Coverage,
    identity_version: i16,
    item_count: i64,
    occurrence_count: i64,
    first_seen_at: Option<DateTime<Utc>>,
    last_seen_at: Option<DateTime<Utc>>,
    kinds: Vec<KindCount>,
}

#[derive(Debug, Serialize)]
struct InventoryItemDetail {
    coverage: crate::runtime_retention::history::Coverage,
    #[serde(flatten)]
    item: InventoryItem,
    evidence: EvidenceLinks,
    policy_placement_summary: Value,
}

#[derive(Debug, Serialize)]
struct EvidenceLinks {
    releases: String,
    sightings: String,
    groups: String,
    occurrences: String,
}

impl EvidenceLinks {
    fn scoped(project_id: Uuid, application_id: Uuid, item_id: Uuid) -> Self {
        let base = format!(
            "/api/v1/projects/{project_id}/applications/{application_id}/runtime-inventory/{item_id}"
        );
        Self {
            releases: format!("{base}/releases"),
            sightings: format!("{base}/sightings"),
            groups: format!("{base}/groups"),
            occurrences: format!("{base}/occurrences"),
        }
    }
}

#[derive(Clone, Debug, FromRow, Serialize)]
struct ReleasePresence {
    release_id: Uuid,
    release_display_name: String,
    version: String,
    deployed_at: DateTime<Utc>,
    presence: String,
    occurrence_count: Option<i64>,
    first_seen_at: Option<DateTime<Utc>>,
    last_seen_at: Option<DateTime<Utc>>,
    release_evidence_count: i64,
}

#[derive(Debug, Serialize)]
struct ReleasePresencePage {
    coverage: crate::runtime_retention::history::Coverage,
    items: Vec<ReleasePresence>,
    next_cursor: Option<Uuid>,
}

#[derive(Clone, Debug, FromRow, Serialize)]
struct InventorySighting {
    cluster_id: Uuid,
    namespace: String,
    workload_kind: String,
    workload_name: String,
    pod_uid: String,
    pod_name: String,
    container_name: String,
    occurrence_count: i64,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    policy_evaluation: Value,
    active_suppression: Option<Value>,
    actionable: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SightingCursor {
    last_seen_at: DateTime<Utc>,
    cluster_id: Uuid,
    namespace: String,
    workload_kind: String,
    workload_name: String,
    pod_uid: String,
    container_name: String,
}

#[derive(Debug, Serialize)]
struct SightingPage {
    coverage: crate::runtime_retention::history::Coverage,
    items: Vec<InventorySighting>,
    next_cursor: Option<String>,
}

#[derive(Clone, Debug, FromRow, Serialize)]
struct InventoryGroup {
    id: Uuid,
    cluster_id: Uuid,
    namespace: String,
    workload_kind: String,
    workload_name: String,
    event_kind: String,
    status: String,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    occurrence_count: i64,
}

#[derive(Debug, Serialize)]
struct GroupPage {
    coverage: crate::runtime_retention::history::Coverage,
    items: Vec<InventoryGroup>,
    next_cursor: Option<Uuid>,
}

#[derive(Clone, Debug, FromRow, Serialize)]
struct InventoryOccurrence {
    id: Uuid,
    event_id: Uuid,
    observed_at: DateTime<Utc>,
    cluster_id: Uuid,
    node_name: String,
    namespace: String,
    pod_uid: String,
    pod_name: String,
    container_name: String,
    process_command: String,
    event_kind: String,
    payload: Value,
    release_id: Option<Uuid>,
    release_version: Option<String>,
    release_display_name: String,
}

#[derive(Debug, Serialize)]
struct OccurrencePage {
    coverage: crate::runtime_retention::history::Coverage,
    items: Vec<InventoryOccurrence>,
    next_cursor: Option<Uuid>,
}

async fn principal(
    headers: &HeaderMap,
    state: &InventoryApiState,
) -> Result<UserPrincipal, InventoryApiError> {
    state
        .auth
        .authenticate_headers(headers)
        .await?
        .ok_or(InventoryApiError::Unauthorized)
}

fn limit(value: Option<i64>) -> Result<i64, InventoryApiError> {
    let value = value.unwrap_or(50);
    if (1..=200).contains(&value) {
        Ok(value)
    } else {
        Err(InventoryApiError::Invalid(
            "limit must be between 1 and 200".into(),
        ))
    }
}

fn aggregate_limit(value: Option<i64>) -> Result<i64, InventoryApiError> {
    let value = value.unwrap_or(5);
    if (1..=10).contains(&value) {
        Ok(value)
    } else {
        Err(InventoryApiError::Invalid(
            "limit must be between 1 and 10".into(),
        ))
    }
}

fn validate_kind(kind: Option<&str>) -> Result<(), InventoryApiError> {
    if kind.is_none_or(|value| {
        matches!(
            value,
            "process"
                | "destination"
                | "domain"
                | "syscall"
                | "inbound_endpoint"
                | "file_activity"
                | "lifecycle"
        )
    }) {
        Ok(())
    } else {
        Err(InventoryApiError::Invalid(
            "kind must be process, destination, domain, syscall, inbound_endpoint, file_activity, or lifecycle".into(),
        ))
    }
}

fn validate_search(search: Option<&str>) -> Result<(), InventoryApiError> {
    if search.is_none_or(|value| !value.is_empty() && value.chars().count() <= 200) {
        Ok(())
    } else {
        Err(InventoryApiError::Invalid(
            "search must contain between 1 and 200 characters".into(),
        ))
    }
}

fn record_validation<T>(
    result: Result<T, InventoryApiError>,
    operation: &'static str,
    failure_class: &'static str,
    cursor: bool,
) -> Result<T, InventoryApiError> {
    if result.is_err() {
        crate::metrics::record_inventory_validation_failure(cursor);
        tracing::warn!(
            operation,
            failure_class,
            "runtime inventory request rejected"
        );
    }
    result
}

impl InventoryScope {
    fn normalize(mut self) -> Result<Self, InventoryApiError> {
        validate_search(self.search.as_deref())?;
        if self
            .operation
            .as_deref()
            .is_some_and(|value| !matches!(value, "create" | "modify" | "delete" | "rename"))
        {
            return Err(InventoryApiError::Invalid(
                "operation must be create, modify, delete, or rename".into(),
            ));
        }
        if self
            .observed_from
            .zip(self.observed_to)
            .is_some_and(|(from, to)| from > to)
        {
            return Err(InventoryApiError::Invalid(
                "observed_from must not be after observed_to".into(),
            ));
        }
        for (name, value) in [
            ("namespace", &mut self.namespace),
            ("workload_kind", &mut self.workload_kind),
            ("workload_name", &mut self.workload_name),
            ("container_name", &mut self.container_name),
        ] {
            if let Some(text) = value {
                *text = text.trim().to_owned();
                if text.is_empty() || text.chars().count() > 253 {
                    return Err(InventoryApiError::Invalid(format!(
                        "{name} must contain between 1 and 253 characters"
                    )));
                }
            }
        }
        Ok(self)
    }

    fn fingerprint(&self, scope: (Uuid, Uuid, Uuid), kind: Option<&str>) -> String {
        let bytes = serde_json::to_vec(&(scope, kind, self))
            .expect("serializing normalized inventory filters cannot fail");
        hex::encode(Sha256::digest(bytes))
    }

    fn search_pattern(&self) -> Option<String> {
        self.search.as_ref().map(|value| format!("%{value}%"))
    }
}

async fn validate_release_scope(
    pool: &PgPool,
    principal: UserPrincipal,
    project_id: Uuid,
    application_id: Uuid,
    release_id: Option<Uuid>,
) -> Result<(), InventoryApiError> {
    let Some(release_id) = release_id else {
        return Ok(());
    };
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM releases WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND id=$4)")
        .bind(principal.organization_id).bind(project_id).bind(application_id).bind(release_id)
        .fetch_one(pool).await?;
    if exists {
        Ok(())
    } else {
        Err(InventoryApiError::Invalid(
            "release_id is invalid for this application".into(),
        ))
    }
}

async fn ensure_application(
    pool: &PgPool,
    principal: UserPrincipal,
    project_id: Uuid,
    application_id: Uuid,
) -> Result<(), InventoryApiError> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM applications WHERE organization_id=$1 AND project_id=$2 AND id=$3)")
        .bind(principal.organization_id)
        .bind(project_id)
        .bind(application_id)
        .fetch_one(pool)
        .await?;
    exists.then_some(()).ok_or(InventoryApiError::NotFound)
}

async fn ensure_item(
    pool: &PgPool,
    principal: UserPrincipal,
    project_id: Uuid,
    application_id: Uuid,
    item_id: Uuid,
) -> Result<(), InventoryApiError> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM runtime_inventory_items WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND id=$4 AND identity_version=$5)")
        .bind(principal.organization_id)
        .bind(project_id)
        .bind(application_id)
        .bind(item_id)
        .bind(CURRENT_INVENTORY_IDENTITY_VERSION.get())
        .fetch_one(pool)
        .await?;
    exists.then_some(()).ok_or(InventoryApiError::NotFound)
}

async fn summary(
    State(state): State<InventoryApiState>,
    headers: HeaderMap,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<SummaryQuery>,
) -> Result<Json<InventorySummary>, InventoryApiError> {
    let started = Instant::now();
    let principal = principal(&headers, &state).await?;
    ensure_application(&state.pool, principal, project_id, application_id).await?;
    let scope = record_validation(query.scope.normalize(), "summary", "scope", false)?;
    record_validation(
        validate_release_scope(
            &state.pool,
            principal,
            project_id,
            application_id,
            scope.release_id,
        )
        .await,
        "summary",
        "release_scope",
        false,
    )?;
    let version = CURRENT_INVENTORY_IDENTITY_VERSION.get();
    let search = scope.search_pattern();
    let rows: Vec<KindAggregate> =
        sqlx::query_as("SELECT CASE WHEN i.inventory_kind IN ('process_exit','container_termination','container_restart') THEN 'lifecycle' ELSE i.inventory_kind END kind,count(*)::bigint item_count,COALESCE(sum(i.occurrence_count),0)::bigint occurrence_count,min(i.first_seen_at) first_seen_at,max(i.last_seen_at) last_seen_at FROM runtime_inventory_items i WHERE i.occurrence_count>0 AND i.organization_id=$1 AND i.project_id=$2 AND i.application_id=$3 AND i.identity_version=$4 AND ($5::uuid IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_releases r WHERE r.item_id=i.id AND r.release_id=$5)) AND ($6::uuid IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.cluster_id=$6)) AND ($7::text IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.namespace=$7)) AND ($8::text IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.workload_kind=$8)) AND ($9::text IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.workload_name=$9)) AND ($10::text IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.container_name=$10)) AND ($11::timestamptz IS NULL OR i.last_seen_at >= $11) AND ($12::timestamptz IS NULL OR i.first_seen_at <= $12) AND ($13::text IS NULL OR i.semantic_summary->>'operation'=$13) AND ($14::text IS NULL OR concat_ws(' ',i.semantic_summary->>'executable',i.semantic_summary->>'process_command',i.semantic_summary->>'destination_address',i.semantic_summary->>'destination_port',i.semantic_summary->>'local_address',i.semantic_summary->>'local_port',i.semantic_summary->>'name',i.semantic_summary->>'query_type',i.semantic_summary->>'syscall',i.semantic_summary->>'operation',i.semantic_summary->>'path',i.semantic_summary->>'new_path') ILIKE $14) GROUP BY 1")
            .bind(principal.organization_id).bind(project_id).bind(application_id).bind(version)
            .bind(scope.release_id).bind(scope.cluster_id).bind(scope.namespace.as_deref()).bind(scope.workload_kind.as_deref()).bind(scope.workload_name.as_deref()).bind(scope.container_name.as_deref()).bind(scope.observed_from).bind(scope.observed_to).bind(scope.operation.as_deref()).bind(search.as_deref())
            .fetch_all(&state.pool).await?;
    let mut kinds: Vec<_> = [
        "destination",
        "domain",
        "inbound_endpoint",
        "file_activity",
        "lifecycle",
        "process",
        "syscall",
    ]
    .into_iter()
    .map(|kind| KindCount {
        kind: kind.into(),
        item_count: 0,
        occurrence_count: 0,
    })
    .collect();
    let mut first_seen_at: Option<DateTime<Utc>> = None;
    let mut last_seen_at: Option<DateTime<Utc>> = None;
    for row in rows {
        let kind = kinds
            .iter_mut()
            .find(|kind| kind.kind == row.kind)
            .expect("database inventory kind constraint must match the API contract");
        kind.item_count = row.item_count;
        kind.occurrence_count = row.occurrence_count;
        first_seen_at =
            Some(first_seen_at.map_or(row.first_seen_at, |value| value.min(row.first_seen_at)));
        last_seen_at =
            Some(last_seen_at.map_or(row.last_seen_at, |value| value.max(row.last_seen_at)));
    }
    let item_count = kinds.iter().map(|kind| kind.item_count).sum();
    let occurrence_count = kinds.iter().map(|kind| kind.occurrence_count).sum();
    let elapsed_micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    crate::metrics::record_inventory_query(elapsed_micros);
    crate::metrics::record_inventory_summary(elapsed_micros, kinds.len());
    tracing::debug!(
        operation = "summary",
        elapsed_micros,
        result_size = kinds.len()
    );
    Ok(Json(InventorySummary {
        coverage: crate::runtime_retention::history::coverage(
            &state.pool,
            principal.organization_id,
            project_id,
        )
        .await?,
        identity_version: version,
        item_count,
        occurrence_count,
        first_seen_at,
        last_seen_at,
        kinds,
    }))
}

#[allow(clippy::too_many_lines)]
async fn distribution(
    State(state): State<InventoryApiState>,
    headers: HeaderMap,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<DistributionQuery>,
) -> Result<Json<InventoryDistribution>, InventoryApiError> {
    let started = Instant::now();
    let principal = principal(&headers, &state).await?;
    ensure_application(&state.pool, principal, project_id, application_id).await?;
    validate_kind(Some(&query.kind))?;
    let scope = query.scope.normalize()?;
    validate_release_scope(
        &state.pool,
        principal,
        project_id,
        application_id,
        scope.release_id,
    )
    .await?;
    let limit = aggregate_limit(query.limit)?;
    let version = CURRENT_INVENTORY_IDENTITY_VERSION.get();
    let search = scope.search_pattern();
    let rows = sqlx::query_as::<_, DistributionRow>(
        "WITH scoped AS MATERIALIZED (SELECT i.id,i.identity_digest,i.semantic_summary,i.occurrence_count FROM runtime_inventory_items i WHERE i.occurrence_count>0 AND i.organization_id=$1 AND i.project_id=$2 AND i.application_id=$3 AND i.identity_version=$4 AND i.inventory_kind=$5 AND ($6::uuid IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_releases r WHERE r.item_id=i.id AND r.release_id=$6)) AND ($7::uuid IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.cluster_id=$7)) AND ($8::text IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.namespace=$8)) AND ($9::text IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.workload_kind=$9)) AND ($10::text IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.workload_name=$10)) AND ($11::text IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.container_name=$11)) AND ($12::timestamptz IS NULL OR i.last_seen_at >= $12) AND ($13::timestamptz IS NULL OR i.first_seen_at <= $13) AND ($14::text IS NULL OR i.semantic_summary->>'operation'=$14) AND ($15::text IS NULL OR concat_ws(' ',i.semantic_summary->>'executable',i.semantic_summary->>'process_command',i.semantic_summary->>'destination_address',i.semantic_summary->>'destination_port',i.semantic_summary->>'local_address',i.semantic_summary->>'local_port',i.semantic_summary->>'name',i.semantic_summary->>'query_type',i.semantic_summary->>'syscall',i.semantic_summary->>'operation',i.semantic_summary->>'path',i.semantic_summary->>'new_path') ILIKE $15)), ranked AS (SELECT id,identity_digest,semantic_summary,occurrence_count,count(*) OVER()::bigint total_item_count,COALESCE(sum(occurrence_count) OVER(),0)::bigint total_occurrence_count FROM scoped) SELECT id,identity_digest,semantic_summary,occurrence_count,total_item_count,total_occurrence_count FROM ranked ORDER BY occurrence_count DESC,identity_digest ASC LIMIT $16",
    )
    .bind(principal.organization_id)
    .bind(project_id)
    .bind(application_id)
    .bind(version)
    .bind(&query.kind)
    .bind(scope.release_id)
    .bind(scope.cluster_id)
    .bind(scope.namespace.as_deref())
    .bind(scope.workload_kind.as_deref())
    .bind(scope.workload_name.as_deref())
    .bind(scope.container_name.as_deref())
    .bind(scope.observed_from)
    .bind(scope.observed_to)
    .bind(scope.operation.as_deref())
    .bind(search.as_deref())
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;
    let total_item_count = rows.first().map_or(0, |row| row.total_item_count);
    let total_occurrence_count = rows.first().map_or(0, |row| row.total_occurrence_count);
    let mut entry_occurrence_count = 0;
    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        entry_occurrence_count += row.occurrence_count;
        let identity_digest = hex::encode(&row.identity_digest);
        let identity_token = state.identity_tokens.issue(IdentityTokenPayload {
            format_version: 1,
            identity_version: version,
            organization_id: principal.organization_id,
            project_id,
            application_id,
            kind: query.kind.clone(),
            item_id: row.id,
            identity_digest,
            issued_at: 0,
            expires_at: 0,
        })?;
        entries.push(DistributionEntry {
            identity_token,
            semantic_summary: row.semantic_summary,
            item_count: 1,
            occurrence_count: row.occurrence_count,
        });
    }
    let entry_item_count = i64::try_from(entries.len()).unwrap_or(i64::MAX);
    let other_item_count = total_item_count - entry_item_count;
    let other = (other_item_count > 0).then_some(DistributionOther {
        item_count: other_item_count,
        occurrence_count: total_occurrence_count - entry_occurrence_count,
    });
    crate::metrics::record_inventory_query(
        u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
    );
    Ok(Json(InventoryDistribution {
        coverage: crate::runtime_retention::history::coverage(
            &state.pool,
            principal.organization_id,
            project_id,
        )
        .await?,
        identity_version: version,
        kind: query.kind,
        total_item_count,
        total_occurrence_count,
        entries,
        other,
    }))
}

async fn facets(
    State(state): State<InventoryApiState>,
    headers: HeaderMap,
    Path((project_id, application_id, facet_name)): Path<(Uuid, Uuid, String)>,
    Query(query): Query<FacetQuery>,
) -> Result<Json<FacetPage>, InventoryApiError> {
    let started = Instant::now();
    let principal = principal(&headers, &state).await?;
    ensure_application(&state.pool, principal, project_id, application_id).await?;
    let facet = record_validation(
        InventoryFacet::parse(&facet_name),
        "facet",
        "facet_name",
        false,
    )?;
    record_validation(validate_kind(query.kind.as_deref()), "facet", "kind", false)?;
    record_validation(
        validate_search(query.facet_search.as_deref()),
        "facet",
        "option_search",
        false,
    )?;
    let mut scope = record_validation(query.scope.normalize(), "facet", "scope", false)?;
    facet.clear_selected_filter(&mut scope);
    record_validation(
        validate_release_scope(
            &state.pool,
            principal,
            project_id,
            application_id,
            scope.release_id,
        )
        .await,
        "facet",
        "release_scope",
        false,
    )?;
    let limit = record_validation(limit(query.limit), "facet", "limit", false)?;
    let fingerprint = scope.fingerprint(
        (principal.organization_id, project_id, application_id),
        query.kind.as_deref(),
    );
    let cursor = record_validation(
        query
            .cursor
            .as_deref()
            .map(decode_cursor::<FacetCursor>)
            .transpose(),
        "facet",
        "cursor_encoding",
        true,
    )?;
    if cursor.as_ref().is_some_and(|cursor| {
        cursor.facet != facet.name() || cursor.scope != fingerprint || cursor.item_count < 0
    }) {
        crate::metrics::record_inventory_validation_failure(true);
        tracing::warn!(
            operation = "facet",
            failure_class = "cursor_scope",
            "runtime inventory request rejected"
        );
        return Err(InventoryApiError::Invalid(
            "facet cursor is invalid for this scope".into(),
        ));
    }
    let mut items = load_facet_options(
        &state.pool,
        &FacetLoad {
            organization_id: principal.organization_id,
            project_id,
            application_id,
            facet,
            kind: query.kind,
            scope,
            facet_search: query.facet_search,
            cursor,
            limit,
        },
    )
    .await?;
    let next_cursor = facet_next_cursor(&mut items, limit, facet, fingerprint)?;
    let elapsed_micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    crate::metrics::record_inventory_query(elapsed_micros);
    crate::metrics::record_inventory_facet(elapsed_micros, items.len());
    tracing::debug!(
        operation = "facet",
        facet = facet.name(),
        elapsed_micros,
        result_size = items.len()
    );
    Ok(Json(FacetPage {
        coverage: crate::runtime_retention::history::coverage(
            &state.pool,
            principal.organization_id,
            project_id,
        )
        .await?,
        items,
        next_cursor,
    }))
}

async fn load_facet_options(
    pool: &PgPool,
    load: &FacetLoad,
) -> Result<Vec<FacetOption>, InventoryApiError> {
    let (value_sql, label_sql, cluster_join) = match load.facet {
        InventoryFacet::Cluster => (
            "s.cluster_id::text",
            "c.name",
            "JOIN clusters c ON c.organization_id=s.organization_id AND c.id=s.cluster_id",
        ),
        InventoryFacet::Namespace => ("s.namespace", "s.namespace", ""),
        InventoryFacet::WorkloadKind => ("s.workload_kind", "s.workload_kind", ""),
        InventoryFacet::WorkloadName => ("s.workload_name", "s.workload_name", ""),
        InventoryFacet::ContainerName => ("s.container_name", "s.container_name", ""),
    };
    let sql = format!(
        "SELECT {value_sql} value,{label_sql} label,count(DISTINCT i.id)::bigint item_count,COALESCE(sum(s.occurrence_count),0)::bigint occurrence_count FROM runtime_inventory_sightings s JOIN runtime_inventory_items i ON i.id=s.item_id {cluster_join} WHERE i.organization_id=$1 AND i.project_id=$2 AND i.application_id=$3 AND i.identity_version=$4 AND ($5::text IS NULL OR i.inventory_kind=$5) AND ($6::uuid IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_releases r WHERE r.item_id=i.id AND r.release_id=$6)) AND ($7::uuid IS NULL OR s.cluster_id=$7) AND ($8::text IS NULL OR s.namespace=$8) AND ($9::text IS NULL OR s.workload_kind=$9) AND ($10::text IS NULL OR s.workload_name=$10) AND ($11::text IS NULL OR s.container_name=$11) AND ($12::timestamptz IS NULL OR s.last_seen_at >= $12) AND ($13::timestamptz IS NULL OR s.first_seen_at <= $13) AND ($14::text IS NULL OR i.semantic_summary->>'operation'=$14) AND ($15::text IS NULL OR concat_ws(' ',i.semantic_summary->>'executable',i.semantic_summary->>'process_command',i.semantic_summary->>'destination_address',i.semantic_summary->>'destination_port',i.semantic_summary->>'local_address',i.semantic_summary->>'local_port',i.semantic_summary->>'name',i.semantic_summary->>'query_type',i.semantic_summary->>'syscall',i.semantic_summary->>'operation',i.semantic_summary->>'path',i.semantic_summary->>'new_path') ILIKE $15) AND ($16::text IS NULL OR concat_ws(' ',{label_sql},{value_sql}) ILIKE $16) GROUP BY {value_sql},{label_sql} HAVING ($17::bigint IS NULL OR count(DISTINCT i.id)<$17 OR (count(DISTINCT i.id)=$17 AND ({label_sql}>$18 OR ({label_sql}=$18 AND {value_sql}>$19)))) ORDER BY item_count DESC,label ASC,value ASC LIMIT $20"
    );
    let search = load.scope.search_pattern();
    let facet_search = load.facet_search.as_ref().map(|value| format!("%{value}%"));
    Ok(sqlx::query_as::<_, FacetOption>(&sql)
        .bind(load.organization_id)
        .bind(load.project_id)
        .bind(load.application_id)
        .bind(CURRENT_INVENTORY_IDENTITY_VERSION.get())
        .bind(load.kind.as_deref())
        .bind(load.scope.release_id)
        .bind(load.scope.cluster_id)
        .bind(load.scope.namespace.as_deref())
        .bind(load.scope.workload_kind.as_deref())
        .bind(load.scope.workload_name.as_deref())
        .bind(load.scope.container_name.as_deref())
        .bind(load.scope.observed_from)
        .bind(load.scope.observed_to)
        .bind(load.scope.operation.as_deref())
        .bind(search.as_deref())
        .bind(facet_search.as_deref())
        .bind(load.cursor.as_ref().map(|value| value.item_count))
        .bind(load.cursor.as_ref().map(|value| value.label.as_str()))
        .bind(load.cursor.as_ref().map(|value| value.value.as_str()))
        .bind(load.limit + 1)
        .fetch_all(pool)
        .await?)
}

fn facet_next_cursor(
    items: &mut Vec<FacetOption>,
    limit: i64,
    facet: InventoryFacet,
    fingerprint: String,
) -> Result<Option<String>, InventoryApiError> {
    Ok(
        if items.len() > usize::try_from(limit).unwrap_or(usize::MAX) {
            items.pop();
            items
                .last()
                .map(|item| {
                    encode_cursor(&FacetCursor {
                        facet: facet.name().into(),
                        scope: fingerprint,
                        item_count: item.item_count,
                        label: item.label.clone(),
                        value: item.value.clone(),
                    })
                })
                .transpose()?
        } else {
            None
        },
    )
}

#[allow(clippy::too_many_lines)]
async fn list_items(
    State(state): State<InventoryApiState>,
    headers: HeaderMap,
    Path((project_id, application_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<InventoryQuery>,
) -> Result<Json<InventoryItemPage>, InventoryApiError> {
    let started = Instant::now();
    let principal = principal(&headers, &state).await?;
    ensure_application(&state.pool, principal, project_id, application_id).await?;
    validate_kind(query.kind.as_deref())?;
    if query.verdict.as_deref().is_some_and(|value| {
        !matches!(
            value,
            "unclassified" | "expected" | "requires_review" | "policy_conflict"
        )
    }) {
        return Err(InventoryApiError::Invalid("verdict is invalid".into()));
    }
    let identity = query
        .identity_token
        .as_deref()
        .map(|token| {
            state.identity_tokens.validate(
                token,
                (
                    principal.organization_id,
                    project_id,
                    application_id,
                    query.kind.as_deref(),
                ),
            )
        })
        .transpose()?;
    let scope = query.scope.normalize()?;
    validate_release_scope(
        &state.pool,
        principal,
        project_id,
        application_id,
        scope.release_id,
    )
    .await?;
    let limit = limit(query.limit)?;
    let cursor = if let Some(cursor) = query.cursor {
        Some(sqlx::query_as::<_, (DateTime<Utc>, Uuid)>("SELECT last_seen_at,id FROM runtime_inventory_items WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND id=$4 AND identity_version=$5")
            .bind(principal.organization_id).bind(project_id).bind(application_id).bind(cursor).bind(CURRENT_INVENTORY_IDENTITY_VERSION.get())
            .fetch_optional(&state.pool).await?.ok_or_else(|| InventoryApiError::Invalid("cursor is invalid for this application".into()))?)
    } else {
        None
    };
    let (cursor_time, cursor_id) = cursor.map_or((None, None), |(time, id)| (Some(time), Some(id)));
    let search = scope.search_pattern();
    let mut items = sqlx::query_as::<_, InventoryItem>(
        "SELECT i.id,i.project_id,i.application_id,i.inventory_kind,i.identity_version,i.semantic_summary,i.first_seen_at,i.last_seen_at,i.occurrence_count,(SELECT count(*) FROM runtime_inventory_releases r WHERE r.item_id=i.id) release_count,(SELECT count(DISTINCT s.cluster_id) FROM runtime_inventory_sightings s WHERE s.item_id=i.id) cluster_count,(SELECT count(DISTINCT (s.cluster_id,s.namespace)) FROM runtime_inventory_sightings s WHERE s.item_id=i.id) namespace_count,(SELECT count(DISTINCT (s.cluster_id,s.namespace,s.workload_kind,s.workload_name)) FROM runtime_inventory_sightings s WHERE s.item_id=i.id) workload_count,(SELECT count(DISTINCT (s.cluster_id,s.pod_uid)) FROM runtime_inventory_sightings s WHERE s.item_id=i.id) pod_count,(SELECT count(DISTINCT s.container_name) FROM runtime_inventory_sightings s WHERE s.item_id=i.id) container_count,(SELECT count(*) FROM runtime_inventory_group_links gl WHERE gl.item_id=i.id) group_count FROM runtime_inventory_items i WHERE i.occurrence_count>0 AND i.organization_id=$1 AND i.project_id=$2 AND i.application_id=$3 AND i.identity_version=$4 AND ($5::text IS NULL OR i.inventory_kind=$5) AND ($6::uuid IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_releases r WHERE r.item_id=i.id AND r.release_id=$6)) AND ($7::uuid IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.cluster_id=$7)) AND ($8::text IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.namespace=$8)) AND ($9::text IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.workload_kind=$9)) AND ($10::text IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.workload_name=$10)) AND ($11::text IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.container_name=$11)) AND ($12::timestamptz IS NULL OR i.last_seen_at >= $12) AND ($13::timestamptz IS NULL OR i.first_seen_at <= $13) AND ($14::text IS NULL OR i.semantic_summary->>'operation'=$14) AND ($15::text IS NULL OR concat_ws(' ',i.semantic_summary->>'executable',i.semantic_summary->>'process_command',i.semantic_summary->>'destination_address',i.semantic_summary->>'destination_port',i.semantic_summary->>'local_address',i.semantic_summary->>'local_port',i.semantic_summary->>'name',i.semantic_summary->>'query_type',i.semantic_summary->>'syscall',i.semantic_summary->>'operation',i.semantic_summary->>'path',i.semantic_summary->>'new_path') ILIKE $15) AND ($16::uuid IS NULL OR (i.id=$16 AND i.identity_digest=$17)) AND ($18::text IS NULL OR EXISTS(SELECT 1 FROM runtime_sighting_policy_evaluations e JOIN runtime_policy_states ps ON ps.organization_id=e.organization_id AND ps.project_id=e.project_id AND ps.application_id=e.application_id WHERE e.item_id=i.id AND e.policy_state_version=ps.state_version AND e.evaluator_version=$21 AND e.verdict=$18)) AND ($19::bool IS NULL OR $19=EXISTS(SELECT 1 FROM runtime_inventory_sightings s JOIN runtime_policy_suppressions z ON z.organization_id=s.organization_id AND z.project_id=s.project_id AND z.application_id=s.application_id AND z.identity_version=i.identity_version AND z.identity_digest=i.identity_digest AND z.cancelled_at IS NULL AND z.expires_at>now() AND (cardinality(z.cluster_ids)=0 OR s.cluster_id=ANY(z.cluster_ids)) AND (cardinality(z.namespaces)=0 OR s.namespace=ANY(z.namespaces)) AND (cardinality(z.workload_kinds)=0 OR s.workload_kind=ANY(z.workload_kinds)) AND (cardinality(z.workload_names)=0 OR s.workload_name=ANY(z.workload_names)) WHERE s.item_id=i.id)) AND ($20::bool IS NULL OR $20=EXISTS(SELECT 1 FROM runtime_inventory_sightings s LEFT JOIN runtime_sighting_policy_evaluations e ON e.item_id=s.item_id AND e.cluster_id=s.cluster_id AND e.namespace=s.namespace AND e.workload_kind=s.workload_kind AND e.workload_name=s.workload_name AND e.pod_uid=s.pod_uid AND e.container_name=s.container_name LEFT JOIN runtime_policy_states ps ON ps.organization_id=s.organization_id AND ps.project_id=s.project_id AND ps.application_id=s.application_id WHERE s.item_id=i.id AND (e.item_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>$21))) AND ($22::timestamptz IS NULL OR (i.last_seen_at,i.id)<($22,$23)) ORDER BY i.last_seen_at DESC,i.id DESC LIMIT $24",
    )
    .bind(principal.organization_id).bind(project_id).bind(application_id)
    .bind(CURRENT_INVENTORY_IDENTITY_VERSION.get()).bind(query.kind).bind(scope.release_id).bind(scope.cluster_id)
    .bind(scope.namespace).bind(scope.workload_kind).bind(scope.workload_name).bind(scope.container_name)
    .bind(scope.observed_from).bind(scope.observed_to).bind(scope.operation).bind(search)
    .bind(identity.as_ref().map(|value| value.item_id))
    .bind(identity.as_ref().and_then(|value| hex::decode(&value.identity_digest).ok()))
    .bind(query.verdict).bind(query.suppressed).bind(query.evaluation_pending)
    .bind(crate::policy::POLICY_EVALUATOR_VERSION)
    .bind(cursor_time).bind(cursor_id).bind(limit + 1)
    .fetch_all(&state.pool).await?;
    let next_cursor = if items.len() > usize::try_from(limit).unwrap_or(usize::MAX) {
        items.pop();
        items.last().map(|item| item.id)
    } else {
        None
    };
    crate::metrics::record_inventory_query(
        u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
    );
    Ok(Json(InventoryItemPage {
        coverage: crate::runtime_retention::history::coverage(
            &state.pool,
            principal.organization_id,
            project_id,
        )
        .await?,
        items,
        next_cursor,
    }))
}

async fn fetch_item(
    state: &InventoryApiState,
    principal: UserPrincipal,
    project_id: Uuid,
    application_id: Uuid,
    item_id: Uuid,
) -> Result<InventoryItem, InventoryApiError> {
    sqlx::query_as::<_, InventoryItem>("SELECT i.id,i.project_id,i.application_id,i.inventory_kind,i.identity_version,i.semantic_summary,i.first_seen_at,i.last_seen_at,i.occurrence_count,(SELECT count(*) FROM runtime_inventory_releases r WHERE r.item_id=i.id) release_count,(SELECT count(DISTINCT s.cluster_id) FROM runtime_inventory_sightings s WHERE s.item_id=i.id) cluster_count,(SELECT count(DISTINCT (s.cluster_id,s.namespace)) FROM runtime_inventory_sightings s WHERE s.item_id=i.id) namespace_count,(SELECT count(DISTINCT (s.cluster_id,s.namespace,s.workload_kind,s.workload_name)) FROM runtime_inventory_sightings s WHERE s.item_id=i.id) workload_count,(SELECT count(DISTINCT (s.cluster_id,s.pod_uid)) FROM runtime_inventory_sightings s WHERE s.item_id=i.id) pod_count,(SELECT count(DISTINCT s.container_name) FROM runtime_inventory_sightings s WHERE s.item_id=i.id) container_count,(SELECT count(*) FROM runtime_inventory_group_links gl WHERE gl.item_id=i.id) group_count FROM runtime_inventory_items i WHERE i.organization_id=$1 AND i.project_id=$2 AND i.application_id=$3 AND i.id=$4 AND i.identity_version=$5")
        .bind(principal.organization_id).bind(project_id).bind(application_id).bind(item_id).bind(CURRENT_INVENTORY_IDENTITY_VERSION.get())
        .fetch_optional(&state.pool).await?.ok_or(InventoryApiError::NotFound)
}

async fn item_detail(
    State(state): State<InventoryApiState>,
    headers: HeaderMap,
    Path((project_id, application_id, item_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<Json<InventoryItemDetail>, InventoryApiError> {
    let started = Instant::now();
    let principal = principal(&headers, &state).await?;
    let item = fetch_item(&state, principal, project_id, application_id, item_id).await?;
    let policy_placement_summary: Value = sqlx::query_scalar(
        "SELECT jsonb_build_object('placement_count',count(*),'evaluation_pending',count(*) FILTER (WHERE e.item_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>$5),'verdicts',jsonb_build_object('expected',count(*) FILTER (WHERE e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=$5 AND e.verdict='expected'),'requires_review',count(*) FILTER (WHERE e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=$5 AND e.verdict='requires_review'),'policy_conflict',count(*) FILTER (WHERE e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=$5 AND e.verdict='policy_conflict'),'unclassified',count(*) FILTER (WHERE e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=$5 AND e.verdict='unclassified'))) FROM runtime_inventory_sightings s LEFT JOIN runtime_sighting_policy_evaluations e ON e.item_id=s.item_id AND e.cluster_id=s.cluster_id AND e.namespace=s.namespace AND e.workload_kind=s.workload_kind AND e.workload_name=s.workload_name AND e.pod_uid=s.pod_uid AND e.container_name=s.container_name LEFT JOIN runtime_policy_states ps ON ps.organization_id=s.organization_id AND ps.project_id=s.project_id AND ps.application_id=s.application_id WHERE s.organization_id=$1 AND s.project_id=$2 AND s.application_id=$3 AND s.item_id=$4",
    )
    .bind(principal.organization_id)
    .bind(project_id)
    .bind(application_id)
    .bind(item_id)
    .bind(crate::policy::POLICY_EVALUATOR_VERSION)
    .fetch_one(&state.pool)
    .await?;
    crate::metrics::record_inventory_query(
        u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
    );
    Ok(Json(InventoryItemDetail {
        coverage: crate::runtime_retention::history::coverage(
            &state.pool,
            principal.organization_id,
            project_id,
        )
        .await?,
        item,
        evidence: EvidenceLinks::scoped(project_id, application_id, item_id),
        policy_placement_summary,
    }))
}

async fn item_releases(
    State(state): State<InventoryApiState>,
    headers: HeaderMap,
    Path((project_id, application_id, item_id)): Path<(Uuid, Uuid, Uuid)>,
    Query(query): Query<PageQuery>,
) -> Result<Json<ReleasePresencePage>, InventoryApiError> {
    let principal = principal(&headers, &state).await?;
    ensure_item(&state.pool, principal, project_id, application_id, item_id).await?;
    let limit = limit(query.limit)?;
    let cursor = if let Some(cursor) = query.cursor {
        Some(sqlx::query_as::<_, (DateTime<Utc>, Uuid)>("SELECT deployed_at,id FROM releases WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND id=$4")
            .bind(principal.organization_id).bind(project_id).bind(application_id).bind(cursor)
            .fetch_optional(&state.pool).await?.ok_or_else(|| InventoryApiError::Invalid("release cursor is invalid".into()))?)
    } else {
        None
    };
    let (cursor_time, cursor_id) = cursor.map_or((None, None), |(time, id)| (Some(time), Some(id)));
    let mut items = sqlx::query_as::<_, ReleasePresence>("SELECT r.id release_id,release_display_name(a.name,r.source,r.version,r.identity_digest,r.identity_components) release_display_name,r.version,r.deployed_at,CASE WHEN ir.release_id IS NOT NULL AND ir.occurrence_count>0 THEN 'observed' WHEN EXISTS(SELECT 1 FROM projects p WHERE p.id=r.project_id AND r.deployed_at<p.runtime_closed_before) THEN 'unknown' WHEN EXISTS(SELECT 1 FROM runtime_events e WHERE e.organization_id=r.organization_id AND e.project_id=r.project_id AND e.application_id=r.application_id AND e.release_id=r.id) THEN 'not_observed' ELSE 'unknown' END presence,ir.occurrence_count,ir.first_seen_at,ir.last_seen_at,(SELECT count(*) FROM runtime_events e WHERE e.organization_id=r.organization_id AND e.project_id=r.project_id AND e.application_id=r.application_id AND e.release_id=r.id) release_evidence_count FROM releases r JOIN applications a ON a.id=r.application_id LEFT JOIN runtime_inventory_releases ir ON ir.release_id=r.id AND ir.item_id=$4 WHERE r.organization_id=$1 AND r.project_id=$2 AND r.application_id=$3 AND ($5::timestamptz IS NULL OR (r.deployed_at,r.id)<($5,$6)) ORDER BY r.deployed_at DESC,r.id DESC LIMIT $7")
        .bind(principal.organization_id).bind(project_id).bind(application_id).bind(item_id).bind(cursor_time).bind(cursor_id).bind(limit + 1)
        .fetch_all(&state.pool).await?;
    let next_cursor = if items.len() > usize::try_from(limit).unwrap_or(usize::MAX) {
        items.pop();
        items.last().map(|item| item.release_id)
    } else {
        None
    };
    Ok(Json(ReleasePresencePage {
        coverage: crate::runtime_retention::history::coverage(
            &state.pool,
            principal.organization_id,
            project_id,
        )
        .await?,
        items,
        next_cursor,
    }))
}

fn encode_cursor<T: Serialize>(cursor: &T) -> Result<String, InventoryApiError> {
    serde_json::to_vec(cursor)
        .map(hex::encode)
        .map_err(|_| InventoryApiError::Invalid("cursor cannot be encoded".into()))
}

fn decode_cursor<T: DeserializeOwned>(cursor: &str) -> Result<T, InventoryApiError> {
    let bytes =
        hex::decode(cursor).map_err(|_| InventoryApiError::Invalid("cursor is invalid".into()))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| InventoryApiError::Invalid("cursor is invalid".into()))
}

async fn item_sightings(
    State(state): State<InventoryApiState>,
    headers: HeaderMap,
    Path((project_id, application_id, item_id)): Path<(Uuid, Uuid, Uuid)>,
    Query(query): Query<StringCursorPageQuery>,
) -> Result<Json<SightingPage>, InventoryApiError> {
    let principal = principal(&headers, &state).await?;
    ensure_item(&state.pool, principal, project_id, application_id, item_id).await?;
    let limit = limit(query.limit)?;
    let cursor: Option<SightingCursor> = query.cursor.as_deref().map(decode_cursor).transpose()?;
    let mut items = sqlx::query_as::<_, InventorySighting>("SELECT s.cluster_id,s.namespace,s.workload_kind,s.workload_name,s.pod_uid,s.pod_name,s.container_name,s.occurrence_count,s.first_seen_at,s.last_seen_at,jsonb_build_object('state',CASE WHEN e.item_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>$13 THEN 'evaluation_pending' ELSE 'current' END,'verdict',CASE WHEN e.item_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>$13 THEN NULL ELSE e.verdict END,'reason_code',CASE WHEN e.item_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>$13 THEN 'evaluation_pending' ELSE e.reason_code END,'winning_revision_id',CASE WHEN e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=$13 THEN e.winning_revision_id END,'explanation',CASE WHEN e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=$13 THEN e.explanation ELSE '{}'::jsonb END,'evaluated_at',CASE WHEN e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=$13 THEN e.evaluated_at END) policy_evaluation,x.summary active_suppression,(x.summary IS NULL AND (e.item_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>$13 OR e.verdict<>'expected')) actionable FROM runtime_inventory_sightings s LEFT JOIN runtime_sighting_policy_evaluations e ON e.item_id=s.item_id AND e.cluster_id=s.cluster_id AND e.namespace=s.namespace AND e.workload_kind=s.workload_kind AND e.workload_name=s.workload_name AND e.pod_uid=s.pod_uid AND e.container_name=s.container_name LEFT JOIN runtime_policy_states ps ON ps.organization_id=s.organization_id AND ps.project_id=s.project_id AND ps.application_id=s.application_id LEFT JOIN runtime_inventory_items i ON i.id=s.item_id LEFT JOIN LATERAL (SELECT jsonb_build_object('id',z.id,'reason',z.reason,'expires_at',z.expires_at,'created_at',z.created_at) summary FROM runtime_policy_suppressions z WHERE z.organization_id=s.organization_id AND z.project_id=s.project_id AND z.application_id=s.application_id AND z.identity_version=i.identity_version AND z.identity_digest=i.identity_digest AND z.cancelled_at IS NULL AND z.expires_at>now() AND (cardinality(z.cluster_ids)=0 OR s.cluster_id=ANY(z.cluster_ids)) AND (cardinality(z.namespaces)=0 OR s.namespace=ANY(z.namespaces)) AND (cardinality(z.workload_kinds)=0 OR s.workload_kind=ANY(z.workload_kinds)) AND (cardinality(z.workload_names)=0 OR s.workload_name=ANY(z.workload_names)) ORDER BY z.expires_at,z.id LIMIT 1) x ON true WHERE s.organization_id=$1 AND s.project_id=$2 AND s.application_id=$3 AND s.item_id=$4 AND ($5::timestamptz IS NULL OR (s.last_seen_at,s.cluster_id,s.namespace,s.workload_kind,s.workload_name,s.pod_uid,s.container_name)<($5,$6,$7,$8,$9,$10,$11)) ORDER BY s.last_seen_at DESC,s.cluster_id DESC,s.namespace DESC,s.workload_kind DESC,s.workload_name DESC,s.pod_uid DESC,s.container_name DESC LIMIT $12")
        .bind(principal.organization_id).bind(project_id).bind(application_id).bind(item_id)
        .bind(cursor.as_ref().map(|value| value.last_seen_at)).bind(cursor.as_ref().map(|value| value.cluster_id))
        .bind(cursor.as_ref().map(|value| value.namespace.as_str())).bind(cursor.as_ref().map(|value| value.workload_kind.as_str()))
        .bind(cursor.as_ref().map(|value| value.workload_name.as_str())).bind(cursor.as_ref().map(|value| value.pod_uid.as_str()))
        .bind(cursor.as_ref().map(|value| value.container_name.as_str())).bind(limit + 1)
        .bind(crate::policy::POLICY_EVALUATOR_VERSION).fetch_all(&state.pool).await?;
    let next_cursor = if items.len() > usize::try_from(limit).unwrap_or(usize::MAX) {
        items.pop();
        items
            .last()
            .map(|item| {
                encode_cursor(&SightingCursor {
                    last_seen_at: item.last_seen_at,
                    cluster_id: item.cluster_id,
                    namespace: item.namespace.clone(),
                    workload_kind: item.workload_kind.clone(),
                    workload_name: item.workload_name.clone(),
                    pod_uid: item.pod_uid.clone(),
                    container_name: item.container_name.clone(),
                })
            })
            .transpose()?
    } else {
        None
    };
    Ok(Json(SightingPage {
        coverage: crate::runtime_retention::history::coverage(
            &state.pool,
            principal.organization_id,
            project_id,
        )
        .await?,
        items,
        next_cursor,
    }))
}

async fn item_groups(
    State(state): State<InventoryApiState>,
    headers: HeaderMap,
    Path((project_id, application_id, item_id)): Path<(Uuid, Uuid, Uuid)>,
    Query(query): Query<PageQuery>,
) -> Result<Json<GroupPage>, InventoryApiError> {
    let principal = principal(&headers, &state).await?;
    ensure_item(&state.pool, principal, project_id, application_id, item_id).await?;
    let limit = limit(query.limit)?;
    let mut items = sqlx::query_as::<_, InventoryGroup>("SELECT g.id,g.cluster_id,g.namespace,g.workload_kind,g.workload_name,g.event_kind,g.status,g.first_seen_at,g.last_seen_at,g.occurrence_count FROM runtime_inventory_group_links l JOIN runtime_event_groups g ON g.id=l.group_id WHERE l.organization_id=$1 AND l.project_id=$2 AND l.application_id=$3 AND l.item_id=$4 AND ($5::uuid IS NULL OR g.id<$5) ORDER BY g.id DESC LIMIT $6")
        .bind(principal.organization_id).bind(project_id).bind(application_id).bind(item_id).bind(query.cursor).bind(limit + 1)
        .fetch_all(&state.pool).await?;
    let next_cursor = if items.len() > usize::try_from(limit).unwrap_or(usize::MAX) {
        items.pop();
        items.last().map(|item| item.id)
    } else {
        None
    };
    Ok(Json(GroupPage {
        coverage: crate::runtime_retention::history::coverage(
            &state.pool,
            principal.organization_id,
            project_id,
        )
        .await?,
        items,
        next_cursor,
    }))
}

async fn item_occurrences(
    State(state): State<InventoryApiState>,
    headers: HeaderMap,
    Path((project_id, application_id, item_id)): Path<(Uuid, Uuid, Uuid)>,
    Query(query): Query<PageQuery>,
) -> Result<Json<OccurrencePage>, InventoryApiError> {
    let principal = principal(&headers, &state).await?;
    ensure_item(&state.pool, principal, project_id, application_id, item_id).await?;
    let limit = limit(query.limit)?;
    let cursor = if let Some(cursor) = query.cursor {
        Some(sqlx::query_as::<_, (DateTime<Utc>, Uuid)>("SELECT e.observed_at,e.id FROM runtime_inventory_event_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE m.organization_id=$1 AND m.project_id=$2 AND m.application_id=$3 AND m.item_id=$4 AND e.id=$5")
            .bind(principal.organization_id).bind(project_id).bind(application_id).bind(item_id).bind(cursor)
            .fetch_optional(&state.pool).await?.ok_or_else(|| InventoryApiError::Invalid("occurrence cursor is invalid".into()))?)
    } else {
        None
    };
    let (cursor_time, cursor_id) = cursor.map_or((None, None), |(time, id)| (Some(time), Some(id)));
    let mut items = sqlx::query_as::<_, InventoryOccurrence>("SELECT e.id,e.event_id,e.observed_at,e.cluster_id,e.node_name,e.namespace,e.pod_uid,e.pod_name,e.container_name,e.process_command,e.event_kind,e.payload,e.release_id,r.version release_version,CASE WHEN r.id IS NULL THEN 'Unattributed' ELSE release_display_name(a.name,r.source,r.version,r.identity_digest,r.identity_components) END release_display_name FROM runtime_inventory_event_memberships m JOIN runtime_events e ON e.id=m.event_id LEFT JOIN releases r ON r.id=e.release_id LEFT JOIN applications a ON a.id=r.application_id WHERE m.organization_id=$1 AND m.project_id=$2 AND m.application_id=$3 AND m.item_id=$4 AND m.identity_version=$5 AND ($6::timestamptz IS NULL OR (e.observed_at,e.id)<($6,$7)) ORDER BY e.observed_at DESC,e.id DESC LIMIT $8")
        .bind(principal.organization_id).bind(project_id).bind(application_id).bind(item_id).bind(CURRENT_INVENTORY_IDENTITY_VERSION.get()).bind(cursor_time).bind(cursor_id).bind(limit + 1)
        .fetch_all(&state.pool).await?;
    let next_cursor = if items.len() > usize::try_from(limit).unwrap_or(usize::MAX) {
        items.pop();
        items.last().map(|item| item.id)
    } else {
        None
    };
    Ok(Json(OccurrencePage {
        coverage: crate::runtime_retention::history::coverage(
            &state.pool,
            principal.organization_id,
            project_id,
        )
        .await?,
        items,
        next_cursor,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized_scope_rejects_invalid_bounds() {
        let scope = InventoryScope {
            search: Some(String::new()),
            ..Default::default()
        };
        assert!(scope.normalize().is_err());
        let scope = InventoryScope {
            search: Some("x".repeat(201)),
            ..Default::default()
        };
        assert!(scope.normalize().is_err());
        let scope = InventoryScope {
            namespace: Some(" ".into()),
            ..Default::default()
        };
        assert!(scope.normalize().is_err());
        let scope = InventoryScope {
            observed_from: Some(Utc::now()),
            observed_to: Some(Utc::now() - chrono::Duration::seconds(1)),
            ..Default::default()
        };
        assert!(scope.normalize().is_err());
        let scope = InventoryScope {
            operation: Some("read".into()),
            ..Default::default()
        };
        assert!(scope.normalize().is_err());
        let scope = InventoryScope {
            container_name: Some("x".repeat(254)),
            ..Default::default()
        };
        assert!(scope.normalize().is_err());
    }

    #[test]
    fn normalized_scope_trims_deployment_values_and_preserves_valid_bounds() {
        let from = Utc::now() - chrono::Duration::minutes(1);
        let to = Utc::now();
        let scope = InventoryScope {
            namespace: Some(" production ".into()),
            workload_kind: Some(" Deployment ".into()),
            workload_name: Some(" api ".into()),
            container_name: Some(" server ".into()),
            observed_from: Some(from),
            observed_to: Some(to),
            search: Some("worker".into()),
            ..Default::default()
        }
        .normalize()
        .unwrap();
        assert_eq!(scope.namespace.as_deref(), Some("production"));
        assert_eq!(scope.workload_kind.as_deref(), Some("Deployment"));
        assert_eq!(scope.workload_name.as_deref(), Some("api"));
        assert_eq!(scope.container_name.as_deref(), Some("server"));
        assert_eq!(scope.observed_from, Some(from));
        assert_eq!(scope.observed_to, Some(to));
    }

    #[test]
    fn inventory_kinds_are_closed() {
        for kind in [
            None,
            Some("process"),
            Some("destination"),
            Some("domain"),
            Some("syscall"),
            Some("inbound_endpoint"),
            Some("file_activity"),
            Some("lifecycle"),
        ] {
            assert!(validate_kind(kind).is_ok(), "kind {kind:?}");
        }
        assert!(validate_kind(Some("payload")).is_err());
    }

    #[test]
    fn scope_fingerprint_is_stable_and_tenant_bound() {
        let scope = InventoryScope {
            namespace: Some(" production ".into()),
            ..Default::default()
        }
        .normalize()
        .unwrap();
        let org = Uuid::from_u128(1);
        let project = Uuid::from_u128(2);
        let app = Uuid::from_u128(3);
        assert_eq!(
            scope.fingerprint((org, project, app), Some("process")),
            scope.fingerprint((org, project, app), Some("process"))
        );
        assert_ne!(
            scope.fingerprint((org, project, app), Some("process")),
            scope.fingerprint((org, project, Uuid::from_u128(4)), Some("process"))
        );
        assert_ne!(
            scope.fingerprint((org, project, app), Some("process")),
            scope.fingerprint((org, project, app), Some("domain"))
        );
        let changed_scope = InventoryScope {
            namespace: Some("staging".into()),
            ..Default::default()
        }
        .normalize()
        .unwrap();
        assert_ne!(
            scope.fingerprint((org, project, app), Some("process")),
            changed_scope.fingerprint((org, project, app), Some("process"))
        );
    }

    #[test]
    fn evidence_hints_are_exact_root_relative_allowlisted_paths() {
        let links =
            EvidenceLinks::scoped(Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        for (path, suffix) in [
            (links.releases, "releases"),
            (links.sightings, "sightings"),
            (links.groups, "groups"),
            (links.occurrences, "occurrences"),
        ] {
            assert!(path.starts_with('/'));
            assert!(path.ends_with(suffix));
            assert!(!path.contains(['?', '#', '\\']));
            assert!(!path.contains(".."));
            assert!(!path.contains("://"));
        }
    }

    fn token_payload() -> IdentityTokenPayload {
        IdentityTokenPayload {
            format_version: 1,
            identity_version: CURRENT_INVENTORY_IDENTITY_VERSION.get(),
            organization_id: Uuid::from_u128(1),
            project_id: Uuid::from_u128(2),
            application_id: Uuid::from_u128(3),
            kind: "process".into(),
            item_id: Uuid::from_u128(4),
            identity_digest: "11".repeat(32),
            issued_at: 0,
            expires_at: 0,
        }
    }

    #[test]
    fn identity_tokens_round_trip_reject_tampering_and_bind_scope() {
        let codec = IdentityTokenCodec {
            key: Arc::new([7; 32]),
        };
        let token = codec.issue(token_payload()).unwrap();
        let decoded = codec
            .validate(
                &token,
                (
                    Uuid::from_u128(1),
                    Uuid::from_u128(2),
                    Uuid::from_u128(3),
                    Some("process"),
                ),
            )
            .unwrap();
        assert_eq!(decoded.item_id, Uuid::from_u128(4));
        let mut tampered = token.into_bytes();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == b'0' { b'1' } else { b'0' };
        assert!(matches!(
            codec.validate(
                std::str::from_utf8(&tampered).unwrap(),
                (
                    Uuid::from_u128(1),
                    Uuid::from_u128(2),
                    Uuid::from_u128(3),
                    Some("process")
                )
            ),
            Err(InventoryApiError::IdentityToken("invalid_identity_token"))
        ));
        let token = codec.issue(token_payload()).unwrap();
        assert!(matches!(
            codec.validate(
                &token,
                (
                    Uuid::from_u128(1),
                    Uuid::from_u128(2),
                    Uuid::from_u128(9),
                    Some("process")
                )
            ),
            Err(InventoryApiError::IdentityToken(
                "identity_token_scope_mismatch"
            ))
        ));
    }

    #[test]
    fn identity_token_length_and_aggregate_limits_are_bounded() {
        let codec = IdentityTokenCodec {
            key: Arc::new([7; 32]),
        };
        assert!(matches!(
            codec.validate(
                &"x".repeat(1001),
                (Uuid::nil(), Uuid::nil(), Uuid::nil(), None)
            ),
            Err(InventoryApiError::IdentityToken("invalid_identity_token"))
        ));
        for valid in [1, 5, 10] {
            assert_eq!(aggregate_limit(Some(valid)).unwrap(), valid);
        }
        for invalid in [0, 11] {
            assert!(aggregate_limit(Some(invalid)).is_err());
        }
        let mut expired = token_payload();
        expired.issued_at = 1;
        expired.expires_at = 2;
        let token = codec.encode(&expired).unwrap();
        assert!(matches!(
            codec.validate(
                &token,
                (
                    Uuid::from_u128(1),
                    Uuid::from_u128(2),
                    Uuid::from_u128(3),
                    Some("process")
                )
            ),
            Err(InventoryApiError::IdentityToken("expired_identity_token"))
        ));
    }
}
