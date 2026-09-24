//! The runtime inventory of an application: the distinct behaviours its
//! workloads showed (processes, destinations, domains, syscalls, endpoints,
//! file activity, lifecycle), where and when, and the labels people give them.
//!
//! The query types below are also the request's query strings, and the scope
//! is fingerprinted into facet cursors, so their fields are part of the API.

use std::{
    sync::{Arc, OnceLock},
    time::Instant,
};

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool};
use thiserror::Error;
use uuid::Uuid;

use crate::access_control::resolve_project_access;
use crate::auth::IdentityPrincipal;
use crate::inventory::CURRENT_INVENTORY_IDENTITY_VERSION;
use crate::repository::inventory::{FacetColumn, InventoryFilter, InventoryRepository};
use crate::repository::{ApplicationRepository, ProjectRepository};

/// Why an inventory use case failed.
#[derive(Debug, Error)]
pub enum InventoryServiceError {
    /// The request is malformed; the message says how.
    #[error("{0}")]
    Invalid(String),
    /// The identity token cannot select an item for this request.
    #[error("identity token is invalid for this request: {0:?}")]
    IdentityToken(IdentityTokenProblem),
    /// The project, application or item does not exist, or the principal may
    /// not see it.
    #[error("runtime inventory resource not found")]
    NotFound,
    /// The label was changed by another request since it was read.
    #[error("the runtime behavior label was changed by another request")]
    Conflict,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// What is wrong with an identity token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityTokenProblem {
    /// Malformed, or its signature does not match.
    Invalid,
    /// Issued too long ago.
    Expired,
    /// Issued for another organization, project, application, kind or
    /// identity version.
    ScopeMismatch,
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

    fn issue(&self, mut payload: IdentityTokenPayload) -> Result<String, InventoryServiceError> {
        let now = Utc::now().timestamp();
        payload.issued_at = now - now.rem_euclid(IDENTITY_TOKEN_TTL_SECONDS);
        payload.expires_at = payload.issued_at + IDENTITY_TOKEN_TTL_SECONDS * 2;
        self.encode(&payload)
    }

    fn encode(&self, payload: &IdentityTokenPayload) -> Result<String, InventoryServiceError> {
        let encoded =
            hex::encode(serde_json::to_vec(payload).map_err(|_| {
                InventoryServiceError::IdentityToken(IdentityTokenProblem::Invalid)
            })?);
        let mut mac = HmacSha256::new_from_slice(self.key.as_ref())
            .map_err(|_| InventoryServiceError::IdentityToken(IdentityTokenProblem::Invalid))?;
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
    ) -> Result<IdentityTokenPayload, InventoryServiceError> {
        if token.is_empty() || token.len() > 1000 {
            return Err(InventoryServiceError::IdentityToken(
                IdentityTokenProblem::Invalid,
            ));
        }
        let mut parts = token.split('.');
        let digest_prefix = parts.next().unwrap_or_default();
        let encoded = parts.next().unwrap_or_default();
        let signature = parts.next().unwrap_or_default();
        if parts.next().is_some() || digest_prefix.len() != 64 {
            return Err(InventoryServiceError::IdentityToken(
                IdentityTokenProblem::Invalid,
            ));
        }
        let signature = hex::decode(signature)
            .map_err(|_| InventoryServiceError::IdentityToken(IdentityTokenProblem::Invalid))?;
        let mut mac = HmacSha256::new_from_slice(self.key.as_ref())
            .map_err(|_| InventoryServiceError::IdentityToken(IdentityTokenProblem::Invalid))?;
        mac.update(encoded.as_bytes());
        mac.verify_slice(&signature)
            .map_err(|_| InventoryServiceError::IdentityToken(IdentityTokenProblem::Invalid))?;
        let payload: IdentityTokenPayload =
            serde_json::from_slice(&hex::decode(encoded).map_err(|_| {
                InventoryServiceError::IdentityToken(IdentityTokenProblem::Invalid)
            })?)
            .map_err(|_| InventoryServiceError::IdentityToken(IdentityTokenProblem::Invalid))?;
        if payload.identity_digest != digest_prefix || hex::decode(digest_prefix).is_err() {
            return Err(InventoryServiceError::IdentityToken(
                IdentityTokenProblem::Invalid,
            ));
        }
        if Utc::now().timestamp() >= payload.expires_at {
            return Err(InventoryServiceError::IdentityToken(
                IdentityTokenProblem::Expired,
            ));
        }
        if payload.format_version != 1
            || payload.identity_version != CURRENT_INVENTORY_IDENTITY_VERSION.get()
            || payload.organization_id != expected.0
            || payload.project_id != expected.1
            || payload.application_id != expected.2
            || expected.3.is_some_and(|kind| payload.kind != kind)
        {
            return Err(InventoryServiceError::IdentityToken(
                IdentityTokenProblem::ScopeMismatch,
            ));
        }
        Ok(payload)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct InventoryScope {
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
pub struct InventoryQuery {
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
pub struct SummaryQuery {
    #[serde(flatten)]
    scope: InventoryScope,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DistributionQuery {
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
    user_label: Option<Value>,
    occurrence_count: i64,
    total_item_count: i64,
    total_occurrence_count: i64,
}

#[derive(Debug, Serialize)]
pub struct DistributionEntry {
    identity_token: String,
    semantic_summary: Value,
    user_label: Option<Value>,
    item_count: i64,
    occurrence_count: i64,
}

#[derive(Debug, Serialize)]
pub struct DistributionOther {
    item_count: i64,
    occurrence_count: i64,
}

#[derive(Debug, Serialize)]
pub struct InventoryDistribution {
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

    fn parse(value: &str) -> Result<Self, InventoryServiceError> {
        match value {
            "cluster" => Ok(Self::Cluster),
            "namespace" => Ok(Self::Namespace),
            "workload_kind" => Ok(Self::WorkloadKind),
            "workload_name" => Ok(Self::WorkloadName),
            "container_name" => Ok(Self::ContainerName),
            _ => Err(InventoryServiceError::Invalid(
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
pub struct FacetQuery {
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
pub struct FacetOption {
    value: String,
    label: String,
    item_count: i64,
    occurrence_count: i64,
}

#[derive(Debug, Serialize)]
pub struct FacetPage {
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
pub struct PageQuery {
    cursor: Option<Uuid>,
    limit: Option<i64>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct StringCursorPageQuery {
    cursor: Option<String>,
    limit: Option<i64>,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct InventoryItem {
    id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    inventory_kind: String,
    identity_version: i16,
    semantic_summary: Value,
    user_label: Option<Value>,
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
pub struct InventoryItemPage {
    coverage: crate::runtime_retention::history::Coverage,
    items: Vec<InventoryItem>,
    next_cursor: Option<Uuid>,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct KindCount {
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
pub struct InventorySummary {
    coverage: crate::runtime_retention::history::Coverage,
    identity_version: i16,
    item_count: i64,
    occurrence_count: i64,
    first_seen_at: Option<DateTime<Utc>>,
    last_seen_at: Option<DateTime<Utc>>,
    kinds: Vec<KindCount>,
}

#[derive(Debug, Serialize)]
pub struct InventoryItemDetail {
    coverage: crate::runtime_retention::history::Coverage,
    #[serde(flatten)]
    item: InventoryItem,
    evidence: EvidenceLinks,
    policy_placement_summary: Value,
}

#[derive(Debug, Serialize)]
pub struct EvidenceLinks {
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
pub struct ReleasePresence {
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
pub struct ReleasePresencePage {
    coverage: crate::runtime_retention::history::Coverage,
    items: Vec<ReleasePresence>,
    next_cursor: Option<Uuid>,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct InventorySighting {
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
pub struct SightingPage {
    coverage: crate::runtime_retention::history::Coverage,
    items: Vec<InventorySighting>,
    next_cursor: Option<String>,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct InventoryGroup {
    id: Uuid,
    cluster_id: Uuid,
    namespace: String,
    workload_kind: String,
    workload_name: String,
    event_kind: String,
    user_labels: Value,
    status: String,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    occurrence_count: i64,
}

#[derive(Debug, Serialize)]
pub struct GroupPage {
    coverage: crate::runtime_retention::history::Coverage,
    items: Vec<InventoryGroup>,
    next_cursor: Option<Uuid>,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct InventoryOccurrence {
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
pub struct OccurrencePage {
    coverage: crate::runtime_retention::history::Coverage,
    items: Vec<InventoryOccurrence>,
    next_cursor: Option<Uuid>,
}

#[derive(Clone, Copy)]
struct ProjectPrincipal {
    organization_id: Uuid,
    user_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct PutUserLabel {
    display_name: String,
    expected_updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteUserLabel {
    expected_updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, FromRow, Serialize)]
pub struct UserLabel {
    display_name: String,
    created_by_user_id: Uuid,
    updated_by_user_id: Uuid,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

fn normalize_display_name(value: &str) -> Result<String, InventoryServiceError> {
    let value = value.trim().to_owned();
    if value.is_empty() || value.chars().count() > 120 || value.chars().any(char::is_control) {
        return Err(InventoryServiceError::Invalid(
            "display_name must contain 1 to 120 non-control characters".into(),
        ));
    }
    Ok(value)
}

fn limit(value: Option<i64>) -> Result<i64, InventoryServiceError> {
    let value = value.unwrap_or(50);
    if (1..=200).contains(&value) {
        Ok(value)
    } else {
        Err(InventoryServiceError::Invalid(
            "limit must be between 1 and 200".into(),
        ))
    }
}

fn aggregate_limit(value: Option<i64>) -> Result<i64, InventoryServiceError> {
    let value = value.unwrap_or(5);
    if (1..=10).contains(&value) {
        Ok(value)
    } else {
        Err(InventoryServiceError::Invalid(
            "limit must be between 1 and 10".into(),
        ))
    }
}

fn validate_kind(kind: Option<&str>) -> Result<(), InventoryServiceError> {
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
        Err(InventoryServiceError::Invalid(
            "kind must be process, destination, domain, syscall, inbound_endpoint, file_activity, or lifecycle".into(),
        ))
    }
}

fn validate_search(search: Option<&str>) -> Result<(), InventoryServiceError> {
    if search.is_none_or(|value| !value.is_empty() && value.chars().count() <= 200) {
        Ok(())
    } else {
        Err(InventoryServiceError::Invalid(
            "search must contain between 1 and 200 characters".into(),
        ))
    }
}

fn record_validation<T>(
    result: Result<T, InventoryServiceError>,
    operation: &'static str,
    failure_class: &'static str,
    cursor: bool,
) -> Result<T, InventoryServiceError> {
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
    fn normalize(mut self) -> Result<Self, InventoryServiceError> {
        validate_search(self.search.as_deref())?;
        if self
            .operation
            .as_deref()
            .is_some_and(|value| !matches!(value, "create" | "modify" | "delete" | "rename"))
        {
            return Err(InventoryServiceError::Invalid(
                "operation must be create, modify, delete, or rename".into(),
            ));
        }
        if self
            .observed_from
            .zip(self.observed_to)
            .is_some_and(|(from, to)| from > to)
        {
            return Err(InventoryServiceError::Invalid(
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
                    return Err(InventoryServiceError::Invalid(format!(
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

    /// The repository filter for this scope within a tenant path; `search`
    /// is the `ILIKE` pattern from [`Self::search_pattern`].
    fn filter<'a>(
        &'a self,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        search: Option<&'a str>,
    ) -> InventoryFilter<'a> {
        InventoryFilter {
            organization_id,
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
            operation: self.operation.as_deref(),
            search,
        }
    }

    fn search_pattern(&self) -> Option<String> {
        self.search.as_ref().map(|value| format!("%{value}%"))
    }
}

async fn validate_release_scope(
    pool: &PgPool,
    principal: ProjectPrincipal,
    project_id: Uuid,
    application_id: Uuid,
    release_id: Option<Uuid>,
) -> Result<(), InventoryServiceError> {
    let Some(release_id) = release_id else {
        return Ok(());
    };
    let exists: bool = crate::repository::ReleaseRepository::exists(
        pool,
        crate::repository::ApplicationScope {
            organization_id: principal.organization_id,
            project_id,
            application_id,
        },
        release_id,
    )
    .await?;
    if exists {
        Ok(())
    } else {
        Err(InventoryServiceError::Invalid(
            "release_id is invalid for this application".into(),
        ))
    }
}

async fn ensure_application(
    pool: &PgPool,
    principal: ProjectPrincipal,
    project_id: Uuid,
    application_id: Uuid,
) -> Result<(), InventoryServiceError> {
    let exists =
        ApplicationRepository::exists(pool, principal.organization_id, project_id, application_id)
            .await?;
    exists.then_some(()).ok_or(InventoryServiceError::NotFound)
}

async fn ensure_item(
    pool: &PgPool,
    principal: ProjectPrincipal,
    project_id: Uuid,
    application_id: Uuid,
    item_id: Uuid,
) -> Result<(), InventoryServiceError> {
    let exists: bool = InventoryRepository::exists(
        pool,
        principal.organization_id,
        project_id,
        application_id,
        item_id,
        CURRENT_INVENTORY_IDENTITY_VERSION.get(),
    )
    .await?;
    exists.then_some(()).ok_or(InventoryServiceError::NotFound)
}

async fn load_facet_options(
    pool: &PgPool,
    load: &FacetLoad,
) -> Result<Vec<FacetOption>, InventoryServiceError> {
    let column = match load.facet {
        InventoryFacet::Cluster => FacetColumn::Cluster,
        InventoryFacet::Namespace => FacetColumn::Namespace,
        InventoryFacet::WorkloadKind => FacetColumn::WorkloadKind,
        InventoryFacet::WorkloadName => FacetColumn::WorkloadName,
        InventoryFacet::ContainerName => FacetColumn::ContainerName,
    };
    let search = load.scope.search_pattern();
    let facet_search = load.facet_search.as_ref().map(|value| format!("%{value}%"));
    Ok(InventoryRepository::facet_options(
        pool,
        column,
        load.scope.filter(
            load.organization_id,
            load.project_id,
            load.application_id,
            search.as_deref(),
        ),
        load.kind.as_deref(),
        facet_search.as_deref(),
        load.cursor.as_ref().map(|value| value.item_count),
        load.cursor.as_ref().map(|value| value.label.as_str()),
        load.cursor.as_ref().map(|value| value.value.as_str()),
        load.limit + 1,
    )
    .await?)
}

fn facet_next_cursor(
    items: &mut Vec<FacetOption>,
    limit: i64,
    facet: InventoryFacet,
    fingerprint: String,
) -> Result<Option<String>, InventoryServiceError> {
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

fn encode_cursor<T: Serialize>(cursor: &T) -> Result<String, InventoryServiceError> {
    serde_json::to_vec(cursor)
        .map(hex::encode)
        .map_err(|_| InventoryServiceError::Invalid("cursor cannot be encoded".into()))
}

fn decode_cursor<T: DeserializeOwned>(cursor: &str) -> Result<T, InventoryServiceError> {
    let bytes = hex::decode(cursor)
        .map_err(|_| InventoryServiceError::Invalid("cursor is invalid".into()))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| InventoryServiceError::Invalid("cursor is invalid".into()))
}

/// Reads and labels an application's runtime inventory.
#[derive(Clone, Debug)]
pub struct InventoryService {
    pool: PgPool,
    identity_tokens: IdentityTokenCodec,
}

impl InventoryService {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            identity_tokens: IdentityTokenCodec::process_default(),
        }
    }

    /// Names an item for the project. With `expected_updated_at`, only the label
    /// last changed then is replaced; otherwise the change conflicts.
    pub async fn put_user_label(
        &self,
        identity: IdentityPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        item_id: Uuid,
        input: PutUserLabel,
    ) -> Result<UserLabel, InventoryServiceError> {
        let principal = self.project_principal(identity, project_id).await?;
        let display_name = normalize_display_name(&input.display_name)?;
        let row = InventoryRepository::put_user_label::<_, UserLabel>(
            &self.pool,
            principal.organization_id,
            project_id,
            application_id,
            item_id,
            display_name,
            principal.user_id,
            input.expected_updated_at,
        )
        .await?;
        if let Some(row) = row {
            return Ok(row);
        }
        ensure_item(&self.pool, principal, project_id, application_id, item_id).await?;
        Err(InventoryServiceError::Conflict)
    }

    /// Removes an item's label, under the same optimistic check as setting it.
    pub async fn delete_user_label(
        &self,
        identity: IdentityPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        item_id: Uuid,
        input: DeleteUserLabel,
    ) -> Result<(), InventoryServiceError> {
        let principal = self.project_principal(identity, project_id).await?;
        ensure_item(&self.pool, principal, project_id, application_id, item_id).await?;
        let result = InventoryRepository::delete_user_label(
            &self.pool,
            principal.organization_id,
            project_id,
            application_id,
            item_id,
            input.expected_updated_at,
        )
        .await?;
        if result.rows_affected() == 0 && input.expected_updated_at.is_some() {
            let exists: bool = InventoryRepository::user_label_exists(&self.pool, item_id).await?;
            if exists {
                return Err(InventoryServiceError::Conflict);
            }
        }
        Ok(())
    }

    /// Item and occurrence counts per inventory kind within the scope.
    /// `started` is when the request arrived, for the latency metrics.
    pub async fn summary(
        &self,
        identity: IdentityPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        query: SummaryQuery,
        started: Instant,
    ) -> Result<InventorySummary, InventoryServiceError> {
        let principal = self.project_principal(identity, project_id).await?;
        ensure_application(&self.pool, principal, project_id, application_id).await?;
        let scope = record_validation(query.scope.normalize(), "summary", "scope", false)?;
        record_validation(
            validate_release_scope(
                &self.pool,
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
        let rows: Vec<KindAggregate> = InventoryRepository::kind_summary(
            &self.pool,
            scope.filter(
                principal.organization_id,
                project_id,
                application_id,
                search.as_deref(),
            ),
        )
        .await?;
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
        Ok(InventorySummary {
            coverage: crate::runtime_retention::history::coverage(
                &self.pool,
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
        })
    }

    /// The items of one kind with the most occurrences, each with an identity
    /// token that selects it in the item list, and the rest folded together.
    #[allow(clippy::too_many_lines)]
    pub async fn distribution(
        &self,
        identity: IdentityPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        query: DistributionQuery,
        started: Instant,
    ) -> Result<InventoryDistribution, InventoryServiceError> {
        let principal = self.project_principal(identity, project_id).await?;
        ensure_application(&self.pool, principal, project_id, application_id).await?;
        validate_kind(Some(&query.kind))?;
        let scope = query.scope.normalize()?;
        validate_release_scope(
            &self.pool,
            principal,
            project_id,
            application_id,
            scope.release_id,
        )
        .await?;
        let limit = aggregate_limit(query.limit)?;
        let version = CURRENT_INVENTORY_IDENTITY_VERSION.get();
        let search = scope.search_pattern();
        let rows: Vec<DistributionRow> = InventoryRepository::distribution(
            &self.pool,
            scope.filter(
                principal.organization_id,
                project_id,
                application_id,
                search.as_deref(),
            ),
            &query.kind,
            limit,
        )
        .await?;
        let total_item_count = rows.first().map_or(0, |row| row.total_item_count);
        let total_occurrence_count = rows.first().map_or(0, |row| row.total_occurrence_count);
        let mut entry_occurrence_count = 0;
        let mut entries = Vec::with_capacity(rows.len());
        for row in rows {
            entry_occurrence_count += row.occurrence_count;
            let identity_digest = hex::encode(&row.identity_digest);
            let identity_token = self.identity_tokens.issue(IdentityTokenPayload {
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
                user_label: row.user_label,
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
        Ok(InventoryDistribution {
            coverage: crate::runtime_retention::history::coverage(
                &self.pool,
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
        })
    }

    /// The values of one deployment facet within the scope, ignoring the
    /// facet's own filter, most common first. Validation failures are counted
    /// in the metrics.
    pub async fn facets(
        &self,
        identity: IdentityPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        facet_name: &str,
        query: FacetQuery,
        started: Instant,
    ) -> Result<FacetPage, InventoryServiceError> {
        let principal = self.project_principal(identity, project_id).await?;
        ensure_application(&self.pool, principal, project_id, application_id).await?;
        let facet = record_validation(
            InventoryFacet::parse(facet_name),
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
                &self.pool,
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
            return Err(InventoryServiceError::Invalid(
                "facet cursor is invalid for this scope".into(),
            ));
        }
        let mut items = load_facet_options(
            &self.pool,
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
        Ok(FacetPage {
            coverage: crate::runtime_retention::history::coverage(
                &self.pool,
                principal.organization_id,
                project_id,
            )
            .await?,
            items,
            next_cursor,
        })
    }

    /// The items within the scope, newest first.
    #[allow(clippy::too_many_lines)]
    pub async fn list_items(
        &self,
        identity: IdentityPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        query: InventoryQuery,
        started: Instant,
    ) -> Result<InventoryItemPage, InventoryServiceError> {
        let principal = self.project_principal(identity, project_id).await?;
        ensure_application(&self.pool, principal, project_id, application_id).await?;
        validate_kind(query.kind.as_deref())?;
        if query.verdict.as_deref().is_some_and(|value| {
            !matches!(
                value,
                "unclassified" | "expected" | "requires_review" | "policy_conflict"
            )
        }) {
            return Err(InventoryServiceError::Invalid("verdict is invalid".into()));
        }
        let identity = query
            .identity_token
            .as_deref()
            .map(|token| {
                self.identity_tokens.validate(
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
            &self.pool,
            principal,
            project_id,
            application_id,
            scope.release_id,
        )
        .await?;
        let limit = limit(query.limit)?;
        let cursor = if let Some(cursor) = query.cursor {
            Some(
                InventoryRepository::item_cursor(
                    &self.pool,
                    principal.organization_id,
                    project_id,
                    application_id,
                    cursor,
                    CURRENT_INVENTORY_IDENTITY_VERSION.get(),
                )
                .await?
                .ok_or_else(|| {
                    InventoryServiceError::Invalid("cursor is invalid for this application".into())
                })?,
            )
        } else {
            None
        };
        let (cursor_time, cursor_id) =
            cursor.map_or((None, None), |(time, id)| (Some(time), Some(id)));
        let search = scope.search_pattern();
        let mut items: Vec<InventoryItem> = InventoryRepository::item_page(
            &self.pool,
            scope.filter(
                principal.organization_id,
                project_id,
                application_id,
                search.as_deref(),
            ),
            query.kind.as_deref(),
            identity.as_ref().map(|value| value.item_id),
            identity
                .as_ref()
                .and_then(|value| hex::decode(&value.identity_digest).ok()),
            query.verdict.as_deref(),
            query.suppressed,
            query.evaluation_pending,
            cursor_time,
            cursor_id,
            limit + 1,
        )
        .await?;
        let next_cursor = if items.len() > usize::try_from(limit).unwrap_or(usize::MAX) {
            items.pop();
            items.last().map(|item| item.id)
        } else {
            None
        };
        crate::metrics::record_inventory_query(
            u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
        Ok(InventoryItemPage {
            coverage: crate::runtime_retention::history::coverage(
                &self.pool,
                principal.organization_id,
                project_id,
            )
            .await?,
            items,
            next_cursor,
        })
    }

    /// One item with links to its evidence and where policies place it.
    pub async fn item_detail(
        &self,
        identity: IdentityPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        item_id: Uuid,
        started: Instant,
    ) -> Result<InventoryItemDetail, InventoryServiceError> {
        let principal = self.project_principal(identity, project_id).await?;
        let item = self
            .fetch_item(principal, project_id, application_id, item_id)
            .await?;
        let policy_placement_summary: Value = InventoryRepository::placement_summary(
            &self.pool,
            principal.organization_id,
            project_id,
            application_id,
            item_id,
            crate::policy::POLICY_EVALUATOR_VERSION,
        )
        .await?;
        crate::metrics::record_inventory_query(
            u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
        Ok(InventoryItemDetail {
            coverage: crate::runtime_retention::history::coverage(
                &self.pool,
                principal.organization_id,
                project_id,
            )
            .await?,
            item,
            evidence: EvidenceLinks::scoped(project_id, application_id, item_id),
            policy_placement_summary,
        })
    }

    /// Whether the item appeared in each release of the application.
    pub async fn item_releases(
        &self,
        identity: IdentityPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        item_id: Uuid,
        query: PageQuery,
    ) -> Result<ReleasePresencePage, InventoryServiceError> {
        let principal = self.project_principal(identity, project_id).await?;
        ensure_item(&self.pool, principal, project_id, application_id, item_id).await?;
        let limit = limit(query.limit)?;
        let cursor = if let Some(cursor) = query.cursor {
            Some(
                crate::repository::ReleaseRepository::cursor(
                    &self.pool,
                    crate::repository::ApplicationScope {
                        organization_id: principal.organization_id,
                        project_id,
                        application_id,
                    },
                    cursor,
                )
                .await?
                .ok_or_else(|| {
                    InventoryServiceError::Invalid("release cursor is invalid".into())
                })?,
            )
        } else {
            None
        };
        let (cursor_time, cursor_id) =
            cursor.map_or((None, None), |(time, id)| (Some(time), Some(id)));
        let mut items = InventoryRepository::release_presence_page::<_, ReleasePresence>(
            &self.pool,
            principal.organization_id,
            project_id,
            application_id,
            item_id,
            cursor_time,
            cursor_id,
            limit + 1,
        )
        .await?;
        let next_cursor = if items.len() > usize::try_from(limit).unwrap_or(usize::MAX) {
            items.pop();
            items.last().map(|item| item.release_id)
        } else {
            None
        };
        Ok(ReleasePresencePage {
            coverage: crate::runtime_retention::history::coverage(
                &self.pool,
                principal.organization_id,
                project_id,
            )
            .await?,
            items,
            next_cursor,
        })
    }

    /// Where the item was seen: each cluster, workload, pod and container.
    pub async fn item_sightings(
        &self,
        identity: IdentityPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        item_id: Uuid,
        query: StringCursorPageQuery,
    ) -> Result<SightingPage, InventoryServiceError> {
        let principal = self.project_principal(identity, project_id).await?;
        ensure_item(&self.pool, principal, project_id, application_id, item_id).await?;
        let limit = limit(query.limit)?;
        let cursor: Option<SightingCursor> =
            query.cursor.as_deref().map(decode_cursor).transpose()?;
        let mut items = InventoryRepository::sighting_page::<_, InventorySighting>(
            &self.pool,
            principal.organization_id,
            project_id,
            application_id,
            item_id,
            cursor.as_ref().map(|value| value.last_seen_at),
            cursor.as_ref().map(|value| value.cluster_id),
            cursor.as_ref().map(|value| value.namespace.as_str()),
            cursor.as_ref().map(|value| value.workload_kind.as_str()),
            cursor.as_ref().map(|value| value.workload_name.as_str()),
            cursor.as_ref().map(|value| value.pod_uid.as_str()),
            cursor.as_ref().map(|value| value.container_name.as_str()),
            limit + 1,
            crate::policy::POLICY_EVALUATOR_VERSION,
        )
        .await?;
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
        Ok(SightingPage {
            coverage: crate::runtime_retention::history::coverage(
                &self.pool,
                principal.organization_id,
                project_id,
            )
            .await?,
            items,
            next_cursor,
        })
    }

    /// The runtime groups the item's occurrences belong to.
    pub async fn item_groups(
        &self,
        identity: IdentityPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        item_id: Uuid,
        query: PageQuery,
    ) -> Result<GroupPage, InventoryServiceError> {
        let principal = self.project_principal(identity, project_id).await?;
        ensure_item(&self.pool, principal, project_id, application_id, item_id).await?;
        let limit = limit(query.limit)?;
        let mut items = InventoryRepository::group_page::<_, InventoryGroup>(
            &self.pool,
            principal.organization_id,
            project_id,
            application_id,
            item_id,
            query.cursor,
            limit + 1,
        )
        .await?;
        let next_cursor = if items.len() > usize::try_from(limit).unwrap_or(usize::MAX) {
            items.pop();
            items.last().map(|item| item.id)
        } else {
            None
        };
        Ok(GroupPage {
            coverage: crate::runtime_retention::history::coverage(
                &self.pool,
                principal.organization_id,
                project_id,
            )
            .await?,
            items,
            next_cursor,
        })
    }

    /// The item's individual occurrences, newest first.
    pub async fn item_occurrences(
        &self,
        identity: IdentityPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        item_id: Uuid,
        query: PageQuery,
    ) -> Result<OccurrencePage, InventoryServiceError> {
        let principal = self.project_principal(identity, project_id).await?;
        ensure_item(&self.pool, principal, project_id, application_id, item_id).await?;
        let limit = limit(query.limit)?;
        let cursor = if let Some(cursor) = query.cursor {
            Some(
                InventoryRepository::occurrence_cursor(
                    &self.pool,
                    principal.organization_id,
                    project_id,
                    application_id,
                    item_id,
                    cursor,
                )
                .await?
                .ok_or_else(|| {
                    InventoryServiceError::Invalid("occurrence cursor is invalid".into())
                })?,
            )
        } else {
            None
        };
        let (cursor_time, cursor_id) =
            cursor.map_or((None, None), |(time, id)| (Some(time), Some(id)));
        let mut items = InventoryRepository::occurrence_page::<_, InventoryOccurrence>(
            &self.pool,
            principal.organization_id,
            project_id,
            application_id,
            item_id,
            CURRENT_INVENTORY_IDENTITY_VERSION.get(),
            cursor_time,
            cursor_id,
            limit + 1,
        )
        .await?;
        let next_cursor = if items.len() > usize::try_from(limit).unwrap_or(usize::MAX) {
            items.pop();
            items.last().map(|item| item.id)
        } else {
            None
        };
        Ok(OccurrencePage {
            coverage: crate::runtime_retention::history::coverage(
                &self.pool,
                principal.organization_id,
                project_id,
            )
            .await?,
            items,
            next_cursor,
        })
    }

    /// Resolves the project's organization and checks the principal may see
    /// the project; a project they cannot see does not exist for them.
    async fn project_principal(
        &self,
        identity: IdentityPrincipal,
        project_id: Uuid,
    ) -> Result<ProjectPrincipal, InventoryServiceError> {
        let organization_id: Uuid = ProjectRepository::organization_of(&self.pool, project_id)
            .await?
            .ok_or(InventoryServiceError::NotFound)?;
        resolve_project_access(&self.pool, identity, organization_id, project_id)
            .await?
            .ok_or(InventoryServiceError::NotFound)?;
        Ok(ProjectPrincipal {
            organization_id,
            user_id: identity.user_id,
        })
    }

    async fn fetch_item(
        &self,
        principal: ProjectPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        item_id: Uuid,
    ) -> Result<InventoryItem, InventoryServiceError> {
        InventoryRepository::item::<_, InventoryItem>(
            &self.pool,
            principal.organization_id,
            project_id,
            application_id,
            item_id,
            CURRENT_INVENTORY_IDENTITY_VERSION.get(),
        )
        .await?
        .ok_or(InventoryServiceError::NotFound)
    }
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
            Err(InventoryServiceError::IdentityToken(
                IdentityTokenProblem::Invalid
            ))
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
            Err(InventoryServiceError::IdentityToken(
                IdentityTokenProblem::ScopeMismatch
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
            Err(InventoryServiceError::IdentityToken(
                IdentityTokenProblem::Invalid
            ))
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
            Err(InventoryServiceError::IdentityToken(
                IdentityTokenProblem::Expired
            ))
        ));
    }

    /// The use cases against a real database, through the service.
    mod use_cases {
        use super::super::*;
        use crate::auth::OrganizationRole;
        use crate::repository::test_support::{Tenant, exec, ingest, tenant, user};

        fn owner(tenant: &Tenant, user_id: Uuid) -> IdentityPrincipal {
            IdentityPrincipal {
                user_id,
                session_id: Uuid::new_v4(),
                active_organization_id: Some(tenant.organization_id),
                organization_role: Some(OrganizationRole::Owner),
                is_super_admin: false,
                privileged_until: None,
            }
        }

        fn items(kind: Option<&str>, identity_token: Option<String>) -> InventoryQuery {
            InventoryQuery {
                scope: InventoryScope::default(),
                kind: kind.map(str::to_owned),
                identity_token,
                verdict: None,
                suppressed: None,
                evaluation_pending: None,
                cursor: None,
                limit: None,
            }
        }

        fn page() -> PageQuery {
            PageQuery {
                cursor: None,
                limit: None,
            }
        }

        /// Ingests `/bin/a` twice and `/bin/b` once; returns the id of `/bin/a`.
        async fn seed(pool: &PgPool, tenant: &Tenant) -> Uuid {
            let base = Utc::now() - chrono::Duration::hours(1);
            ingest(
                pool,
                tenant,
                &[
                    exec(tenant, "/bin/a", base),
                    exec(tenant, "/bin/a", base + chrono::Duration::minutes(1)),
                    exec(tenant, "/bin/b", base + chrono::Duration::minutes(2)),
                ],
            )
            .await;
            sqlx::query_scalar(
                "SELECT id FROM runtime_inventory_items WHERE application_id=$1 AND semantic_summary->>'executable'='/bin/a'",
            )
            .bind(tenant.application_id)
            .fetch_one(pool)
            .await
            .unwrap()
        }

        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn access_is_checked_before_the_scope(pool: PgPool) {
            let other = tenant(&pool, "inventory-service-other").await;
            let tenant = tenant(&pool, "inventory-service-access").await;
            let service = InventoryService::new(pool.clone());
            let invalid = || SummaryQuery {
                scope: InventoryScope {
                    search: Some(String::new()),
                    ..InventoryScope::default()
                },
            };
            let stranger = owner(&other, Uuid::new_v4());
            let principal = owner(&tenant, Uuid::new_v4());
            let (project, application) = (tenant.project_id, tenant.application_id);
            assert!(matches!(
                service
                    .summary(stranger, project, application, invalid(), Instant::now())
                    .await,
                Err(InventoryServiceError::NotFound)
            ));
            assert!(matches!(
                service
                    .summary(
                        principal,
                        project,
                        other.application_id,
                        invalid(),
                        Instant::now()
                    )
                    .await,
                Err(InventoryServiceError::NotFound)
            ));
            assert!(matches!(
                service
                    .summary(principal, project, application, invalid(), Instant::now())
                    .await,
                Err(InventoryServiceError::Invalid(_))
            ));
            let foreign_release = SummaryQuery {
                scope: InventoryScope {
                    release_id: Some(Uuid::new_v4()),
                    ..InventoryScope::default()
                },
            };
            assert!(matches!(
                service
                    .summary(principal, project, application, foreign_release, Instant::now())
                    .await,
                Err(InventoryServiceError::Invalid(message))
                    if message == "release_id is invalid for this application"
            ));
            let summary = service
                .summary(
                    principal,
                    project,
                    application,
                    SummaryQuery {
                        scope: InventoryScope::default(),
                    },
                    Instant::now(),
                )
                .await
                .unwrap();
            assert_eq!(summary.item_count, 0);
            assert_eq!(summary.kinds.len(), 7);
        }

        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn identity_tokens_select_one_item_of_their_kind(pool: PgPool) {
            let tenant = tenant(&pool, "inventory-service-tokens").await;
            let a = seed(&pool, &tenant).await;
            let service = InventoryService::new(pool.clone());
            let principal = owner(&tenant, Uuid::new_v4());
            let (project, application) = (tenant.project_id, tenant.application_id);

            let summary = service
                .summary(
                    principal,
                    project,
                    application,
                    SummaryQuery {
                        scope: InventoryScope::default(),
                    },
                    Instant::now(),
                )
                .await
                .unwrap();
            let process = summary
                .kinds
                .iter()
                .find(|kind| kind.kind == "process")
                .unwrap();
            assert_eq!((process.item_count, process.occurrence_count), (2, 3));

            let distribution = service
                .distribution(
                    principal,
                    project,
                    application,
                    DistributionQuery {
                        scope: InventoryScope::default(),
                        kind: "process".into(),
                        limit: Some(1),
                    },
                    Instant::now(),
                )
                .await
                .unwrap();
            assert_eq!(distribution.entries.len(), 1);
            let other = distribution.other.as_ref().expect("one item is folded");
            assert_eq!((other.item_count, other.occurrence_count), (1, 1));
            let token = distribution.entries[0].identity_token.clone();

            let selected = service
                .list_items(
                    principal,
                    project,
                    application,
                    items(Some("process"), Some(token.clone())),
                    Instant::now(),
                )
                .await
                .unwrap();
            assert_eq!(selected.items.len(), 1);
            assert_eq!(selected.items[0].id, a);
            assert!(matches!(
                service
                    .list_items(
                        principal,
                        project,
                        application,
                        items(Some("domain"), Some(token)),
                        Instant::now(),
                    )
                    .await,
                Err(InventoryServiceError::IdentityToken(
                    IdentityTokenProblem::ScopeMismatch
                ))
            ));
            assert!(matches!(
                service
                    .list_items(
                        principal,
                        project,
                        application,
                        items(None, Some("garbage".into())),
                        Instant::now(),
                    )
                    .await,
                Err(InventoryServiceError::IdentityToken(
                    IdentityTokenProblem::Invalid
                ))
            ));
            let mut unknown_verdict = items(None, Some("garbage".into()));
            unknown_verdict.verdict = Some("maybe".into());
            // The verdict is checked before the identity token.
            assert!(matches!(
                service
                    .list_items(principal, project, application, unknown_verdict, Instant::now())
                    .await,
                Err(InventoryServiceError::Invalid(message)) if message == "verdict is invalid"
            ));

            let facets = service
                .facets(
                    principal,
                    project,
                    application,
                    "namespace",
                    FacetQuery {
                        scope: InventoryScope::default(),
                        kind: None,
                        facet_search: None,
                        cursor: None,
                        limit: None,
                    },
                    Instant::now(),
                )
                .await
                .unwrap();
            assert_eq!(facets.items.len(), 1);
            assert_eq!(facets.items[0].value, "production");
            assert!(matches!(
                service
                    .facets(
                        principal,
                        project,
                        application,
                        "pod",
                        FacetQuery {
                            scope: InventoryScope::default(),
                            kind: None,
                            facet_search: None,
                            cursor: None,
                            limit: None,
                        },
                        Instant::now(),
                    )
                    .await,
                Err(InventoryServiceError::Invalid(message)) if message == "unsupported inventory facet"
            ));
        }

        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn items_show_their_evidence_and_take_labels(pool: PgPool) {
            let tenant = tenant(&pool, "inventory-service-items").await;
            let a = seed(&pool, &tenant).await;
            let service = InventoryService::new(pool.clone());
            let principal = owner(&tenant, user(&pool).await);
            let (project, application) = (tenant.project_id, tenant.application_id);

            let detail = service
                .item_detail(principal, project, application, a, Instant::now())
                .await
                .unwrap();
            assert_eq!(detail.item.occurrence_count, 2);
            assert!(
                detail
                    .evidence
                    .occurrences
                    .ends_with(&format!("{a}/occurrences"))
            );
            assert!(matches!(
                service
                    .item_detail(
                        principal,
                        project,
                        application,
                        Uuid::new_v4(),
                        Instant::now()
                    )
                    .await,
                Err(InventoryServiceError::NotFound)
            ));
            let occurrences = service
                .item_occurrences(principal, project, application, a, page())
                .await
                .unwrap();
            assert_eq!(occurrences.items.len(), 2);
            let sightings = service
                .item_sightings(
                    principal,
                    project,
                    application,
                    a,
                    StringCursorPageQuery {
                        cursor: None,
                        limit: None,
                    },
                )
                .await
                .unwrap();
            assert_eq!(sightings.items.len(), 2, "one sighting per pod");
            let groups = service
                .item_groups(principal, project, application, a, page())
                .await
                .unwrap();
            assert_eq!(groups.items.len(), 1);
            let releases = service
                .item_releases(principal, project, application, a, page())
                .await
                .unwrap();
            assert!(releases.items.is_empty());
            assert!(matches!(
                service
                    .item_occurrences(
                        principal,
                        project,
                        application,
                        a,
                        PageQuery {
                            cursor: Some(Uuid::new_v4()),
                            limit: None,
                        },
                    )
                    .await,
                Err(InventoryServiceError::Invalid(message)) if message == "occurrence cursor is invalid"
            ));

            assert!(matches!(
                service
                    .put_user_label(
                        principal,
                        project,
                        application,
                        a,
                        PutUserLabel {
                            display_name: " ".into(),
                            expected_updated_at: None,
                        },
                    )
                    .await,
                Err(InventoryServiceError::Invalid(_))
            ));
            let label = service
                .put_user_label(
                    principal,
                    project,
                    application,
                    a,
                    PutUserLabel {
                        display_name: " Web server ".into(),
                        expected_updated_at: None,
                    },
                )
                .await
                .unwrap();
            assert_eq!(label.display_name, "Web server");
            let stale = Some(label.updated_at - chrono::Duration::seconds(1));
            assert!(matches!(
                service
                    .put_user_label(
                        principal,
                        project,
                        application,
                        a,
                        PutUserLabel {
                            display_name: "Other".into(),
                            expected_updated_at: stale,
                        },
                    )
                    .await,
                Err(InventoryServiceError::Conflict)
            ));
            assert!(matches!(
                service
                    .delete_user_label(
                        principal,
                        project,
                        application,
                        a,
                        DeleteUserLabel {
                            expected_updated_at: stale,
                        },
                    )
                    .await,
                Err(InventoryServiceError::Conflict)
            ));
            service
                .delete_user_label(
                    principal,
                    project,
                    application,
                    a,
                    DeleteUserLabel {
                        expected_updated_at: Some(label.updated_at),
                    },
                )
                .await
                .unwrap();
        }
    }
}
