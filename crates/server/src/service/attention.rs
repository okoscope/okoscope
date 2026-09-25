//! Attention summaries: what needs a person's attention across an
//! organization or in one application, with recommendations.
//!
//! The query types below are also the request's query strings.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

use crate::auth::{IdentityPrincipal, OrganizationRole};
use crate::notification::health::{
    NotificationHealthState, NotificationQueueSnapshot, derive_state,
};
use crate::repository::MembershipRepository;
use crate::repository::attention::AttentionRepository;
use crate::repository::resources::ResourceRepository;
use crate::repository::transaction::TransactionRepository;
use crate::service::project_access::project_scope;

/// Why an attention use case failed.
#[derive(Debug, Error)]
pub enum AttentionServiceError {
    /// A limit is out of range; the message says which.
    #[error("{0}")]
    Invalid(String),
    /// No active organization, or the project or application does not exist
    /// or the principal may not see it.
    #[error("resource not found")]
    NotFound,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

// Authentication plus a fixed repository statement sequence; neither budget depends on tenant cardinality.
pub const ORGANIZATION_ATTENTION_QUERY_BUDGET: usize = 10;
pub const APPLICATION_ATTENTION_QUERY_BUDGET: usize = 10;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum WindowKind {
    #[serde(rename = "24h")]
    #[default]
    Day,
    #[serde(rename = "7d")]
    Week,
}
impl WindowKind {
    fn duration(self) -> Duration {
        match self {
            Self::Day => Duration::hours(24),
            Self::Week => Duration::days(7),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct OrganizationQuery {
    #[serde(default)]
    window: WindowKind,
    limit: Option<i64>,
    changed_application_limit: Option<i64>,
    recommendation_limit: Option<i64>,
}
#[derive(Debug, Deserialize)]
pub struct ApplicationQuery {
    #[serde(default)]
    window: WindowKind,
    limit: Option<i64>,
    largest_change_limit: Option<i64>,
    recommendation_limit: Option<i64>,
}

fn bounded(
    value: Option<i64>,
    default: i64,
    max: i64,
    name: &str,
) -> Result<i64, AttentionServiceError> {
    let value = value.unwrap_or(default);
    if (1..=max).contains(&value) {
        Ok(value)
    } else {
        Err(AttentionServiceError::Invalid(format!(
            "{name} must be between 1 and {max}"
        )))
    }
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct ProjectRef {
    id: Uuid,
    name: String,
    slug: String,
}
#[derive(Clone, Debug, FromRow, Serialize)]
pub struct ApplicationRef {
    id: Uuid,
    name: String,
    slug: String,
}
#[derive(Clone, Debug, FromRow, Serialize)]
pub struct ReleaseRef {
    id: Uuid,
    version: String,
    display_name: String,
    deployed_at: DateTime<Utc>,
}
#[derive(Clone, Debug, Serialize)]
pub struct AttentionWindow {
    kind: WindowKind,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum Priority {
    Urgent,
    High,
    Normal,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum ItemKind {
    NotificationDeliveryFailing,
    NotificationDeliveryBacklogged,
    NotificationDestinationMissing,
    ReleaseRuntimeChanged,
    NewDiscovery,
    OpenDiscovery,
    ContainerRestartLoop,
    ResourceRegression,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReasonCode {
    NotificationHealthFailing,
    NotificationHealthBacklogged,
    NotificationHealthRetrying,
    EnabledDestinationMissing,
    ReleaseRuntimeChanged,
    DiscoveryFirstSeenInWindow,
    DiscoveryOpen,
    ContainerRestartLoopObserved,
    PolicyReviewRequired,
    PolicyConflict,
    PolicyUnclassified,
    PolicyEvaluationPending,
    OomObserved,
    MemoryLimitPressure,
    CpuThrottlingIncreased,
    CpuPressureIncreased,
    MemoryPressureIncreased,
    IoPressureIncreased,
    ResourceUsageIncreased,
}
#[derive(Clone, Debug, Serialize)]
struct RestartLoopFacts {
    projection_version: i64,
    threshold: i64,
    observed_restart_count: i64,
    window_started_at: DateTime<Utc>,
    window_ended_at: DateTime<Utc>,
    container_name: String,
}
#[derive(Clone, Debug, Serialize)]
#[allow(clippy::struct_field_names)]
struct AttentionFacts {
    reason_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    new_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disappeared_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failed_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    occurrence_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    restart_loop: Option<RestartLoopFacts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_regression: Option<Value>,
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ResourceRef {
    Project {
        project_id: Uuid,
    },
    Application {
        project_id: Uuid,
        application_id: Uuid,
    },
    RuntimeGroup {
        project_id: Uuid,
        application_id: Uuid,
        runtime_group_id: Uuid,
        event_kind: String,
        semantic_summary: Value,
        user_labels: Value,
        namespace: String,
        workload_kind: String,
        workload_name: String,
        policy_verdict: Option<String>,
        policy_evaluation_state: String,
    },
    RuntimeDiff {
        project_id: Uuid,
        application_id: Uuid,
        target_release_id: Uuid,
        target_release_display_name: String,
        baseline_release_id: Uuid,
        baseline_release_display_name: String,
    },
    ResourceComparison {
        project_id: Uuid,
        application_id: Uuid,
        target_release_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    },
}
#[derive(Clone, Debug, Serialize)]
pub struct PriorityItem {
    id: String,
    kind: ItemKind,
    priority: Priority,
    reason_code: ReasonCode,
    facts: AttentionFacts,
    occurred_at: DateTime<Utc>,
    project: ProjectRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    application: Option<ApplicationRef>,
    resource: ResourceRef,
    #[serde(skip)]
    stable_id: Uuid,
}

#[derive(Clone, Debug, FromRow)]
struct DiscoveryRow {
    group_id: Uuid,
    project_id: Uuid,
    project_name: String,
    project_slug: String,
    application_id: Uuid,
    application_name: String,
    application_slug: String,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    occurrence_count: i64,
    event_kind: String,
    semantic_summary: Value,
    user_labels: Value,
    namespace: String,
    workload_kind: String,
    workload_name: String,
    is_new: bool,
    policy_verdict: Option<String>,
    policy_evaluation_state: String,
}

#[derive(Clone, Debug, FromRow)]
struct ChangedRow {
    project_id: Uuid,
    project_name: String,
    project_slug: String,
    application_id: Uuid,
    application_name: String,
    application_slug: String,
    target_id: Uuid,
    target_version: String,
    target_display_name: String,
    target_deployed_at: DateTime<Utc>,
    baseline_id: Uuid,
    baseline_version: String,
    baseline_display_name: String,
    baseline_deployed_at: DateTime<Utc>,
    new_count: i64,
    disappeared_count: i64,
    unchanged_count: i64,
    total_item_count: i64,
    absolute_occurrence_delta_sum: i64,
    max_absolute_occurrence_delta: i64,
}

#[derive(Clone, Debug, Serialize)]
struct LargestChange {
    group_id: Uuid,
    classification: String,
    baseline_occurrence_count: i64,
    target_occurrence_count: i64,
    occurrence_delta: i64,
}
#[derive(Clone, Debug, Serialize)]
pub struct ReleaseComparison {
    target_release: ReleaseRef,
    baseline_release: Option<ReleaseRef>,
    new_count: i64,
    disappeared_count: i64,
    unchanged_count: i64,
    total_item_count: i64,
    absolute_occurrence_delta_sum: i64,
    max_absolute_occurrence_delta: i64,
    largest_changes: Vec<LargestChange>,
}
#[derive(Clone, Debug, Serialize)]
pub struct ChangedApplication {
    project: ProjectRef,
    application: ApplicationRef,
    #[serde(flatten)]
    comparison: ReleaseComparison,
    changed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, FromRow)]
struct ProblemRow {
    project_id: Uuid,
    project_name: String,
    project_slug: String,
    enabled_destination_count: i64,
    pending_count: i64,
    due_count: i64,
    retrying_count: i64,
    in_flight_count: i64,
    expired_lease_count: i64,
    failed_count: i64,
    oldest_due_age_seconds: Option<i64>,
    total_problem_count: i64,
}
#[derive(Clone, Debug, Serialize)]
pub struct NotificationProblem {
    project: ProjectRef,
    state: NotificationHealthState,
    delivery_enabled: bool,
    enabled_destination_count: i64,
    pending_count: i64,
    due_count: i64,
    retrying_count: i64,
    in_flight_count: i64,
    expired_lease_count: i64,
    failed_count: i64,
    oldest_due_age_seconds: Option<i64>,
    observed_at: DateTime<Utc>,
    priority: Priority,
    reason_code: ReasonCode,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum RecommendationKind {
    ReviewFailedDeliveries,
    ConfigureWebhookDestination,
    ReviewNotificationBacklog,
    ReviewReleaseChanges,
    ReviewNewDiscoveries,
    ReviewResourceRegression,
}
#[derive(Clone, Debug, Serialize)]
pub struct Recommendation {
    id: String,
    kind: RecommendationKind,
    priority: Priority,
    reason_code: ReasonCode,
    facts: AttentionFacts,
    project: ProjectRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    application: Option<ApplicationRef>,
    resource: ResourceRef,
    created_from_snapshot_at: DateTime<Utc>,
}

#[derive(Clone, Debug, FromRow)]
struct NewDiscoveryScope {
    project_id: Uuid,
    project_name: String,
    project_slug: String,
    application_id: Uuid,
    application_name: String,
    application_slug: String,
    discovery_count: i64,
}

#[derive(Clone, Debug, FromRow)]
struct ResourceFindingRow {
    id: Uuid,
    project_id: Uuid,
    project_name: String,
    project_slug: String,
    application_id: Uuid,
    application_name: String,
    application_slug: String,
    target_release_id: Uuid,
    priority: String,
    reason_code: String,
    facts: Value,
    opened_at: DateTime<Utc>,
}

async fn load_resource_findings(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    project_ids: &[Uuid],
    application_id: Option<Uuid>,
    from: DateTime<Utc>,
    limit: i64,
) -> Result<Vec<ResourceFindingRow>, sqlx::Error> {
    AttentionRepository::resource_findings(
        &mut **tx,
        organization_id,
        project_ids,
        application_id,
        from,
        limit,
    )
    .await
}

fn resource_reason(value: &str) -> ReasonCode {
    match value {
        "oom_observed" => ReasonCode::OomObserved,
        "memory_limit_pressure" => ReasonCode::MemoryLimitPressure,
        "cpu_throttling_increased" => ReasonCode::CpuThrottlingIncreased,
        "cpu_pressure_increased" => ReasonCode::CpuPressureIncreased,
        "memory_pressure_increased" => ReasonCode::MemoryPressureIncreased,
        "io_pressure_increased" => ReasonCode::IoPressureIncreased,
        _ => ReasonCode::ResourceUsageIncreased,
    }
}

fn resource_priority(value: &str) -> Priority {
    match value {
        "urgent" => Priority::Urgent,
        "high" => Priority::High,
        _ => Priority::Normal,
    }
}

fn resource_item(row: &ResourceFindingRow) -> PriorityItem {
    let from =
        serde_json::from_value(row.facts["target_window"]["from"].clone()).unwrap_or(row.opened_at);
    let to =
        serde_json::from_value(row.facts["target_window"]["to"].clone()).unwrap_or(row.opened_at);
    PriorityItem {
        id: format!("resource_regression:{}", row.id),
        kind: ItemKind::ResourceRegression,
        priority: resource_priority(&row.priority),
        reason_code: resource_reason(&row.reason_code),
        facts: AttentionFacts {
            reason_count: 1,
            new_count: None,
            disappeared_count: None,
            failed_count: None,
            occurrence_count: None,
            restart_loop: None,
            resource_regression: Some(row.facts.clone()),
        },
        occurred_at: row.opened_at,
        project: ProjectRef {
            id: row.project_id,
            name: row.project_name.clone(),
            slug: row.project_slug.clone(),
        },
        application: Some(ApplicationRef {
            id: row.application_id,
            name: row.application_name.clone(),
            slug: row.application_slug.clone(),
        }),
        resource: ResourceRef::ResourceComparison {
            project_id: row.project_id,
            application_id: row.application_id,
            target_release_id: row.target_release_id,
            from,
            to,
        },
        stable_id: row.id,
    }
}

fn resource_recommendations(
    rows: &[ResourceFindingRow],
    now: DateTime<Utc>,
) -> Vec<Recommendation> {
    let mut seen = std::collections::HashSet::new();
    rows.iter()
        .filter(|row| seen.insert((row.application_id, row.target_release_id)))
        .map(|row| {
            let item = resource_item(row);
            Recommendation {
                id: format!(
                    "review_resource_regression:{}:{}",
                    row.application_id, row.target_release_id
                ),
                kind: RecommendationKind::ReviewResourceRegression,
                priority: item.priority,
                reason_code: item.reason_code,
                facts: item.facts,
                project: item.project,
                application: item.application,
                resource: item.resource,
                created_from_snapshot_at: now,
            }
        })
        .collect()
}

#[derive(Debug, FromRow, Serialize)]
pub struct OrganizationTotals {
    new_discoveries: i64,
    open_discoveries: i64,
    acknowledged_discoveries: i64,
    changed_applications: i64,
    projects_with_notification_problems: i64,
    failed_notification_deliveries: i64,
    resource_regressions: i64,
    policy: Value,
}
#[derive(Debug, Serialize)]
pub struct OrganizationSummary {
    generated_at: DateTime<Utc>,
    window: AttentionWindow,
    totals: OrganizationTotals,
    priority_items: Vec<PriorityItem>,
    changed_applications: Vec<ChangedApplication>,
    notification_problems: Vec<NotificationProblem>,
    recommendations: Vec<Recommendation>,
}
#[derive(Debug, Serialize)]
pub struct ApplicationTotals {
    new_discoveries: i64,
    open_discoveries: i64,
    acknowledged_discoveries: i64,
    new_runtime_items: i64,
    disappeared_runtime_items: i64,
    unchanged_runtime_items: i64,
    total_runtime_items: i64,
    resource_regressions: i64,
    policy: Value,
}
#[derive(Debug, Serialize)]
pub struct ApplicationSummary {
    generated_at: DateTime<Utc>,
    window: AttentionWindow,
    project: ProjectRef,
    application: ApplicationRef,
    totals: ApplicationTotals,
    release_comparison: Option<ReleaseComparison>,
    priority_items: Vec<PriorityItem>,
    recommendations: Vec<Recommendation>,
}

struct OrganizationAccess {
    organization_id: Uuid,
    project_ids: Vec<Uuid>,
}

async fn organization_access(
    state: &AttentionService,
    principal: IdentityPrincipal,
) -> Result<OrganizationAccess, AttentionServiceError> {
    let organization_id = principal
        .active_organization_id
        .ok_or(AttentionServiceError::NotFound)?;
    let inherited = principal.is_super_admin
        || principal
            .organization_role
            .is_some_and(OrganizationRole::inherits_project_access);
    let project_ids = if inherited {
        crate::repository::ProjectRepository::ids_in(&state.pool, organization_id).await?
    } else {
        MembershipRepository::accessible_project_ids(
            &state.pool,
            organization_id,
            principal.user_id,
        )
        .await?
    };
    Ok(OrganizationAccess {
        organization_id,
        project_ids,
    })
}

async fn project_organization(
    state: &AttentionService,
    principal: IdentityPrincipal,
    project_id: Uuid,
) -> Result<Uuid, AttentionServiceError> {
    let scope = project_scope(&state.pool, principal, project_id)
        .await?
        .ok_or(AttentionServiceError::NotFound)?;
    Ok(scope.organization_id)
}
async fn snapshot(
    pool: &PgPool,
) -> Result<(Transaction<'_, Postgres>, DateTime<Utc>), AttentionServiceError> {
    let mut tx = pool.begin().await?;
    TransactionRepository::begin_consistent_read(&mut *tx).await?;
    let now = TransactionRepository::snapshot_time(&mut *tx).await?;
    Ok((tx, now))
}

#[derive(FromRow)]
struct LargestRow {
    application_id: Uuid,
    group_id: Uuid,
    classification: String,
    baseline_occurrence_count: i64,
    target_occurrence_count: i64,
    occurrence_delta: i64,
}

async fn load_largest(
    tx: &mut Transaction<'_, Postgres>,
    rows: &[ChangedRow],
    limit: i64,
) -> Result<HashMap<Uuid, Vec<LargestChange>>, sqlx::Error> {
    if rows.is_empty() {
        return Ok(HashMap::new());
    }
    let application_ids: Vec<_> = rows.iter().map(|r| r.application_id).collect();
    let target_ids: Vec<_> = rows.iter().map(|r| r.target_id).collect();
    let baseline_ids: Vec<_> = rows.iter().map(|r| r.baseline_id).collect();
    let values: Vec<LargestRow> = AttentionRepository::largest_changes(
        &mut **tx,
        application_ids,
        target_ids,
        baseline_ids,
        limit,
    )
    .await?;
    let mut result: HashMap<Uuid, Vec<LargestChange>> = HashMap::new();
    for row in values {
        result
            .entry(row.application_id)
            .or_default()
            .push(LargestChange {
                group_id: row.group_id,
                classification: row.classification,
                baseline_occurrence_count: row.baseline_occurrence_count,
                target_occurrence_count: row.target_occurrence_count,
                occurrence_delta: row.occurrence_delta,
            });
    }
    Ok(result)
}

async fn load_changed(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    project_ids: &[Uuid],
    limit: i64,
) -> Result<Vec<ChangedRow>, sqlx::Error> {
    AttentionRepository::changed(&mut **tx, organization_id, project_ids, limit).await
}

async fn load_application_changed(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
) -> Result<Option<ChangedRow>, sqlx::Error> {
    AttentionRepository::application_changed(
        &mut **tx,
        organization_id,
        vec![project_id],
        application_id,
    )
    .await
}

async fn load_discoveries(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    project_ids: &[Uuid],
    application_id: Option<Uuid>,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    limit: i64,
) -> Result<Vec<DiscoveryRow>, sqlx::Error> {
    AttentionRepository::discoveries(
        &mut **tx,
        organization_id,
        project_ids,
        application_id,
        from,
        to,
        limit,
        crate::policy::POLICY_EVALUATOR_VERSION,
    )
    .await
}

async fn load_problems(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    project_ids: &[Uuid],
    now: DateTime<Utc>,
    delivery_enabled: bool,
    limit: i64,
) -> Result<(Vec<NotificationProblem>, i64), sqlx::Error> {
    let rows: Vec<ProblemRow> = AttentionRepository::notification_problems(
        &mut **tx,
        organization_id,
        project_ids,
        now,
        delivery_enabled,
        limit,
    )
    .await?;
    let total = rows.first().map_or(0, |row| row.total_problem_count);
    Ok((
        rows.into_iter()
            .filter_map(|r| {
                let snap = NotificationQueueSnapshot {
                    enabled_destination_count: r.enabled_destination_count,
                    pending_count: r.pending_count,
                    due_count: r.due_count,
                    retrying_count: r.retrying_count,
                    in_flight_count: r.in_flight_count,
                    expired_lease_count: r.expired_lease_count,
                    failed_count: r.failed_count,
                    oldest_due_age_seconds: r.oldest_due_age_seconds,
                };
                let state = derive_state(delivery_enabled, false, &snap);
                let missing = delivery_enabled && r.enabled_destination_count == 0;
                let (priority, reason_code) = if missing {
                    (Priority::Urgent, ReasonCode::EnabledDestinationMissing)
                } else {
                    match state {
                        NotificationHealthState::Failing => {
                            (Priority::Urgent, ReasonCode::NotificationHealthFailing)
                        }
                        NotificationHealthState::Backlogged => {
                            (Priority::High, ReasonCode::NotificationHealthBacklogged)
                        }
                        NotificationHealthState::Retrying => {
                            (Priority::High, ReasonCode::NotificationHealthRetrying)
                        }
                        _ => return None,
                    }
                };
                Some(NotificationProblem {
                    project: ProjectRef {
                        id: r.project_id,
                        name: r.project_name,
                        slug: r.project_slug,
                    },
                    state,
                    delivery_enabled,
                    enabled_destination_count: r.enabled_destination_count,
                    pending_count: r.pending_count,
                    due_count: r.due_count,
                    retrying_count: r.retrying_count,
                    in_flight_count: r.in_flight_count,
                    expired_lease_count: r.expired_lease_count,
                    failed_count: r.failed_count,
                    oldest_due_age_seconds: r.oldest_due_age_seconds,
                    observed_at: now,
                    priority,
                    reason_code,
                })
            })
            .collect(),
        total,
    ))
}

async fn load_new_discovery_scopes(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    project_ids: &[Uuid],
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    limit: i64,
) -> Result<Vec<NewDiscoveryScope>, sqlx::Error> {
    AttentionRepository::new_discovery_scopes(
        &mut **tx,
        organization_id,
        project_ids,
        from,
        to,
        limit,
    )
    .await
}

fn recommendation_stable_id(value: &Recommendation) -> Uuid {
    match value.resource {
        ResourceRef::Project { project_id } => project_id,
        ResourceRef::Application { application_id, .. }
        | ResourceRef::RuntimeGroup { application_id, .. }
        | ResourceRef::RuntimeDiff { application_id, .. }
        | ResourceRef::ResourceComparison { application_id, .. } => application_id,
    }
}

#[allow(clippy::too_many_lines)]
fn build_recommendations(
    problems: &[NotificationProblem],
    changed: &[ChangedRow],
    new_discoveries: &[NewDiscoveryScope],
    now: DateTime<Utc>,
    limit: usize,
) -> Vec<Recommendation> {
    let mut values = Vec::new();
    for p in problems {
        let missing = p.delivery_enabled && p.enabled_destination_count == 0;
        if p.failed_count > 0 || p.state == NotificationHealthState::Failing {
            values.push(Recommendation {
                id: format!("review_failed_deliveries:{}", p.project.id),
                kind: RecommendationKind::ReviewFailedDeliveries,
                priority: Priority::Urgent,
                reason_code: ReasonCode::NotificationHealthFailing,
                facts: AttentionFacts {
                    reason_count: p.failed_count.max(1),
                    new_count: None,
                    disappeared_count: None,
                    failed_count: Some(p.failed_count),
                    occurrence_count: None,
                    restart_loop: None,
                    resource_regression: None,
                },
                project: p.project.clone(),
                application: None,
                resource: ResourceRef::Project {
                    project_id: p.project.id,
                },
                created_from_snapshot_at: now,
            });
        }
        if missing {
            values.push(Recommendation {
                id: format!("configure_webhook_destination:{}", p.project.id),
                kind: RecommendationKind::ConfigureWebhookDestination,
                priority: Priority::Urgent,
                reason_code: ReasonCode::EnabledDestinationMissing,
                facts: AttentionFacts {
                    reason_count: 1,
                    new_count: None,
                    disappeared_count: None,
                    failed_count: None,
                    occurrence_count: None,
                    restart_loop: None,
                    resource_regression: None,
                },
                project: p.project.clone(),
                application: None,
                resource: ResourceRef::Project {
                    project_id: p.project.id,
                },
                created_from_snapshot_at: now,
            });
        }
        if p.state == NotificationHealthState::Backlogged || p.due_count > 0 || p.retrying_count > 0
        {
            values.push(Recommendation {
                id: format!("review_notification_backlog:{}", p.project.id),
                kind: RecommendationKind::ReviewNotificationBacklog,
                priority: Priority::High,
                reason_code: if p.retrying_count > 0 {
                    ReasonCode::NotificationHealthRetrying
                } else {
                    ReasonCode::NotificationHealthBacklogged
                },
                facts: AttentionFacts {
                    reason_count: p.due_count.max(p.retrying_count).max(p.expired_lease_count),
                    new_count: None,
                    disappeared_count: None,
                    failed_count: None,
                    occurrence_count: None,
                    restart_loop: None,
                    resource_regression: None,
                },
                project: p.project.clone(),
                application: None,
                resource: ResourceRef::Project {
                    project_id: p.project.id,
                },
                created_from_snapshot_at: now,
            });
        }
    }
    for r in changed {
        values.push(Recommendation {
            id: format!("review_release_changes:{}", r.application_id),
            kind: RecommendationKind::ReviewReleaseChanges,
            priority: Priority::High,
            reason_code: ReasonCode::ReleaseRuntimeChanged,
            facts: AttentionFacts {
                reason_count: r.new_count + r.disappeared_count,
                new_count: Some(r.new_count),
                disappeared_count: Some(r.disappeared_count),
                failed_count: None,
                occurrence_count: None,
                restart_loop: None,
                resource_regression: None,
            },
            project: ProjectRef {
                id: r.project_id,
                name: r.project_name.clone(),
                slug: r.project_slug.clone(),
            },
            application: Some(ApplicationRef {
                id: r.application_id,
                name: r.application_name.clone(),
                slug: r.application_slug.clone(),
            }),
            resource: ResourceRef::Application {
                project_id: r.project_id,
                application_id: r.application_id,
            },
            created_from_snapshot_at: now,
        });
    }
    for r in new_discoveries {
        values.push(Recommendation {
            id: format!("review_new_discoveries:{}", r.application_id),
            kind: RecommendationKind::ReviewNewDiscoveries,
            priority: Priority::Normal,
            reason_code: ReasonCode::DiscoveryFirstSeenInWindow,
            facts: AttentionFacts {
                reason_count: r.discovery_count,
                new_count: None,
                disappeared_count: None,
                failed_count: None,
                occurrence_count: Some(r.discovery_count),
                restart_loop: None,
                resource_regression: None,
            },
            project: ProjectRef {
                id: r.project_id,
                name: r.project_name.clone(),
                slug: r.project_slug.clone(),
            },
            application: Some(ApplicationRef {
                id: r.application_id,
                name: r.application_name.clone(),
                slug: r.application_slug.clone(),
            }),
            resource: ResourceRef::Application {
                project_id: r.project_id,
                application_id: r.application_id,
            },
            created_from_snapshot_at: now,
        });
    }
    values.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| b.facts.reason_count.cmp(&a.facts.reason_count))
            .then_with(|| a.id.cmp(&b.id))
            .then_with(|| recommendation_stable_id(a).cmp(&recommendation_stable_id(b)))
    });
    values.truncate(limit);
    values
}

fn discovery_item(r: DiscoveryRow) -> PriorityItem {
    let relevant = if r.is_new {
        r.first_seen_at
    } else {
        r.last_seen_at
    };
    let restart_loop = (r.event_kind == "container.restart_loop").then(|| RestartLoopFacts {
        projection_version: r.semantic_summary["projection_version"]
            .as_i64()
            .unwrap_or(1),
        threshold: r.semantic_summary["threshold"].as_i64().unwrap_or(3),
        observed_restart_count: r.semantic_summary["observed_restart_count"]
            .as_i64()
            .unwrap_or(r.occurrence_count),
        window_started_at: serde_json::from_value(r.semantic_summary["window_started_at"].clone())
            .unwrap_or(r.first_seen_at),
        window_ended_at: serde_json::from_value(r.semantic_summary["window_ended_at"].clone())
            .unwrap_or(r.last_seen_at),
        container_name: r.semantic_summary["container_name"]
            .as_str()
            .unwrap_or("unknown")
            .to_owned(),
    });
    let is_restart_loop = restart_loop.is_some();
    PriorityItem {
        id: format!(
            "{}:{}",
            if r.is_new {
                "new_discovery"
            } else {
                "open_discovery"
            },
            r.group_id
        ),
        kind: if is_restart_loop {
            ItemKind::ContainerRestartLoop
        } else if r.is_new {
            ItemKind::NewDiscovery
        } else {
            ItemKind::OpenDiscovery
        },
        priority: if r.policy_verdict.as_deref() == Some("policy_conflict") {
            Priority::Urgent
        } else if is_restart_loop || r.policy_verdict.as_deref() == Some("requires_review") {
            Priority::High
        } else {
            Priority::Normal
        },
        reason_code: if r.policy_evaluation_state == "evaluation_pending" {
            ReasonCode::PolicyEvaluationPending
        } else if r.policy_verdict.as_deref() == Some("policy_conflict") {
            ReasonCode::PolicyConflict
        } else if r.policy_verdict.as_deref() == Some("requires_review") {
            ReasonCode::PolicyReviewRequired
        } else if r.policy_verdict.as_deref() == Some("unclassified") {
            ReasonCode::PolicyUnclassified
        } else if is_restart_loop {
            ReasonCode::ContainerRestartLoopObserved
        } else if r.is_new {
            ReasonCode::DiscoveryFirstSeenInWindow
        } else {
            ReasonCode::DiscoveryOpen
        },
        facts: AttentionFacts {
            reason_count: r.occurrence_count,
            new_count: None,
            disappeared_count: None,
            failed_count: None,
            occurrence_count: Some(r.occurrence_count),
            restart_loop,
            resource_regression: None,
        },
        occurred_at: relevant,
        project: ProjectRef {
            id: r.project_id,
            name: r.project_name,
            slug: r.project_slug,
        },
        application: Some(ApplicationRef {
            id: r.application_id,
            name: r.application_name,
            slug: r.application_slug,
        }),
        resource: ResourceRef::RuntimeGroup {
            project_id: r.project_id,
            application_id: r.application_id,
            runtime_group_id: r.group_id,
            event_kind: r.event_kind,
            semantic_summary: r.semantic_summary,
            user_labels: r.user_labels,
            namespace: r.namespace,
            workload_kind: r.workload_kind,
            workload_name: r.workload_name,
            policy_verdict: r.policy_verdict,
            policy_evaluation_state: r.policy_evaluation_state,
        },
        stable_id: r.group_id,
    }
}
fn changed_item(r: &ChangedRow) -> PriorityItem {
    PriorityItem {
        id: format!("release_runtime_changed:{}:{}", r.target_id, r.baseline_id),
        kind: ItemKind::ReleaseRuntimeChanged,
        priority: Priority::High,
        reason_code: ReasonCode::ReleaseRuntimeChanged,
        facts: AttentionFacts {
            reason_count: r.new_count + r.disappeared_count,
            new_count: Some(r.new_count),
            disappeared_count: Some(r.disappeared_count),
            failed_count: None,
            occurrence_count: None,
            restart_loop: None,
            resource_regression: None,
        },
        occurred_at: r.target_deployed_at,
        project: ProjectRef {
            id: r.project_id,
            name: r.project_name.clone(),
            slug: r.project_slug.clone(),
        },
        application: Some(ApplicationRef {
            id: r.application_id,
            name: r.application_name.clone(),
            slug: r.application_slug.clone(),
        }),
        resource: ResourceRef::RuntimeDiff {
            project_id: r.project_id,
            application_id: r.application_id,
            target_release_id: r.target_id,
            target_release_display_name: r.target_display_name.clone(),
            baseline_release_id: r.baseline_id,
            baseline_release_display_name: r.baseline_display_name.clone(),
        },
        stable_id: r.application_id,
    }
}
fn changed_response(r: ChangedRow, largest_changes: Vec<LargestChange>) -> ChangedApplication {
    ChangedApplication {
        project: ProjectRef {
            id: r.project_id,
            name: r.project_name,
            slug: r.project_slug,
        },
        application: ApplicationRef {
            id: r.application_id,
            name: r.application_name,
            slug: r.application_slug,
        },
        comparison: ReleaseComparison {
            target_release: ReleaseRef {
                id: r.target_id,
                version: r.target_version,
                display_name: r.target_display_name,
                deployed_at: r.target_deployed_at,
            },
            baseline_release: Some(ReleaseRef {
                id: r.baseline_id,
                version: r.baseline_version,
                display_name: r.baseline_display_name,
                deployed_at: r.baseline_deployed_at,
            }),
            new_count: r.new_count,
            disappeared_count: r.disappeared_count,
            unchanged_count: r.unchanged_count,
            total_item_count: r.total_item_count,
            absolute_occurrence_delta_sum: r.absolute_occurrence_delta_sum,
            max_absolute_occurrence_delta: r.max_absolute_occurrence_delta,
            largest_changes,
        },
        changed_at: r.target_deployed_at,
    }
}
fn sort_items(items: &mut [PriorityItem]) {
    items.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| b.facts.reason_count.cmp(&a.facts.reason_count))
            .then_with(|| b.occurred_at.cmp(&a.occurred_at))
            .then_with(|| a.stable_id.cmp(&b.stable_id))
    });
}

/// Builds attention summaries.
#[derive(Clone, Debug)]
pub struct AttentionService {
    pool: PgPool,
    delivery_enabled: bool,
}

impl AttentionService {
    /// `delivery_enabled` says whether notification delivery runs, which
    /// decides how notification problems read.
    pub fn new(pool: PgPool, delivery_enabled: bool) -> Self {
        Self {
            pool,
            delivery_enabled,
        }
    }

    /// What needs attention across the projects the principal can see in the
    /// active organization: new discoveries, changed applications, notification
    /// problems, resource regressions, and what to do about them. Everything is
    /// read from one consistent snapshot.
    #[allow(clippy::too_many_lines)]
    pub async fn organization_summary(
        &self,
        principal: IdentityPrincipal,
        q: OrganizationQuery,
    ) -> Result<OrganizationSummary, AttentionServiceError> {
        let access = organization_access(self, principal).await?;
        let limit = bounded(q.limit, 20, 50, "limit")?;
        let changed_limit = bounded(
            q.changed_application_limit,
            5,
            10,
            "changed_application_limit",
        )?;
        let rec_limit = bounded(q.recommendation_limit, 5, 10, "recommendation_limit")?;
        let (mut tx, now) = snapshot(&self.pool).await?;
        let from = now - q.window.duration();
        let changed = load_changed(
            &mut tx,
            access.organization_id,
            &access.project_ids,
            limit.max(changed_limit),
        )
        .await?;
        let selected_changed: Vec<_> = changed
            .iter()
            .take(usize::try_from(changed_limit).unwrap_or_default())
            .cloned()
            .collect();
        let mut largest_by_application = load_largest(&mut tx, &selected_changed, 5).await?;
        let discoveries = load_discoveries(
            &mut tx,
            access.organization_id,
            &access.project_ids,
            None,
            from,
            now,
            limit,
        )
        .await?;
        let (problems, total_problem_count) = load_problems(
            &mut tx,
            access.organization_id,
            &access.project_ids,
            now,
            self.delivery_enabled,
            limit,
        )
        .await?;
        let new_discovery_scopes = load_new_discovery_scopes(
            &mut tx,
            access.organization_id,
            &access.project_ids,
            from,
            now,
            rec_limit,
        )
        .await?;
        let resource_findings = load_resource_findings(
            &mut tx,
            access.organization_id,
            &access.project_ids,
            None,
            from,
            limit,
        )
        .await?;
        let mut totals: OrganizationTotals = AttentionRepository::organization_totals(
            &mut *tx,
            access.organization_id,
            &access.project_ids,
            from,
            now,
        )
        .await?;
        totals.projects_with_notification_problems = total_problem_count;
        let mut items: Vec<_> = changed
            .iter()
            .map(changed_item)
            .chain(discoveries.into_iter().map(discovery_item))
            .chain(resource_findings.iter().map(resource_item))
            .collect();
        for p in &problems {
            let count = if p.failed_count > 0 {
                p.failed_count
            } else {
                p.due_count
                    .max(p.retrying_count)
                    .max(p.expired_lease_count)
                    .max(1)
            };
            items.push(PriorityItem {
                id: format!("notification:{:?}:{}", p.reason_code, p.project.id),
                kind: match p.reason_code {
                    ReasonCode::EnabledDestinationMissing => {
                        ItemKind::NotificationDestinationMissing
                    }
                    ReasonCode::NotificationHealthBacklogged
                    | ReasonCode::NotificationHealthRetrying => {
                        ItemKind::NotificationDeliveryBacklogged
                    }
                    _ => ItemKind::NotificationDeliveryFailing,
                },
                priority: p.priority,
                reason_code: p.reason_code.clone(),
                facts: AttentionFacts {
                    reason_count: count,
                    new_count: None,
                    disappeared_count: None,
                    failed_count: Some(p.failed_count),
                    occurrence_count: None,
                    restart_loop: None,
                    resource_regression: None,
                },
                occurred_at: now,
                project: p.project.clone(),
                application: None,
                resource: ResourceRef::Project {
                    project_id: p.project.id,
                },
                stable_id: p.project.id,
            });
        }
        sort_items(&mut items);
        items.truncate(usize::try_from(limit).unwrap_or_default());
        let mut recommendations = build_recommendations(
            &problems,
            &changed,
            &new_discovery_scopes,
            now,
            usize::try_from(rec_limit).unwrap_or_default(),
        );
        recommendations.extend(resource_recommendations(&resource_findings, now));
        recommendations.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));
        recommendations.truncate(usize::try_from(rec_limit).unwrap_or_default());
        let changed_applications = selected_changed
            .into_iter()
            .map(|r| {
                let largest = largest_by_application
                    .remove(&r.application_id)
                    .unwrap_or_default();
                changed_response(r, largest)
            })
            .collect();
        tx.commit().await?;
        Ok(OrganizationSummary {
            generated_at: now,
            window: AttentionWindow {
                kind: q.window,
                from,
                to: now,
            },
            totals,
            priority_items: items,
            changed_applications,
            notification_problems: problems,
            recommendations,
        })
    }

    /// What needs attention in one application, including how its latest
    /// release compares with the one before.
    #[allow(clippy::too_many_lines)]
    pub async fn application_summary(
        &self,
        principal: IdentityPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        q: ApplicationQuery,
    ) -> Result<ApplicationSummary, AttentionServiceError> {
        let organization_id = project_organization(self, principal, project_id).await?;
        let limit = bounded(q.limit, 20, 50, "limit")?;
        let largest = bounded(q.largest_change_limit, 5, 10, "largest_change_limit")?;
        let rec_limit = bounded(q.recommendation_limit, 5, 10, "recommendation_limit")?;
        let (mut tx, now) = snapshot(&self.pool).await?;
        let from = now - q.window.duration();
        let identity: Option<(Uuid, String, String, String, String)> =
            AttentionRepository::application_identity(
                &mut *tx,
                organization_id,
                project_id,
                application_id,
            )
            .await?;
        let (_, pn, ps, an, aslug) = identity.ok_or(AttentionServiceError::NotFound)?;
        let project = ProjectRef {
            id: project_id,
            name: pn,
            slug: ps,
        };
        let application = ApplicationRef {
            id: application_id,
            name: an,
            slug: aslug,
        };
        let discoveries = load_discoveries(
            &mut tx,
            organization_id,
            &[project_id],
            Some(application_id),
            from,
            now,
            limit,
        )
        .await?;
        let resource_findings = load_resource_findings(
            &mut tx,
            organization_id,
            &[project_id],
            Some(application_id),
            from,
            limit,
        )
        .await?;
        let mut items: Vec<_> = discoveries.into_iter().map(discovery_item).collect();
        items.extend(resource_findings.iter().map(resource_item));
        let changed =
            load_application_changed(&mut tx, organization_id, project_id, application_id).await?;
        if let Some(ref r) = changed
            && r.new_count + r.disappeared_count > 0
        {
            items.push(changed_item(r));
        }
        sort_items(&mut items);
        items.truncate(usize::try_from(limit).unwrap_or_default());
        let counts: (i64, i64, i64) = AttentionRepository::application_discovery_counts(
            &mut *tx,
            organization_id,
            application_id,
            from,
            now,
        )
        .await?;
        let policy: Value = AttentionRepository::application_policy_summary(
            &mut *tx,
            organization_id,
            application_id,
            crate::policy::POLICY_EVALUATOR_VERSION,
        )
        .await?;
        let largest_changes = if let Some(ref row) = changed {
            load_largest(&mut tx, std::slice::from_ref(row), largest)
                .await?
                .remove(&application_id)
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let comparison = changed
            .map(|r| changed_response(r, largest_changes))
            .map(|x| x.comparison);
        let (
            new_runtime_items,
            disappeared_runtime_items,
            unchanged_runtime_items,
            total_runtime_items,
        ) = comparison.as_ref().map_or((0, 0, 0, 0), |c| {
            (
                c.new_count,
                c.disappeared_count,
                c.unchanged_count,
                c.total_item_count,
            )
        });
        let mut recommendations = Vec::new();
        if let Some(c) = &comparison
            && c.new_count + c.disappeared_count > 0
        {
            recommendations.push(Recommendation {
                id: format!("recommendation:release:{application_id}"),
                kind: RecommendationKind::ReviewReleaseChanges,
                priority: Priority::High,
                reason_code: ReasonCode::ReleaseRuntimeChanged,
                facts: AttentionFacts {
                    reason_count: c.new_count + c.disappeared_count,
                    new_count: Some(c.new_count),
                    disappeared_count: Some(c.disappeared_count),
                    failed_count: None,
                    occurrence_count: None,
                    restart_loop: None,
                    resource_regression: None,
                },
                project: project.clone(),
                application: Some(application.clone()),
                resource: ResourceRef::Application {
                    project_id,
                    application_id,
                },
                created_from_snapshot_at: now,
            });
        }
        if counts.0 > 0 {
            recommendations.push(Recommendation {
                id: format!("recommendation:new:{application_id}"),
                kind: RecommendationKind::ReviewNewDiscoveries,
                priority: Priority::Normal,
                reason_code: ReasonCode::DiscoveryFirstSeenInWindow,
                facts: AttentionFacts {
                    reason_count: counts.0,
                    new_count: None,
                    disappeared_count: None,
                    failed_count: None,
                    occurrence_count: Some(counts.0),
                    restart_loop: None,
                    resource_regression: None,
                },
                project: project.clone(),
                application: Some(application.clone()),
                resource: ResourceRef::Application {
                    project_id,
                    application_id,
                },
                created_from_snapshot_at: now,
            });
        }
        recommendations.extend(resource_recommendations(&resource_findings, now));
        recommendations.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));
        recommendations.truncate(usize::try_from(rec_limit).unwrap_or_default());
        let resource_regressions: i64 = ResourceRepository::open_finding_count(
            &mut *tx,
            organization_id,
            project_id,
            application_id,
        )
        .await?;
        tx.commit().await?;
        Ok(ApplicationSummary {
            generated_at: now,
            window: AttentionWindow {
                kind: q.window,
                from,
                to: now,
            },
            project,
            application,
            totals: ApplicationTotals {
                new_discoveries: counts.0,
                open_discoveries: counts.1,
                acknowledged_discoveries: counts.2,
                new_runtime_items,
                disappeared_runtime_items,
                unchanged_runtime_items,
                total_runtime_items,
                resource_regressions,
                policy,
            },
            release_comparison: comparison,
            priority_items: items,
            recommendations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_and_limits() {
        let now = Utc::now();
        assert_eq!(now - WindowKind::Day.duration(), now - Duration::hours(24));
        assert_eq!(now - WindowKind::Week.duration(), now - Duration::days(7));
        for max in [10, 50] {
            assert!(bounded(Some(0), 5, max, "limit").is_err());
            assert!(bounded(Some(max + 1), 5, max, "limit").is_err());
            assert_eq!(bounded(Some(1), 5, max, "limit").unwrap(), 1);
            assert_eq!(bounded(Some(max), 5, max, "limit").unwrap(), max);
        }
        assert_eq!(bounded(None, 20, 50, "limit").unwrap(), 20);
        assert_eq!(serde_json::to_string(&WindowKind::Day).unwrap(), "\"24h\"");
        assert!(serde_json::from_str::<WindowKind>("\"30d\"").is_err());
        assert_eq!(ORGANIZATION_ATTENTION_QUERY_BUDGET, 10);
        assert_eq!(APPLICATION_ATTENTION_QUERY_BUDGET, 10);
    }
    #[test]
    fn tuple_order_is_stable() {
        let id1 = Uuid::from_u128(1);
        let id2 = Uuid::from_u128(2);
        let p = ProjectRef {
            id: id1,
            name: "p".into(),
            slug: "p".into(),
        };
        let occurred_at = Utc::now();
        let make = |id: Uuid, count: i64, priority: Priority, at: DateTime<Utc>| PriorityItem {
            id: id.to_string(),
            kind: ItemKind::OpenDiscovery,
            priority,
            reason_code: ReasonCode::DiscoveryOpen,
            facts: AttentionFacts {
                reason_count: count,
                new_count: None,
                disappeared_count: None,
                failed_count: None,
                occurrence_count: Some(count),
                restart_loop: None,
                resource_regression: None,
            },
            occurred_at: at,
            project: p.clone(),
            application: None,
            resource: ResourceRef::Project { project_id: id },
            stable_id: id,
        };
        let mut v = vec![
            make(id2, 100, Priority::Normal, occurred_at),
            make(id2, 2, Priority::High, occurred_at),
            make(id1, 2, Priority::High, occurred_at),
            make(id1, 1, Priority::Urgent, occurred_at - Duration::days(1)),
        ];
        sort_items(&mut v);
        assert_eq!(v[0].stable_id, id1);
        assert_eq!(v[1].stable_id, id1);
        assert_eq!(v[2].stable_id, id2);
        assert_eq!(v[3].priority, Priority::Normal);
    }

    #[test]
    fn serialized_item_is_typed_and_secret_free() {
        let id = Uuid::from_u128(1);
        let item = PriorityItem {
            id: format!("open_discovery:{id}"),
            kind: ItemKind::OpenDiscovery,
            priority: Priority::Normal,
            reason_code: ReasonCode::DiscoveryOpen,
            facts: AttentionFacts {
                reason_count: 4,
                new_count: None,
                disappeared_count: None,
                failed_count: None,
                occurrence_count: Some(4),
                restart_loop: None,
                resource_regression: None,
            },
            occurred_at: Utc::now(),
            project: ProjectRef {
                id,
                name: "project".into(),
                slug: "project".into(),
            },
            application: None,
            resource: ResourceRef::RuntimeGroup {
                project_id: id,
                application_id: id,
                runtime_group_id: id,
                event_kind: "process.exec".into(),
                semantic_summary: serde_json::json!({"executable": "/app/worker"}),
                user_labels: serde_json::json!([]),
                namespace: "production".into(),
                workload_kind: "Deployment".into(),
                workload_name: "worker".into(),
                policy_verdict: Some("unclassified".into()),
                policy_evaluation_state: "current".into(),
            },
            stable_id: id,
        };
        let value = serde_json::to_value(item).unwrap();
        assert_eq!(value["resource"]["type"], "runtime_group");
        assert_eq!(value["resource"]["event_kind"], "process.exec");
        assert_eq!(
            value["resource"]["semantic_summary"]["executable"],
            "/app/worker"
        );
        assert_eq!(value["resource"]["namespace"], "production");
        assert_eq!(value["resource"]["workload_kind"], "Deployment");
        assert_eq!(value["resource"]["workload_name"], "worker");
        let text = value.to_string();
        for forbidden in [
            "webhook",
            "secret",
            "credential",
            "response_excerpt",
            "frontend_url",
        ] {
            assert!(!text.contains(forbidden));
        }
    }

    #[test]
    fn restart_loop_discovery_has_dedicated_attention_variant_and_facts() {
        let now = Utc::now();
        let item = discovery_item(DiscoveryRow {
            group_id: Uuid::from_u128(1),
            project_id: Uuid::from_u128(2),
            project_name: "project".into(),
            project_slug: "project".into(),
            application_id: Uuid::from_u128(3),
            application_name: "app".into(),
            application_slug: "app".into(),
            first_seen_at: now - Duration::minutes(5),
            last_seen_at: now,
            occurrence_count: 1,
            event_kind: "container.restart_loop".into(),
            semantic_summary: serde_json::json!({
                "projection_version": 1,
                "threshold": 3,
                "observed_restart_count": 4,
                "window_started_at": now - Duration::minutes(10),
                "window_ended_at": now,
                "container_name": "worker"
            }),
            user_labels: serde_json::json!([]),
            namespace: "production".into(),
            workload_kind: "Deployment".into(),
            workload_name: "worker".into(),
            is_new: true,
            policy_verdict: Some("requires_review".into()),
            policy_evaluation_state: "current".into(),
        });
        let value = serde_json::to_value(item).unwrap();
        assert_eq!(value["kind"], "container_restart_loop");
        assert_eq!(value["reason_code"], "policy_review_required");
        assert_eq!(value["priority"], "high");
        assert_eq!(value["facts"]["restart_loop"]["threshold"], 3);
        assert_eq!(value["facts"]["restart_loop"]["observed_restart_count"], 4);
    }

    #[test]
    fn recommendation_rules_are_complete_deduplicated_and_bounded() {
        let id = Uuid::from_u128(7);
        let now = Utc::now();
        let project = ProjectRef {
            id,
            name: "p".into(),
            slug: "p".into(),
        };
        let problem = NotificationProblem {
            project: project.clone(),
            state: NotificationHealthState::Failing,
            delivery_enabled: true,
            enabled_destination_count: 0,
            pending_count: 2,
            due_count: 2,
            retrying_count: 1,
            in_flight_count: 0,
            expired_lease_count: 0,
            failed_count: 3,
            oldest_due_age_seconds: Some(10),
            observed_at: now,
            priority: Priority::Urgent,
            reason_code: ReasonCode::EnabledDestinationMissing,
        };
        let changed = ChangedRow {
            project_id: id,
            project_name: "p".into(),
            project_slug: "p".into(),
            application_id: id,
            application_name: "a".into(),
            application_slug: "a".into(),
            target_id: Uuid::from_u128(8),
            target_version: "2".into(),
            target_display_name: "2".into(),
            target_deployed_at: now,
            baseline_id: Uuid::from_u128(9),
            baseline_version: "1".into(),
            baseline_display_name: "1".into(),
            baseline_deployed_at: now - Duration::hours(1),
            new_count: 2,
            disappeared_count: 1,
            unchanged_count: 0,
            total_item_count: 3,
            absolute_occurrence_delta_sum: 3,
            max_absolute_occurrence_delta: 2,
        };
        let discovery = NewDiscoveryScope {
            project_id: id,
            project_name: "p".into(),
            project_slug: "p".into(),
            application_id: id,
            application_name: "a".into(),
            application_slug: "a".into(),
            discovery_count: 4,
        };
        let values = build_recommendations(&[problem], &[changed], &[discovery], now, 10);
        assert_eq!(values.len(), 5);
        let serialized = serde_json::to_value(&values).unwrap().to_string();
        for kind in [
            "review_failed_deliveries",
            "configure_webhook_destination",
            "review_notification_backlog",
            "review_release_changes",
            "review_new_discoveries",
        ] {
            assert!(serialized.contains(kind));
        }
        assert_eq!(build_recommendations(&[], &[], &[], now, 10).len(), 0);
        assert_eq!(values[0].priority, Priority::Urgent);
        assert_eq!(
            build_recommendations(
                &[],
                &[ChangedRow {
                    project_id: id,
                    project_name: "p".into(),
                    project_slug: "p".into(),
                    application_id: id,
                    application_name: "a".into(),
                    application_slug: "a".into(),
                    target_id: Uuid::from_u128(8),
                    target_version: "2".into(),
                    target_display_name: "2".into(),
                    target_deployed_at: now,
                    baseline_id: Uuid::from_u128(9),
                    baseline_version: "1".into(),
                    baseline_display_name: "1".into(),
                    baseline_deployed_at: now,
                    new_count: 1,
                    disappeared_count: 0,
                    unchanged_count: 0,
                    total_item_count: 1,
                    absolute_occurrence_delta_sum: 1,
                    max_absolute_occurrence_delta: 1
                }],
                &[],
                now,
                0
            )
            .len(),
            0
        );
    }

    /// The summaries against a real database, through the service.
    mod use_cases {
        use super::super::*;
        use crate::repository::test_support::{Tenant, exec, ingest, tenant, user};

        fn principal(tenant: &Tenant, user_id: Uuid, role: OrganizationRole) -> IdentityPrincipal {
            IdentityPrincipal {
                user_id,
                session_id: Uuid::new_v4(),
                active_organization_id: Some(tenant.organization_id),
                organization_role: Some(role),
                is_super_admin: false,
                privileged_until: None,
            }
        }

        fn organization(limit: Option<i64>) -> OrganizationQuery {
            OrganizationQuery {
                window: WindowKind::Day,
                limit,
                changed_application_limit: None,
                recommendation_limit: None,
            }
        }

        fn application(limit: Option<i64>) -> ApplicationQuery {
            ApplicationQuery {
                window: WindowKind::Week,
                limit,
                largest_change_limit: None,
                recommendation_limit: None,
            }
        }

        async fn seed(pool: &PgPool, tenant: &Tenant) {
            ingest(
                pool,
                tenant,
                &[
                    exec(tenant, "/bin/a", Utc::now() - Duration::minutes(5)),
                    exec(tenant, "/bin/b", Utc::now() - Duration::minutes(4)),
                ],
            )
            .await;
        }

        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn the_organization_summary_covers_visible_projects(pool: PgPool) {
            let tenant = tenant(&pool, "attention-service-organization").await;
            seed(&pool, &tenant).await;
            let service = AttentionService::new(pool.clone(), false);

            let detached = IdentityPrincipal {
                active_organization_id: None,
                ..principal(&tenant, Uuid::new_v4(), OrganizationRole::Owner)
            };
            assert!(matches!(
                service
                    .organization_summary(detached, organization(Some(0)))
                    .await,
                Err(AttentionServiceError::NotFound)
            ));
            let owner = principal(&tenant, Uuid::new_v4(), OrganizationRole::Owner);
            assert!(matches!(
                service.organization_summary(owner, organization(Some(51))).await,
                Err(AttentionServiceError::Invalid(message)) if message == "limit must be between 1 and 50"
            ));
            let summary = service
                .organization_summary(owner, organization(None))
                .await
                .unwrap();
            assert_eq!(summary.totals.new_discoveries, 2);
            assert!(!summary.priority_items.is_empty());

            // A member sees only the projects they were given.
            let member = principal(&tenant, user(&pool).await, OrganizationRole::Member);
            let summary = service
                .organization_summary(member, organization(None))
                .await
                .unwrap();
            assert_eq!(summary.totals.new_discoveries, 0);
            assert!(summary.priority_items.is_empty());
        }

        #[sqlx::test(migrator = "crate::database::MIGRATOR")]
        #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
        async fn the_application_summary_checks_access_then_limits(pool: PgPool) {
            let other = tenant(&pool, "attention-service-other").await;
            let tenant = tenant(&pool, "attention-service-application").await;
            seed(&pool, &tenant).await;
            let service = AttentionService::new(pool.clone(), false);
            let owner = principal(&tenant, Uuid::new_v4(), OrganizationRole::Owner);
            let (project, application_id) = (tenant.project_id, tenant.application_id);

            assert!(matches!(
                service
                    .application_summary(
                        principal(&other, Uuid::new_v4(), OrganizationRole::Owner),
                        project,
                        application_id,
                        application(Some(0)),
                    )
                    .await,
                Err(AttentionServiceError::NotFound)
            ));
            // Limits are checked before the application is looked up.
            assert!(matches!(
                service
                    .application_summary(owner, project, Uuid::new_v4(), application(Some(0)))
                    .await,
                Err(AttentionServiceError::Invalid(_))
            ));
            assert!(matches!(
                service
                    .application_summary(owner, project, Uuid::new_v4(), application(None))
                    .await,
                Err(AttentionServiceError::NotFound)
            ));
            let summary = service
                .application_summary(owner, project, application_id, application(None))
                .await
                .unwrap();
            assert_eq!(summary.application.name, "Application");
            assert_eq!(summary.project.slug, "project");
            assert_eq!(summary.totals.new_discoveries, 2);
        }
    }
}
