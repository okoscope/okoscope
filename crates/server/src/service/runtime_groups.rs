//! Runtime groups: the deduplicated runtime behaviours of an application
//! with their occurrences, triage status and retained snapshots.
//!
//! The query types below are also the request's query strings.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{FromRow, PgPool};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

use crate::access_control::resolve_project_access;
use crate::auth::IdentityPrincipal;
use crate::repository::event_groups::EventGroupRepository;
use crate::repository::events::EventRepository;
use crate::repository::{ApplicationRepository, ProjectRepository};

/// Why a runtime group use case failed.
#[derive(Debug, Error)]
pub enum RuntimeGroupServiceError {
    /// The request is malformed; the message says how.
    #[error("{0}")]
    Invalid(String),
    /// The project, application or group does not exist, or the principal
    /// may not see it.
    #[error("runtime group not found")]
    NotFound,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Clone, Debug, Deserialize)]
pub struct ListQuery {
    project_id: Uuid,
    application_id: Uuid,
    event_kind: Option<String>,
    status: Option<String>,
    namespace: Option<String>,
    workload_kind: Option<String>,
    workload_name: Option<String>,
    since: Option<DateTime<Utc>>,
    first_seen_from: Option<DateTime<Utc>>,
    first_seen_to: Option<DateTime<Utc>>,
    last_seen_to: Option<DateTime<Utc>>,
    release_id: Option<Uuid>,
    verdict: Option<String>,
    suppressed: Option<bool>,
    evaluation_pending: Option<bool>,
    cursor: Option<Uuid>,
    limit: Option<i64>,
}

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct GroupSummary {
    id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
    cluster_id: Uuid,
    namespace: String,
    workload_kind: String,
    workload_name: String,
    fingerprint_version: i16,
    event_kind: String,
    semantic_summary: Value,
    #[sqlx(skip)]
    user_labels: Vec<Value>,
    status: String,
    first_seen_at: DateTime<Utc>,
    first_seen_event_id: Option<Uuid>,
    last_seen_at: DateTime<Utc>,
    occurrence_count: i64,
    representative_event_id: Option<Uuid>,
    status_changed_at: Option<DateTime<Utc>>,
    status_changed_by: Option<Uuid>,
    #[sqlx(skip)]
    policy_evaluation: Value,
    #[sqlx(skip)]
    active_suppression: Option<Value>,
    #[sqlx(skip)]
    actionable: bool,
    #[sqlx(skip)]
    coverage: crate::runtime_retention::history::Coverage,
}

#[derive(FromRow)]
struct GroupUserLabels {
    group_id: Uuid,
    user_labels: Value,
}

async fn attach_group_user_labels(
    pool: &PgPool,
    organization_id: Uuid,
    groups: &mut [GroupSummary],
) -> Result<(), sqlx::Error> {
    let ids: Vec<_> = groups.iter().map(|group| group.id).collect();
    let rows: Vec<GroupUserLabels> =
        EventGroupRepository::user_labels(pool, organization_id, ids).await?;
    let labels: HashMap<_, _> = rows
        .into_iter()
        .map(|row| (row.group_id, row.user_labels))
        .collect();
    for group in groups {
        group.user_labels = labels
            .get(&group.id)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        group.user_labels.truncate(20);
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct GroupList {
    items: Vec<GroupSummary>,
    next_cursor: Option<Uuid>,
}

#[derive(Debug, FromRow, Serialize)]
struct EventOccurrence {
    id: Uuid,
    event_id: Uuid,
    observed_at: DateTime<Utc>,
    received_at: DateTime<Utc>,
    node_name: String,
    namespace: String,
    pod_name: String,
    container_name: String,
    process_command: String,
    event_kind: String,
    payload: Value,
    correlation: Value,
    #[sqlx(skip)]
    related_evidence: Vec<RelatedEvidence>,
    release_id: Option<Uuid>,
    release_version: Option<String>,
    release_display_name: String,
}

#[derive(Clone, Debug, FromRow, Serialize)]
struct RelatedEvidence {
    id: Uuid,
    event_id: Uuid,
    observed_at: DateTime<Utc>,
    received_at: DateTime<Utc>,
    event_kind: String,
    source: String,
    payload: Value,
}

#[derive(Debug, Serialize)]
pub struct OccurrencePage {
    items: Vec<EventOccurrence>,
    next_cursor: Option<Uuid>,
    ordering: &'static str,
}

#[derive(Debug, FromRow, Serialize)]
struct NotificationSummary {
    state: String,
    delivery_count: i64,
    succeeded_count: i64,
    failed_count: i64,
}

#[derive(Debug, Serialize)]
pub struct GroupDetail {
    #[serde(flatten)]
    group: GroupSummary,
    representative_event: Option<EventOccurrence>,
    notification: NotificationSummary,
}

async fn project_organization(
    state: &RuntimeGroupService,
    principal: IdentityPrincipal,
    project_id: Uuid,
) -> Result<Uuid, RuntimeGroupServiceError> {
    let organization_id: Uuid = ProjectRepository::organization_of(&state.pool, project_id)
        .await?
        .ok_or(RuntimeGroupServiceError::NotFound)?;
    resolve_project_access(&state.pool, principal, organization_id, project_id)
        .await?
        .ok_or(RuntimeGroupServiceError::NotFound)?;
    Ok(organization_id)
}

async fn group_scope(
    state: &RuntimeGroupService,
    principal: IdentityPrincipal,
    group_id: Uuid,
) -> Result<(Uuid, Uuid), RuntimeGroupServiceError> {
    let scope = crate::repository::EventGroupRepository::tenant_of(&state.pool, group_id)
        .await?
        .ok_or(RuntimeGroupServiceError::NotFound)?;
    resolve_project_access(&state.pool, principal, scope.0, scope.1)
        .await?
        .ok_or(RuntimeGroupServiceError::NotFound)?;
    Ok(scope)
}

async fn ensure_application(
    state: &RuntimeGroupService,
    organization_id: Uuid,
    project_id: Uuid,
    application_id: Uuid,
) -> Result<(), RuntimeGroupServiceError> {
    let exists =
        ApplicationRepository::exists(&state.pool, organization_id, project_id, application_id)
            .await?;
    exists
        .then_some(())
        .ok_or(RuntimeGroupServiceError::NotFound)
}

#[derive(FromRow)]
struct GroupPolicyRow {
    group_id: Uuid,
    policy_evaluation: Value,
    active_suppression: Option<Value>,
    actionable: bool,
}

async fn attach_group_policy(
    pool: &PgPool,
    organization_id: Uuid,
    groups: &mut [GroupSummary],
) -> Result<(), sqlx::Error> {
    if groups.is_empty() {
        return Ok(());
    }
    let ids = groups.iter().map(|group| group.id).collect::<Vec<_>>();
    let rows = EventGroupRepository::policy_states::<_, GroupPolicyRow>(
        pool,
        organization_id,
        &ids,
        crate::policy::POLICY_EVALUATOR_VERSION,
    )
    .await?;
    let by_id = rows
        .into_iter()
        .map(|row| (row.group_id, row))
        .collect::<std::collections::HashMap<_, _>>();
    for group in groups {
        if let Some(row) = by_id.get(&group.id) {
            group.policy_evaluation = row.policy_evaluation.clone();
            group.active_suppression = row.active_suppression.clone();
            group.actionable = row.actionable;
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct OccurrenceQuery {
    cursor: Option<Uuid>,
    limit: Option<i64>,
}

async fn notification_summary(
    pool: &PgPool,
    organization_id: Uuid,
    group_id: Uuid,
) -> Result<NotificationSummary, sqlx::Error> {
    let summary = EventGroupRepository::notification_summary::<_, NotificationSummary>(
        pool,
        organization_id,
        group_id,
    )
    .await?;
    Ok(summary.unwrap_or_else(|| NotificationSummary {
        state: "not_configured".into(),
        delivery_count: 0,
        succeeded_count: 0,
        failed_count: 0,
    }))
}

async fn event_by_id(
    pool: &PgPool,
    organization_id: Uuid,
    event_id: Uuid,
) -> Result<Option<EventOccurrence>, sqlx::Error> {
    EventRepository::occurrence::<_, EventOccurrence>(pool, organization_id, event_id).await
}

const RELATED_EVIDENCE_LIMIT: i64 = 20;

async fn load_related_evidence(
    pool: &PgPool,
    organization_id: Uuid,
    group_id: Uuid,
    event_id: Uuid,
    event_kind: &str,
) -> Result<Vec<RelatedEvidence>, sqlx::Error> {
    if event_kind == "container.restart_loop" {
        return EventGroupRepository::related_evidence::<_, RelatedEvidence>(
            pool,
            organization_id,
            group_id,
            RELATED_EVIDENCE_LIMIT,
        )
        .await;
    }
    EventRepository::related_evidence::<_, RelatedEvidence>(
        pool,
        organization_id,
        event_id,
        RELATED_EVIDENCE_LIMIT,
    )
    .await
}

/// Reads and triages runtime groups.
#[derive(Clone, Debug)]
pub struct RuntimeGroupService {
    pool: PgPool,
}

impl RuntimeGroupService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// An application's runtime groups, most recently seen first, with their
    /// policy state and labels.
    pub async fn list_groups(
        &self,
        principal: IdentityPrincipal,
        query: ListQuery,
    ) -> Result<GroupList, RuntimeGroupServiceError> {
        let organization_id = project_organization(self, principal, query.project_id).await?;
        ensure_application(
            self,
            organization_id,
            query.project_id,
            query.application_id,
        )
        .await?;
        let limit = query.limit.unwrap_or(50);
        if !(1..=200).contains(&limit) {
            return Err(RuntimeGroupServiceError::Invalid(
                "limit must be between 1 and 200".into(),
            ));
        }
        if query
            .status
            .as_deref()
            .is_some_and(|status| !matches!(status, "open" | "acknowledged" | "resolved"))
        {
            return Err(RuntimeGroupServiceError::Invalid(
                "unsupported status".into(),
            ));
        }
        if query.verdict.as_deref().is_some_and(|verdict| {
            !matches!(
                verdict,
                "unclassified" | "expected" | "requires_review" | "policy_conflict"
            )
        }) {
            return Err(RuntimeGroupServiceError::Invalid(
                "unsupported policy verdict".into(),
            ));
        }
        let cursor = if let Some(cursor) = query.cursor {
            let position = EventGroupRepository::list_cursor(
                &self.pool,
                cursor,
                organization_id,
                query.project_id,
                query.application_id,
            )
            .await?
            .ok_or_else(|| {
                RuntimeGroupServiceError::Invalid("cursor does not exist in this scope".into())
            })?;
            Some(position)
        } else {
            None
        };
        let (cursor_time, cursor_id) = cursor.unzip();
        let mut items = EventGroupRepository::summary_page::<_, GroupSummary>(
            &self.pool,
            organization_id,
            query.project_id,
            query.application_id,
            query.event_kind,
            query.status,
            query.namespace,
            query.workload_kind,
            query.workload_name,
            query.since,
            query.first_seen_from,
            query.first_seen_to,
            query.last_seen_to,
            query.release_id,
            cursor_time,
            cursor_id,
            limit + 1,
        )
        .await?;
        attach_group_policy(&self.pool, organization_id, &mut items).await?;
        attach_group_user_labels(&self.pool, organization_id, &mut items).await?;
        items.retain(|group| {
            query.verdict.as_ref().is_none_or(|verdict| {
                group.policy_evaluation["verdict"].as_str() == Some(verdict.as_str())
            }) && query
                .suppressed
                .is_none_or(|suppressed| group.active_suppression.is_some() == suppressed)
                && query.evaluation_pending.is_none_or(|pending| {
                    (group.policy_evaluation["state"] == "evaluation_pending") == pending
                })
        });
        let next_cursor = if i64::try_from(items.len()).unwrap_or(i64::MAX) > limit {
            items.pop();
            items.last().map(|group| group.id)
        } else {
            None
        };
        let coverage = crate::runtime_retention::history::coverage(
            &self.pool,
            organization_id,
            query.project_id,
        )
        .await?;
        for item in &mut items {
            item.coverage = coverage.clone();
        }
        Ok(GroupList { items, next_cursor })
    }

    /// One runtime group with its representative occurrence and notification
    /// state.
    pub async fn get_group(
        &self,
        principal: IdentityPrincipal,
        group_id: Uuid,
    ) -> Result<GroupDetail, RuntimeGroupServiceError> {
        let (organization_id, _) = group_scope(self, principal, group_id).await?;
        let mut group =
            EventGroupRepository::summary::<_, GroupSummary>(&self.pool, organization_id, group_id)
                .await?
                .ok_or(RuntimeGroupServiceError::NotFound)?;
        attach_group_policy(
            &self.pool,
            organization_id,
            std::slice::from_mut(&mut group),
        )
        .await?;
        attach_group_user_labels(
            &self.pool,
            organization_id,
            std::slice::from_mut(&mut group),
        )
        .await?;
        group.coverage = crate::runtime_retention::history::coverage(
            &self.pool,
            organization_id,
            group.project_id,
        )
        .await?;
        let mut representative_event = match group.representative_event_id {
            Some(id) => event_by_id(&self.pool, organization_id, id).await?,
            None => None,
        };
        if let Some(event) = &mut representative_event {
            if group.event_kind == "container.restart_loop" {
                event.event_kind.clone_from(&group.event_kind);
                event.payload = serde_json::json!({"type":"ContainerRestartLoop","data":group.semantic_summary});
            }
            event.related_evidence = load_related_evidence(
                &self.pool,
                organization_id,
                group_id,
                event.id,
                &event.event_kind,
            )
            .await?;
        }
        let notification = notification_summary(&self.pool, organization_id, group_id).await?;
        Ok(GroupDetail {
            group,
            representative_event,
            notification,
        })
    }

    /// A group's occurrences in receive order, newest first, each with its
    /// related evidence.
    pub async fn list_occurrences(
        &self,
        principal: IdentityPrincipal,
        group_id: Uuid,
        query: OccurrenceQuery,
    ) -> Result<OccurrencePage, RuntimeGroupServiceError> {
        let (organization_id, _) = group_scope(self, principal, group_id).await?;
        let limit = query.limit.unwrap_or(50);
        if !(1..=200).contains(&limit) {
            return Err(RuntimeGroupServiceError::Invalid(
                "limit must be between 1 and 200".into(),
            ));
        }
        let cursor = if let Some(cursor) = query.cursor {
            Some(
                EventGroupRepository::occurrence_cursor(
                    &self.pool,
                    organization_id,
                    group_id,
                    cursor,
                )
                .await?
                .ok_or_else(|| {
                    RuntimeGroupServiceError::Invalid("cursor does not exist in this scope".into())
                })?,
            )
        } else {
            None
        };
        let (cursor_received_at, cursor_observed_at, cursor_id) = cursor
            .map_or((None, None, None), |(received_at, observed_at, id)| {
                (Some(received_at), Some(observed_at), Some(id))
            });
        let mut items = EventGroupRepository::occurrence_page::<_, EventOccurrence>(
            &self.pool,
            organization_id,
            group_id,
            cursor_received_at,
            cursor_observed_at,
            cursor_id,
            limit + 1,
        )
        .await?;
        for occurrence in &mut items {
            occurrence.related_evidence = load_related_evidence(
                &self.pool,
                organization_id,
                group_id,
                occurrence.id,
                &occurrence.event_kind,
            )
            .await?;
        }
        let next_cursor = if i64::try_from(items.len()).unwrap_or(i64::MAX) > limit {
            items.pop();
            items.last().map(|event| event.id)
        } else {
            None
        };
        Ok(OccurrencePage {
            items,
            next_cursor,
            ordering: "received_at_desc_observed_at_desc_id_desc",
        })
    }

    /// Moves a group to `target` if its status is one of `allowed`. A group
    /// already in `target` is returned unchanged; any other status refuses the
    /// transition.
    async fn transition_group(
        &self,
        principal: IdentityPrincipal,
        group_id: Uuid,
        target: &'static str,
        allowed: &'static [&'static str],
    ) -> Result<GroupSummary, RuntimeGroupServiceError> {
        let (organization_id, _) = group_scope(self, principal, group_id).await?;
        let group = EventGroupRepository::set_status::<_, GroupSummary>(
            &self.pool,
            organization_id,
            group_id,
            target,
            principal.user_id,
            allowed,
        )
        .await?;
        if let Some(mut group) = group {
            attach_group_policy(
                &self.pool,
                organization_id,
                std::slice::from_mut(&mut group),
            )
            .await?;
            attach_group_user_labels(
                &self.pool,
                organization_id,
                std::slice::from_mut(&mut group),
            )
            .await?;
            return Ok(group);
        }
        let current: Option<String> =
            EventGroupRepository::status(&self.pool, organization_id, group_id).await?;
        match current {
            None => Err(RuntimeGroupServiceError::NotFound),
            Some(current) => Err(RuntimeGroupServiceError::Invalid(format!(
                "cannot transition runtime group from {current} to {target}"
            ))),
        }
    }

    /// A group's retained daily snapshots.
    pub async fn list_snapshots(
        &self,
        principal: IdentityPrincipal,
        group_id: Uuid,
        query: crate::runtime_retention::history::Query,
    ) -> Result<crate::runtime_retention::history::Page, RuntimeGroupServiceError> {
        let (organization_id, project) = group_scope(self, principal, group_id).await?;
        if query
            .day_from
            .zip(query.day_to)
            .is_some_and(|(from, to)| from >= to)
        {
            return Err(RuntimeGroupServiceError::Invalid(
                "day_from must precede day_to".into(),
            ));
        }
        Ok(crate::runtime_retention::history::page(
            &self.pool,
            organization_id,
            project,
            group_id,
            query,
        )
        .await?)
    }

    /// Acknowledges an open group.
    pub async fn acknowledge_group(
        &self,
        principal: IdentityPrincipal,
        group_id: Uuid,
    ) -> Result<GroupSummary, RuntimeGroupServiceError> {
        self.transition_group(principal, group_id, "acknowledged", &["open"])
            .await
    }

    /// Resolves an open or acknowledged group.
    pub async fn resolve_group(
        &self,
        principal: IdentityPrincipal,
        group_id: Uuid,
    ) -> Result<GroupSummary, RuntimeGroupServiceError> {
        self.transition_group(principal, group_id, "resolved", &["open", "acknowledged"])
            .await
    }

    /// Reopens an acknowledged or resolved group.
    pub async fn reopen_group(
        &self,
        principal: IdentityPrincipal,
        group_id: Uuid,
    ) -> Result<GroupSummary, RuntimeGroupServiceError> {
        self.transition_group(principal, group_id, "open", &["acknowledged", "resolved"])
            .await
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn occurrence_contract_exposes_receive_order_and_bounded_related_evidence() {
        assert_eq!(RELATED_EVIDENCE_LIMIT, 20);
        let now = Utc::now();
        let occurrence = EventOccurrence {
            id: Uuid::from_u128(1),
            event_id: Uuid::from_u128(2),
            observed_at: now - chrono::Duration::seconds(5),
            received_at: now,
            node_name: "node".into(),
            namespace: "default".into(),
            pod_name: "pod".into(),
            container_name: "worker".into(),
            process_command: "worker".into(),
            event_kind: "container.restart_loop".into(),
            payload: serde_json::json!({
                "type": "ContainerRestartLoop",
                "data": {"evidence_source": "derived", "projection_version": 1}
            }),
            correlation: serde_json::json!({"status": "absent", "candidate_count": 0}),
            related_evidence: Vec::new(),
            release_id: None,
            release_version: None,
            release_display_name: "Unattributed".into(),
        };
        let page = OccurrencePage {
            items: vec![occurrence],
            next_cursor: None,
            ordering: "received_at_desc_observed_at_desc_id_desc",
        };
        let value = serde_json::to_value(page).unwrap();
        assert!(value["items"][0]["received_at"].is_string());
        assert_eq!(value["items"][0]["related_evidence"], serde_json::json!([]));
        assert_eq!(value["items"][0]["payload"]["type"], "ContainerRestartLoop");
        assert_eq!(
            value["ordering"],
            "received_at_desc_observed_at_desc_id_desc"
        );
    }
}

#[cfg(test)]
mod use_cases {
    use super::*;
    use crate::auth::OrganizationRole;
    use crate::repository::test_support::{Tenant, exec, group_ids, ingest, tenant, user};

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

    fn list(tenant: &Tenant, application_id: Uuid) -> ListQuery {
        ListQuery {
            project_id: tenant.project_id,
            application_id,
            event_kind: None,
            status: None,
            namespace: None,
            workload_kind: None,
            workload_name: None,
            since: None,
            first_seen_from: None,
            first_seen_to: None,
            last_seen_to: None,
            release_id: None,
            verdict: None,
            suppressed: None,
            evaluation_pending: None,
            cursor: None,
            limit: None,
        }
    }

    async fn seed(pool: &PgPool, tenant: &Tenant) -> Vec<Uuid> {
        let at = Utc::now() - chrono::Duration::minutes(5);
        ingest(
            pool,
            tenant,
            &[
                exec(tenant, "/bin/a", at),
                exec(tenant, "/bin/a", at + chrono::Duration::seconds(1)),
                exec(tenant, "/bin/b", at + chrono::Duration::seconds(2)),
            ],
        )
        .await;
        group_ids(pool, tenant).await
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn lists_check_access_then_filters(pool: PgPool) {
        let other = tenant(&pool, "groups-service-other").await;
        let tenant = tenant(&pool, "groups-service-list").await;
        seed(&pool, &tenant).await;
        let service = RuntimeGroupService::new(pool.clone());
        let principal = owner(&tenant, Uuid::new_v4());
        let invalid = |mut query: ListQuery| {
            query.limit = Some(0);
            query
        };

        assert!(matches!(
            service
                .list_groups(
                    owner(&other, Uuid::new_v4()),
                    invalid(list(&tenant, tenant.application_id))
                )
                .await,
            Err(RuntimeGroupServiceError::NotFound)
        ));
        assert!(matches!(
            service
                .list_groups(principal, invalid(list(&tenant, other.application_id)))
                .await,
            Err(RuntimeGroupServiceError::NotFound)
        ));
        assert!(matches!(
            service
                .list_groups(principal, invalid(list(&tenant, tenant.application_id)))
                .await,
            Err(RuntimeGroupServiceError::Invalid(message)) if message == "limit must be between 1 and 200"
        ));
        let mut unknown_status = list(&tenant, tenant.application_id);
        unknown_status.status = Some("closed".into());
        assert!(matches!(
            service.list_groups(principal, unknown_status).await,
            Err(RuntimeGroupServiceError::Invalid(message)) if message == "unsupported status"
        ));
        let mut foreign_cursor = list(&tenant, tenant.application_id);
        foreign_cursor.cursor = Some(Uuid::new_v4());
        assert!(matches!(
            service.list_groups(principal, foreign_cursor).await,
            Err(RuntimeGroupServiceError::Invalid(message)) if message == "cursor does not exist in this scope"
        ));

        let mut first = list(&tenant, tenant.application_id);
        first.limit = Some(1);
        let page = service.list_groups(principal, first).await.unwrap();
        assert_eq!(page.items.len(), 1);
        let mut second = list(&tenant, tenant.application_id);
        second.cursor = page.next_cursor;
        let rest = service.list_groups(principal, second).await.unwrap();
        assert_eq!(rest.items.len(), 1);
        assert_ne!(rest.items[0].id, page.items[0].id);
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn groups_open_with_evidence_and_move_through_triage(pool: PgPool) {
        let tenant = tenant(&pool, "groups-service-triage").await;
        let groups = seed(&pool, &tenant).await;
        let service = RuntimeGroupService::new(pool.clone());
        let principal = owner(&tenant, user(&pool).await);
        let group = groups[0];

        let detail = service.get_group(principal, group).await.unwrap();
        assert_eq!(detail.group.status, "open");
        assert!(detail.representative_event.is_some());
        assert!(matches!(
            service.get_group(principal, Uuid::new_v4()).await,
            Err(RuntimeGroupServiceError::NotFound)
        ));
        let occurrences = service
            .list_occurrences(
                principal,
                group,
                OccurrenceQuery {
                    cursor: None,
                    limit: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(occurrences.items.len(), 2);
        assert!(matches!(
            service
                .list_occurrences(
                    principal,
                    group,
                    OccurrenceQuery {
                        cursor: None,
                        limit: Some(201),
                    },
                )
                .await,
            Err(RuntimeGroupServiceError::Invalid(_))
        ));

        let acknowledged = service.acknowledge_group(principal, group).await.unwrap();
        assert_eq!(acknowledged.status, "acknowledged");
        // Repeating a transition keeps the original change.
        let again = service.acknowledge_group(principal, group).await.unwrap();
        assert_eq!(again.status_changed_at, acknowledged.status_changed_at);
        assert_eq!(
            service
                .resolve_group(principal, group)
                .await
                .unwrap()
                .status,
            "resolved"
        );
        assert!(matches!(
            service.acknowledge_group(principal, group).await,
            Err(RuntimeGroupServiceError::Invalid(message))
                if message == "cannot transition runtime group from resolved to acknowledged"
        ));
        assert_eq!(
            service.reopen_group(principal, group).await.unwrap().status,
            "open"
        );
        assert!(matches!(
            service.reopen_group(principal, Uuid::new_v4()).await,
            Err(RuntimeGroupServiceError::NotFound)
        ));

        let today = Utc::now().date_naive();
        assert!(matches!(
            service
                .list_snapshots(
                    principal,
                    group,
                    crate::runtime_retention::history::Query {
                        day_from: Some(today),
                        day_to: Some(today),
                        release_id: None,
                        cursor: None,
                        limit: None,
                    },
                )
                .await,
            Err(RuntimeGroupServiceError::Invalid(message)) if message == "day_from must precede day_to"
        ));
    }
}
