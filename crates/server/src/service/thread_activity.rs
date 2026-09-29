//! Authorized thread-window queries and bounded reconciliation.
use super::project_access::project_scope;
use crate::auth::IdentityPrincipal;
use crate::repository::thread_activity::{ThreadActivityRepository, WindowFilter, WindowRow};
use crate::repository::{ApplicationRepository, releases::ApplicationScope};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::PgPool;
use std::collections::{BTreeMap, HashSet};
use uuid::Uuid;
#[derive(Debug, Deserialize)]
pub struct ScopeQuery {
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    process_generation: Option<i64>,
    observation_epoch: Option<Uuid>,
    limit: Option<i64>,
    cursor: Option<Uuid>,
}
#[derive(Clone, Debug, Serialize)]
pub struct ThreadWindow {
    id: Uuid,
    process_cgroup_id: i64,
    process_pid: i64,
    process_tgid: i64,
    process_command: String,
    process_generation: i64,
    observation_epoch: Uuid,
    start_observed: bool,
    window_started_at: DateTime<Utc>,
    window_ended_at: DateTime<Utc>,
    created_count: i64,
    exited_count: i64,
    active_at_start: i64,
    active_at_end: i64,
    peak_active: i64,
    baseline_provenance: String,
    baseline_complete: bool,
    name_overflow: i64,
    names: Value,
    gaps: Value,
}
impl From<WindowRow> for ThreadWindow {
    fn from(row: WindowRow) -> Self {
        Self {
            id: row.id,
            process_cgroup_id: row.process_cgroup_id,
            process_pid: row.process_pid,
            process_tgid: row.process_tgid,
            process_command: row.process_command,
            process_generation: row.process_generation,
            observation_epoch: row.observation_epoch,
            start_observed: row.start_observed,
            window_started_at: row.window_started_at,
            window_ended_at: row.window_ended_at,
            created_count: row.created_count,
            exited_count: row.exited_count,
            active_at_start: row.active_at_start,
            active_at_end: row.active_at_end,
            peak_active: row.peak_active,
            baseline_provenance: row.baseline_provenance,
            baseline_complete: row.baseline_complete,
            name_overflow: row.name_overflow,
            names: row.names,
            gaps: row.gaps,
        }
    }
}
#[derive(Debug, Serialize)]
pub struct WindowPage {
    items: Vec<ThreadWindow>,
    next_cursor: Option<Uuid>,
}
#[derive(Debug, Serialize)]
pub struct ThreadSummary {
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    window_count: i64,
    truncated: bool,
    created: i64,
    exited: i64,
    active: Option<i64>,
    peak_active: Option<i64>,
    baseline_complete: bool,
    baseline_provenance: Option<String>,
    name_overflow: i64,
    names: Value,
    gaps: Value,
}

#[derive(Debug, thiserror::Error)]
pub enum ThreadActivityError {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("thread activity resource not found")]
    NotFound,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}
#[derive(Clone, Debug)]
pub struct ThreadActivityService {
    pool: PgPool,
}
impl ThreadActivityService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    async fn filter(
        &self,
        identity: IdentityPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        query: &ScopeQuery,
    ) -> Result<WindowFilter, ThreadActivityError> {
        let scope = project_scope(&self.pool, identity, project_id)
            .await?
            .ok_or(ThreadActivityError::NotFound)?;
        if !ApplicationRepository::exists(
            &self.pool,
            scope.organization_id,
            project_id,
            application_id,
        )
        .await?
        {
            return Err(ThreadActivityError::NotFound);
        }
        let to = query.to.unwrap_or_else(Utc::now);
        let from =
            match query.from {
                Some(from) => from,
                None => to.checked_sub_signed(Duration::hours(1)).ok_or(
                    ThreadActivityError::Invalid("time scope exceeds supported timestamp range"),
                )?,
            };
        if from >= to || to - from > Duration::hours(24 * 31) {
            return Err(ThreadActivityError::Invalid(
                "time scope must be positive and no longer than 31 days",
            ));
        }
        if query.process_generation.is_some() != query.observation_epoch.is_some() {
            return Err(ThreadActivityError::Invalid(
                "process_generation and observation_epoch must be supplied together",
            ));
        }
        if query.process_generation.is_some_and(|value| value <= 0)
            || query.observation_epoch.is_some_and(|value| value.is_nil())
        {
            return Err(ThreadActivityError::Invalid(
                "process generation and observation epoch must be valid",
            ));
        }
        Ok(WindowFilter {
            scope: ApplicationScope {
                organization_id: scope.organization_id,
                project_id,
                application_id,
            },
            from,
            to,
            generation: query.process_generation,
            epoch: query.observation_epoch,
        })
    }
    pub async fn list(
        &self,
        identity: IdentityPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        query: ScopeQuery,
    ) -> Result<WindowPage, ThreadActivityError> {
        let filter = self
            .filter(identity, project_id, application_id, &query)
            .await?;
        let limit = query.limit.unwrap_or(50);
        if !(1..=200).contains(&limit) {
            return Err(ThreadActivityError::Invalid(
                "limit must be between 1 and 200",
            ));
        }
        if let Some(cursor) = query.cursor
            && !ThreadActivityRepository::cursor_exists(&self.pool, filter, cursor).await?
        {
            return Err(ThreadActivityError::Invalid(
                "cursor does not belong to the requested scope",
            ));
        }
        let mut rows =
            ThreadActivityRepository::windows(&self.pool, filter, query.cursor, limit + 1).await?;
        let limit = usize::try_from(limit).expect("bounded positive limit");
        let more = rows.len() > limit;
        rows.truncate(limit);
        let next_cursor = more.then(|| rows.last().expect("nonempty page").id);
        Ok(WindowPage {
            items: rows.into_iter().map(ThreadWindow::from).collect(),
            next_cursor,
        })
    }
    pub async fn summary(
        &self,
        identity: IdentityPrincipal,
        project_id: Uuid,
        application_id: Uuid,
        query: ScopeQuery,
    ) -> Result<ThreadSummary, ThreadActivityError> {
        let filter = self
            .filter(identity, project_id, application_id, &query)
            .await?;
        if query.cursor.is_some() || query.limit.is_some() {
            return Err(ThreadActivityError::Invalid(
                "summary does not accept pagination",
            ));
        }
        let mut rows = ThreadActivityRepository::windows(&self.pool, filter, None, 10001).await?;
        let truncated = rows.len() > 10000;
        rows.truncate(10000);
        reconcile(filter.from, filter.to, &rows, truncated)
    }
}
fn qualified_process(row: &WindowRow) -> (Uuid, i64, i64, i64, Uuid) {
    (
        row.agent_id,
        row.process_cgroup_id,
        row.process_tgid,
        row.process_generation,
        row.observation_epoch,
    )
}
fn reconcile(
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    rows: &[WindowRow],
    truncated: bool,
) -> Result<ThreadSummary, ThreadActivityError> {
    let qualified = rows.iter().map(qualified_process).collect::<HashSet<_>>();
    let single = qualified.len() == 1;
    let latest = rows.first(); // Repository ordering is newest first.
    let (names, folded_names) = aggregate_names(rows, single)?;
    let mut gaps = rows
        .iter()
        .flat_map(|row| row.gaps.as_array().into_iter().flatten())
        .cloned()
        .collect::<Vec<_>>();
    gaps.sort_by_key(Value::to_string);
    gaps.dedup();
    Ok(ThreadSummary {
        from,
        to,
        window_count: i64::try_from(rows.len()).expect("bounded rows"),
        truncated,
        created: checked_sum(rows.iter().map(|row| row.created_count))?,
        exited: checked_sum(rows.iter().map(|row| row.exited_count))?,
        active: latest.filter(|_| single).map(|row| row.active_at_end),
        peak_active: single
            .then(|| rows.iter().map(|row| row.peak_active).max())
            .flatten(),
        baseline_complete: !truncated
            && !rows.is_empty()
            && rows
                .iter()
                .all(|row| row.baseline_complete && row.gaps == json!([])),
        baseline_provenance: latest
            .map(|row| row.baseline_provenance.clone())
            .filter(|value| rows.iter().all(|row| row.baseline_provenance == *value)),
        name_overflow: add(
            checked_sum(rows.iter().map(|row| row.name_overflow))?,
            folded_names,
        )?,
        names,
        gaps: json!(gaps),
    })
}
fn aggregate_names(rows: &[WindowRow], single: bool) -> Result<(Value, i64), ThreadActivityError> {
    let mut names: BTreeMap<String, (i64, i64, i64)> = BTreeMap::new();
    for row in rows {
        for name in row.names.as_array().into_iter().flatten() {
            let total = names
                .entry(name["name"].as_str().unwrap_or("unknown").to_owned())
                .or_default();
            total.0 = add(total.0, name["created"].as_i64().unwrap_or(0))?;
            total.1 = add(total.1, name["exited"].as_i64().unwrap_or(0))?;
        }
    }
    if single && let Some(latest) = rows.first() {
        for name in latest.names.as_array().into_iter().flatten() {
            names
                .entry(name["name"].as_str().unwrap_or("unknown").to_owned())
                .or_default()
                .2 = name["active"].as_i64().unwrap_or(0);
        }
    }
    let mut overflow = names.remove("other").unwrap_or_default();
    let mut output = Vec::new();
    let mut folded = 0;
    for (name, (created, exited, active)) in names {
        if output.len() < 65 {
            output.push(json!({"name": name, "created": created, "exited": exited,
                "active": single.then_some(active)}));
        } else {
            overflow.0 = add(overflow.0, created)?;
            overflow.1 = add(overflow.1, exited)?;
            overflow.2 = add(overflow.2, active)?;
            folded += 1;
        }
    }
    if overflow != (0, 0, 0) {
        output.push(
            json!({"name":"other", "created":overflow.0, "exited":overflow.1,
            "active":single.then_some(overflow.2)}),
        );
    }
    Ok((json!(output), folded))
}

fn add(left: i64, right: i64) -> Result<i64, ThreadActivityError> {
    left.checked_add(right).ok_or(ThreadActivityError::Invalid(
        "thread summary exceeds supported counter range",
    ))
}
fn checked_sum(mut values: impl Iterator<Item = i64>) -> Result<i64, ThreadActivityError> {
    values.try_fold(0, add)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::OrganizationRole;
    use crate::repository::runtime_retention::RuntimeRetentionRepository;
    use crate::repository::test_support::{Tenant, event, ingest, tenant};
    use event_model::{
        BaselineProvenance, EventPayload, ProcessGenerationIdentity, ThreadActivityWindow,
        ThreadNameAggregate,
    };

    fn sample(at: DateTime<Utc>) -> WindowRow {
        WindowRow {
            id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            process_cgroup_id: 1,
            process_pid: 2,
            process_tgid: 2,
            process_command: "app".into(),
            process_generation: 1,
            observation_epoch: Uuid::new_v4(),
            start_observed: true,
            window_started_at: at,
            window_ended_at: at + Duration::minutes(1),
            created_count: 1,
            exited_count: 0,
            active_at_start: 0,
            active_at_end: 1,
            peak_active: 1,
            baseline_provenance: "observed".into(),
            baseline_complete: true,
            name_overflow: 0,
            names: json!([{"name":"worker","created":1,"exited":0,"active":1}]),
            gaps: json!([]),
        }
    }
    #[test]
    fn summaries_reconcile_windows_without_double_counting_current_names() {
        let now = Utc::now();
        let newest = sample(now);
        let mut previous = newest.clone();
        previous.window_started_at = now - Duration::minutes(1);
        let summary = reconcile(
            now - Duration::hours(1),
            now,
            &[newest.clone(), previous],
            false,
        )
        .unwrap();
        assert_eq!(
            (summary.created, summary.active, summary.peak_active),
            (2, Some(1), Some(1))
        );
        assert_eq!(
            summary.names,
            json!([{"name":"worker","created":2,"exited":0,"active":1}])
        );
        let mut other = newest.clone();
        other.observation_epoch = Uuid::new_v4();
        let summary = reconcile(now - Duration::hours(1), now, &[newest, other], false).unwrap();
        assert_eq!((summary.active, summary.peak_active), (None, None));
        assert_eq!(summary.names[0]["active"], Value::Null);
    }
    #[test]
    fn summary_overflow_returns_an_error_instead_of_wrapping() {
        let now = Utc::now();
        let mut row = sample(now);
        row.created_count = i64::MAX;
        assert!(reconcile(now, now, &[row.clone(), row], false).is_err());
        let mut row = sample(now);
        row.names[0]["created"] = json!(i64::MAX);
        assert!(reconcile(now, now, &[row.clone(), row], false).is_err());
    }
    fn identity(tenant: &Tenant) -> IdentityPrincipal {
        IdentityPrincipal {
            user_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            active_organization_id: Some(tenant.organization_id),
            organization_role: Some(OrganizationRole::Owner),
            is_super_admin: false,
            privileged_until: None,
        }
    }
    fn query(from: DateTime<Utc>, to: DateTime<Utc>, cursor: Option<Uuid>) -> ScopeQuery {
        ScopeQuery {
            from: Some(from),
            to: Some(to),
            process_generation: None,
            observation_epoch: None,
            limit: Some(1),
            cursor,
        }
    }
    fn window(tenant: &Tenant, start: DateTime<Utc>, epoch: Uuid) -> event_model::RuntimeEvent {
        let mut value = event(
            tenant,
            EventPayload::ProcessStart(event_model::ProcessStart {
                generation: ProcessGenerationIdentity {
                    generation: 1,
                    observation_epoch: epoch,
                    start_observed: true,
                },
                parent_pid: 1,
                parent_tgid: 1,
                parent_command: "parent".into(),
            }),
            start + Duration::minutes(1),
        );
        value.payload = EventPayload::ThreadActivityWindow(ThreadActivityWindow {
            id: value.id,
            process: value.process.clone(),
            generation: ProcessGenerationIdentity {
                generation: 1,
                observation_epoch: epoch,
                start_observed: true,
            },
            window_started_at: start,
            window_ended_at: start + Duration::minutes(1),
            created: 1,
            exited: 0,
            active_at_start: 0,
            active_at_end: 1,
            peak_active: 1,
            names: vec![ThreadNameAggregate {
                name: "worker".into(),
                created: 1,
                exited: 0,
                active: 1,
            }],
            baseline_provenance: BaselineProvenance::Observed,
            baseline_complete: true,
            name_overflow: 0,
            gaps: vec![],
        });
        value
    }
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn ingested_windows_are_scoped_paginated_replay_safe_and_retained(pool: PgPool) {
        let own = tenant(&pool, "thread-service").await;
        let foreign = tenant(&pool, "thread-service-foreign").await;
        let now = Utc::now();
        let epoch = Uuid::new_v4();
        let events = [
            window(&own, now - Duration::minutes(3), epoch),
            window(&own, now - Duration::minutes(2), epoch),
        ];
        ingest(&pool, &own, &events).await;
        ingest(&pool, &own, &events).await;
        let service = ThreadActivityService::new(pool.clone());
        let page = service
            .list(
                identity(&own),
                own.project_id,
                own.application_id,
                query(now - Duration::hours(1), now, None),
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
        let next = service
            .list(
                identity(&own),
                own.project_id,
                own.application_id,
                query(now - Duration::hours(1), now, page.next_cursor),
            )
            .await
            .unwrap();
        assert_eq!(next.items.len(), 1);
        assert!(next.next_cursor.is_none());
        assert_ne!(page.items[0].id, next.items[0].id);
        assert!(matches!(
            service
                .list(
                    identity(&foreign),
                    own.project_id,
                    own.application_id,
                    query(now - Duration::hours(1), now, None)
                )
                .await,
            Err(ThreadActivityError::NotFound)
        ));
        assert!(
            service
                .list(
                    identity(&own),
                    own.project_id,
                    own.application_id,
                    query(now - Duration::hours(1), now, Some(Uuid::new_v4()))
                )
                .await
                .is_err()
        );
        assert!(
            service
                .list(
                    identity(&own),
                    own.project_id,
                    own.application_id,
                    query(now, now, None)
                )
                .await
                .is_err()
        );
        RuntimeRetentionRepository::advance_horizons(&pool, own.project_id, now, None)
            .await
            .unwrap();
        let hidden = service
            .list(
                identity(&own),
                own.project_id,
                own.application_id,
                query(now - Duration::hours(1), now, None),
            )
            .await
            .unwrap();
        assert!(hidden.items.is_empty());
        assert!(
            service
                .list(
                    identity(&own),
                    own.project_id,
                    own.application_id,
                    query(now - Duration::hours(1), now, Some(page.items[0].id))
                )
                .await
                .is_err()
        );
        let mut summary_query = query(now - Duration::hours(1), now, None);
        summary_query.limit = None;
        let hidden = service
            .summary(
                identity(&own),
                own.project_id,
                own.application_id,
                summary_query,
            )
            .await
            .unwrap();
        assert_eq!(hidden.window_count, 0);
        assert!(
            RuntimeRetentionRepository::has_backlog(&pool, own.project_id)
                .await
                .unwrap()
        );
        assert_eq!(
            RuntimeRetentionRepository::expire_thread_windows(&pool, own.project_id, 100)
                .await
                .unwrap(),
            2
        );
        let page = service
            .list(
                identity(&own),
                own.project_id,
                own.application_id,
                query(now - Duration::hours(1), now, None),
            )
            .await
            .unwrap();
        assert!(page.items.is_empty());
    }
}
