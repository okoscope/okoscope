use crate::repository::inventory::InventoryRepository;
use crate::repository::outbox::OutboxRepository;
use crate::repository::terminations::TerminationRepository;
use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use event_model::RestartLoopSummary;
use event_model::{ContainerRestart, EventPayload, RuntimeEvent};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::inventory::CURRENT_INVENTORY_IDENTITY_VERSION;
use crate::repository::{EventGroupRepository, GroupKey};

pub const CORRELATION_TOLERANCE: Duration = Duration::seconds(30);
pub const RESTART_WINDOW: Duration = Duration::minutes(10);
pub const RESTART_THRESHOLD_V1: u32 = 3;
pub const RESTART_PROJECTION_VERSION: u16 = 1;
pub const MAX_RESTART_OCCURRENCES: usize = 100_000;
const DERIVED_GROUP_FINGERPRINT_VERSION: i16 = 101;

pub async fn project_durable_evidence(
    tx: &mut Transaction<'_, Postgres>,
    raw_event_id: Uuid,
    organization_id: Uuid,
    cluster_id: Uuid,
    event: &RuntimeEvent,
) -> Result<(), sqlx::Error> {
    match &event.payload {
        EventPayload::ContainerTermination(_) => {
            correlate_termination(tx, raw_event_id, organization_id, event).await
        }
        EventPayload::ContainerRestart(restart) => {
            project_restart_loop(
                tx,
                raw_event_id,
                organization_id,
                cluster_id,
                event,
                restart,
            )
            .await
        }
        _ => Ok(()),
    }
}

async fn correlate_termination(
    tx: &mut Transaction<'_, Postgres>,
    lifecycle_event_id: Uuid,
    organization_id: Uuid,
    event: &RuntimeEvent,
) -> Result<(), sqlx::Error> {
    let candidates: Vec<Uuid> = TerminationRepository::kernel_exit_candidates(
        &mut **tx,
        organization_id,
        event.attribution.project_id,
        event.attribution.application_id,
        &event.attribution.workload_uid,
        &event.attribution.pod_uid,
        &event.attribution.container_name,
        &event.attribution.container_id,
        event.observed_at,
        format!("{} seconds", CORRELATION_TOLERANCE.num_seconds()),
    )
    .await?;
    let status = match candidates.len() {
        0 => "absent",
        1 => "qualified",
        _ => "ambiguous",
    };
    TerminationRepository::record_outcome(
        &mut **tx,
        organization_id,
        event.attribution.project_id,
        lifecycle_event_id,
        status,
        i32::try_from(candidates.len()).unwrap_or(i32::MAX),
        i32::try_from(CORRELATION_TOLERANCE.num_seconds()).unwrap_or(i32::MAX),
    )
    .await?;
    if let [kernel_event_id] = candidates.as_slice() {
        TerminationRepository::link(
            &mut **tx,
            organization_id,
            event.attribution.project_id,
            lifecycle_event_id,
            *kernel_event_id,
        )
        .await?;
    }
    Ok(())
}

async fn project_restart_loop(
    tx: &mut Transaction<'_, Postgres>,
    raw_event_id: Uuid,
    organization_id: Uuid,
    cluster_id: Uuid,
    event: &RuntimeEvent,
    restart: &ContainerRestart,
) -> Result<(), sqlx::Error> {
    let window_start = event.observed_at - RESTART_WINDOW;
    let version = i16::try_from(RESTART_PROJECTION_VERSION).unwrap_or(i16::MAX);
    let delta = i32::try_from(restart.restart_delta).unwrap_or(i32::MAX);
    let inserted = TerminationRepository::add_restart(
        &mut **tx,
        organization_id,
        event.attribution.project_id,
        version,
        raw_event_id,
        window_start,
        event.observed_at,
        delta,
    )
    .await?;
    if inserted.rows_affected() == 0 {
        return Ok(());
    }
    let projection_end: DateTime<Utc> = TerminationRepository::restart_window_end(
        &mut **tx,
        organization_id,
        event.attribution.project_id,
        event.attribution.application_id,
        cluster_id,
        &event.attribution.pod_uid,
        &event.attribution.container_name,
        &event.attribution.container_id,
        version,
        event.observed_at,
        event.observed_at + RESTART_WINDOW,
    )
    .await?;
    let projection_start = projection_end - RESTART_WINDOW;
    let count: i64 = TerminationRepository::restarts_in_window(
        &mut **tx,
        organization_id,
        event.attribution.project_id,
        event.attribution.application_id,
        cluster_id,
        &event.attribution.pod_uid,
        &event.attribution.container_name,
        &event.attribution.container_id,
        version,
        projection_start,
        projection_end,
    )
    .await?;
    let observed_count = i32::try_from(count).unwrap_or(i32::MAX);
    TerminationRepository::upsert_restart_loop(
        &mut **tx,
        organization_id,
        event.attribution.project_id,
        event.attribution.application_id,
        cluster_id,
        &event.attribution.pod_uid,
        &event.attribution.container_name,
        &event.attribution.container_id,
        version,
        projection_start,
        projection_end,
        observed_count,
        restart
            .previous_termination
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| sqlx::Error::Protocol(error.to_string()))?,
        restart.waiting_reason.as_deref(),
    )
    .await?;
    if count >= i64::from(RESTART_THRESHOLD_V1) {
        upsert_restart_loop_group(
            tx,
            raw_event_id,
            organization_id,
            cluster_id,
            event,
            restart,
            observed_count,
            projection_start,
            projection_end,
        )
        .await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn upsert_restart_loop_group(
    tx: &mut Transaction<'_, Postgres>,
    raw_event_id: Uuid,
    organization_id: Uuid,
    cluster_id: Uuid,
    event: &RuntimeEvent,
    restart: &ContainerRestart,
    observed_count: i32,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    let mut hash = Sha256::new();
    for field in [
        organization_id.to_string(),
        event.attribution.project_id.to_string(),
        event.attribution.application_id.to_string(),
        cluster_id.to_string(),
        event.attribution.namespace.clone(),
        event.attribution.workload_kind.clone(),
        event.attribution.workload_name.clone(),
        event.attribution.container_name.clone(),
        RESTART_PROJECTION_VERSION.to_string(),
    ] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    let digest = hash.finalize();
    let summary = json!({"evidence_source":"derived","projection_version":RESTART_PROJECTION_VERSION,"threshold":RESTART_THRESHOLD_V1,"window_started_at":window_start,"window_ended_at":window_end,"observed_restart_count":observed_count,"container_name":event.attribution.container_name,"latest_termination":restart.previous_termination,"latest_waiting_reason":restart.waiting_reason});
    let candidate = Uuid::new_v4();
    let group_id = EventGroupRepository::upsert_derived(
        &mut **tx,
        candidate,
        GroupKey {
            organization_id,
            project_id: event.attribution.project_id,
            application_id: event.attribution.application_id,
            cluster_id,
            namespace: &event.attribution.namespace,
            workload_kind: &event.attribution.workload_kind,
            workload_name: &event.attribution.workload_name,
            fingerprint_version: DERIVED_GROUP_FINGERPRINT_VERSION,
            fingerprint_digest: digest.as_slice(),
        },
        "container.restart_loop",
        &summary,
        event.observed_at,
        raw_event_id,
    )
    .await?;
    if group_id == candidate {
        OutboxRepository::insert_first_seen(
            &mut **tx,
            Uuid::new_v4(),
            organization_id,
            event.attribution.project_id,
            group_id,
            json!({
                "group_id": group_id,
                "application_id": event.attribution.application_id,
                "event_kind": "container.restart_loop",
                "semantic": summary,
                "fingerprint_version": DERIVED_GROUP_FINGERPRINT_VERSION,
            }),
        )
        .await?;
    }
    let membership = EventGroupRepository::add_membership(
        &mut **tx,
        organization_id,
        event.attribution.project_id,
        event.attribution.application_id,
        raw_event_id,
        group_id,
        DERIVED_GROUP_FINGERPRINT_VERSION,
    )
    .await?;
    if membership.rows_affected() > 0 && group_id != candidate {
        EventGroupRepository::increment_occurrence(&mut **tx, group_id).await?;
    }
    InventoryRepository::link_event_items_to_group(
        &mut **tx,
        organization_id,
        event.attribution.project_id,
        event.attribution.application_id,
        group_id,
        raw_event_id,
        CURRENT_INVENTORY_IDENTITY_VERSION.get(),
    )
    .await?;
    TerminationRepository::attach_restart_loop_group(
        &mut **tx,
        group_id,
        organization_id,
        event.attribution.project_id,
        event.attribution.application_id,
        cluster_id,
        &event.attribution.pod_uid,
        &event.attribution.container_name,
        &event.attribution.container_id,
        i16::try_from(RESTART_PROJECTION_VERSION).unwrap_or(i16::MAX),
    )
    .await?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorrelationScope {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub workload_uid: String,
    pub pod_uid: String,
    pub container_name: String,
    pub runtime_container_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorrelationCandidate {
    pub event_id: Uuid,
    pub scope: CorrelationScope,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorrelationResult {
    None,
    Unique(Uuid),
    Ambiguous,
}

#[must_use]
pub fn correlate(
    lifecycle: &CorrelationCandidate,
    kernel_candidates: &[CorrelationCandidate],
) -> CorrelationResult {
    let mut matches = kernel_candidates.iter().filter(|candidate| {
        candidate.scope == lifecycle.scope
            && (candidate.observed_at - lifecycle.observed_at).abs() <= CORRELATION_TOLERANCE
    });
    let Some(first) = matches.next() else {
        return CorrelationResult::None;
    };
    if matches.next().is_some() {
        CorrelationResult::Ambiguous
    } else {
        CorrelationResult::Unique(first.event_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RestartScope {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub pod_uid: String,
    pub container_name: String,
    pub runtime_container_id: String,
}

#[derive(Clone, Debug)]
pub struct RestartOccurrence {
    pub event_id: Uuid,
    pub scope: RestartScope,
    pub observed_at: DateTime<Utc>,
    pub delta: u32,
    pub waiting_reason: Option<String>,
}

#[derive(Debug)]
pub struct RestartLoopProjector {
    occurrences: HashMap<Uuid, RestartOccurrence>,
    latest_seen: Option<DateTime<Utc>>,
}

impl Default for RestartLoopProjector {
    fn default() -> Self {
        Self {
            occurrences: HashMap::with_capacity(4096),
            latest_seen: None,
        }
    }
}

impl RestartLoopProjector {
    pub fn observe(&mut self, occurrence: RestartOccurrence) -> Option<RestartLoopSummary> {
        if occurrence.delta == 0 || self.occurrences.contains_key(&occurrence.event_id) {
            return None;
        }
        let scope = occurrence.scope.clone();
        let end = occurrence.observed_at;
        self.latest_seen = Some(self.latest_seen.map_or(end, |value| value.max(end)));
        let retention_floor = self.latest_seen.expect("just initialized") - RESTART_WINDOW * 2;
        self.occurrences
            .retain(|_, value| value.observed_at >= retention_floor);
        if self.occurrences.len() >= MAX_RESTART_OCCURRENCES {
            return None;
        }
        self.occurrences.insert(occurrence.event_id, occurrence);
        let start = end - RESTART_WINDOW;
        let matching: Vec<_> = self
            .occurrences
            .values()
            .filter(|value| {
                value.scope == scope && value.observed_at >= start && value.observed_at <= end
            })
            .collect();
        let count = matching.iter().map(|value| value.delta).sum();
        if count < RESTART_THRESHOLD_V1 {
            return None;
        }
        let waiting_reason = matching
            .iter()
            .max_by_key(|value| value.observed_at)
            .and_then(|value| value.waiting_reason.clone());
        RestartLoopSummary::new(
            RESTART_PROJECTION_VERSION,
            RESTART_THRESHOLD_V1,
            start,
            end,
            count,
            scope.container_name,
            None,
            waiting_reason,
        )
        .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn correlation_scope() -> CorrelationScope {
        CorrelationScope {
            organization_id: Uuid::from_u128(1),
            project_id: Uuid::from_u128(2),
            application_id: Uuid::from_u128(3),
            workload_uid: "workload".into(),
            pod_uid: "pod".into(),
            container_name: "worker".into(),
            runtime_container_id: "one".into(),
        }
    }

    #[test]
    fn correlation_is_unique_ambiguous_or_absent_and_tenant_safe() {
        let now = Utc::now();
        let lifecycle = CorrelationCandidate {
            event_id: Uuid::new_v4(),
            scope: correlation_scope(),
            observed_at: now,
        };
        let matching = CorrelationCandidate {
            event_id: Uuid::new_v4(),
            scope: correlation_scope(),
            observed_at: now - Duration::seconds(2),
        };
        assert_eq!(
            correlate(&lifecycle, std::slice::from_ref(&matching)),
            CorrelationResult::Unique(matching.event_id)
        );
        assert_eq!(
            correlate(
                &lifecycle,
                &[
                    matching.clone(),
                    CorrelationCandidate {
                        event_id: Uuid::new_v4(),
                        ..matching.clone()
                    }
                ]
            ),
            CorrelationResult::Ambiguous
        );
        let mut other_tenant = matching;
        other_tenant.scope.organization_id = Uuid::new_v4();
        assert_eq!(
            correlate(&lifecycle, &[other_tenant]),
            CorrelationResult::None
        );
    }

    fn restart(scope: &RestartScope, at: DateTime<Utc>, delta: u32) -> RestartOccurrence {
        RestartOccurrence {
            event_id: Uuid::new_v4(),
            scope: scope.clone(),
            observed_at: at,
            delta,
            waiting_reason: Some("CrashLoopBackOff".into()),
        }
    }

    #[test]
    fn projection_is_thresholded_replay_safe_and_lifetime_scoped() {
        let now = Utc::now();
        let scope = RestartScope {
            organization_id: Uuid::from_u128(1),
            project_id: Uuid::from_u128(2),
            application_id: Uuid::from_u128(3),
            pod_uid: "pod".into(),
            container_name: "worker".into(),
            runtime_container_id: "one".into(),
        };
        let mut projector = RestartLoopProjector::default();
        let first = restart(&scope, now, 1);
        assert!(projector.observe(first.clone()).is_none());
        assert!(projector.observe(first).is_none());
        assert!(
            projector
                .observe(restart(&scope, now + Duration::minutes(1), 1))
                .is_none()
        );
        let summary = projector
            .observe(restart(&scope, now + Duration::minutes(2), 1))
            .unwrap();
        assert_eq!(summary.observed_restart_count, 3);
        let mut replacement = scope;
        replacement.runtime_container_id = "two".into();
        assert!(
            projector
                .observe(restart(&replacement, now + Duration::minutes(3), 3))
                .is_some()
        );
    }

    #[test]
    fn delta_jump_and_late_window_are_counted_exactly() {
        let now = Utc::now();
        let scope = RestartScope {
            organization_id: Uuid::from_u128(1),
            project_id: Uuid::from_u128(2),
            application_id: Uuid::from_u128(3),
            pod_uid: "pod".into(),
            container_name: "worker".into(),
            runtime_container_id: "one".into(),
        };
        let mut projector = RestartLoopProjector::default();
        let summary = projector.observe(restart(&scope, now, 3)).unwrap();
        assert_eq!(summary.observed_restart_count, 3);
        assert!(
            projector
                .observe(restart(&scope, now - Duration::minutes(11), 1))
                .is_none()
        );
    }

    #[test]
    fn representative_restart_volume_remains_bounded() {
        let started = std::time::Instant::now();
        let now = Utc::now();
        let mut projector = RestartLoopProjector::default();
        for profile in ["service", "worker", "job", "sidecar"] {
            let scope = RestartScope {
                organization_id: Uuid::from_u128(1),
                project_id: Uuid::from_u128(2),
                application_id: Uuid::from_u128(3),
                pod_uid: profile.into(),
                container_name: profile.into(),
                runtime_container_id: "one".into(),
            };
            for index in 0..250 {
                let at = now + Duration::milliseconds(index);
                let _ = projector.observe(restart(&scope, at, 1));
            }
        }
        assert!(projector.occurrences.len() <= MAX_RESTART_OCCURRENCES);
        eprintln!(
            "projected 1000 representative restarts in {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn controlled_correlation_profile_is_exact_and_bounded() {
        let started = std::time::Instant::now();
        let now = Utc::now();
        let lifecycle = CorrelationCandidate {
            event_id: Uuid::new_v4(),
            scope: correlation_scope(),
            observed_at: now,
        };
        for index in 0..1_000 {
            let candidate = CorrelationCandidate {
                event_id: Uuid::new_v4(),
                scope: correlation_scope(),
                observed_at: now + Duration::milliseconds(i64::from(index % 30_000)),
            };
            assert_eq!(
                correlate(&lifecycle, std::slice::from_ref(&candidate)),
                CorrelationResult::Unique(candidate.event_id)
            );
            let mut replacement = candidate;
            replacement.scope.runtime_container_id = format!("replacement-{index}");
            assert_eq!(
                correlate(&lifecycle, &[replacement]),
                CorrelationResult::None
            );
        }
        eprintln!(
            "classified 2000 controlled correlation fixtures in {:?}",
            started.elapsed()
        );
    }
}
