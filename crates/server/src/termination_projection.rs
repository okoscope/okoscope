use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use event_model::RestartLoopSummary;
use event_model::{ContainerRestart, EventPayload, RuntimeEvent};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::inventory::CURRENT_INVENTORY_IDENTITY_VERSION;

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
    let candidates: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM runtime_events WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND workload_uid=$4 AND pod_uid=$5 AND container_name=$6 AND container_id=$7 AND event_kind='process.exit' AND observed_at BETWEEN $8-$9::interval AND $8+$9::interval ORDER BY observed_at,id LIMIT 2",
    )
    .bind(organization_id)
    .bind(event.attribution.project_id)
    .bind(event.attribution.application_id)
    .bind(&event.attribution.workload_uid)
    .bind(&event.attribution.pod_uid)
    .bind(&event.attribution.container_name)
    .bind(&event.attribution.container_id)
    .bind(event.observed_at)
    .bind(format!("{} seconds", CORRELATION_TOLERANCE.num_seconds()))
    .fetch_all(&mut **tx)
    .await?;
    let status = match candidates.len() {
        0 => "absent",
        1 => "qualified",
        _ => "ambiguous",
    };
    sqlx::query("INSERT INTO runtime_event_correlation_outcomes (organization_id,project_id,event_id,status,candidate_count,tolerance_seconds) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (event_id) DO UPDATE SET status=EXCLUDED.status,candidate_count=EXCLUDED.candidate_count,tolerance_seconds=EXCLUDED.tolerance_seconds,updated_at=now()")
        .bind(organization_id).bind(event.attribution.project_id).bind(lifecycle_event_id).bind(status)
        .bind(i32::try_from(candidates.len()).unwrap_or(i32::MAX))
        .bind(i32::try_from(CORRELATION_TOLERANCE.num_seconds()).unwrap_or(i32::MAX))
        .execute(&mut **tx).await?;
    if let [kernel_event_id] = candidates.as_slice() {
        sqlx::query("INSERT INTO runtime_event_correlations (organization_id,project_id,lifecycle_event_id,kernel_event_id,correlation_kind) VALUES ($1,$2,$3,$4,'qualified') ON CONFLICT DO NOTHING")
            .bind(organization_id)
            .bind(event.attribution.project_id)
            .bind(lifecycle_event_id)
            .bind(kernel_event_id)
            .execute(&mut **tx)
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
    let inserted = sqlx::query("INSERT INTO runtime_restart_projection_memberships (organization_id,project_id,projection_version,event_id,window_started_at,window_ended_at,restart_delta) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING")
        .bind(organization_id).bind(event.attribution.project_id).bind(version).bind(raw_event_id)
        .bind(window_start).bind(event.observed_at).bind(delta).execute(&mut **tx).await?;
    if inserted.rows_affected() == 0 {
        return Ok(());
    }
    let projection_end: DateTime<Utc> = sqlx::query_scalar(
        "SELECT COALESCE(max(e.observed_at),$9) FROM runtime_restart_projection_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE m.organization_id=$1 AND m.project_id=$2 AND e.application_id=$3 AND e.cluster_id=$4 AND e.pod_uid=$5 AND e.container_name=$6 AND e.container_id=$7 AND m.projection_version=$8 AND e.observed_at BETWEEN $9 AND $10",
    )
    .bind(organization_id).bind(event.attribution.project_id).bind(event.attribution.application_id)
    .bind(cluster_id).bind(&event.attribution.pod_uid).bind(&event.attribution.container_name)
    .bind(&event.attribution.container_id).bind(version).bind(event.observed_at)
    .bind(event.observed_at + RESTART_WINDOW).fetch_one(&mut **tx).await?;
    let projection_start = projection_end - RESTART_WINDOW;
    let count: i64 = sqlx::query_scalar(
        "SELECT COALESCE(sum(m.restart_delta),0)::bigint FROM runtime_restart_projection_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE m.organization_id=$1 AND m.project_id=$2 AND e.application_id=$3 AND e.cluster_id=$4 AND e.pod_uid=$5 AND e.container_name=$6 AND e.container_id=$7 AND m.projection_version=$8 AND e.observed_at BETWEEN $9 AND $10",
    )
    .bind(organization_id).bind(event.attribution.project_id).bind(event.attribution.application_id)
    .bind(cluster_id).bind(&event.attribution.pod_uid).bind(&event.attribution.container_name)
    .bind(&event.attribution.container_id).bind(version).bind(projection_start).bind(projection_end)
    .fetch_one(&mut **tx).await?;
    let observed_count = i32::try_from(count).unwrap_or(i32::MAX);
    sqlx::query("INSERT INTO runtime_restart_loop_projections (organization_id,project_id,application_id,cluster_id,pod_uid,container_name,runtime_container_id,projection_version,window_started_at,window_ended_at,observed_restart_count,latest_termination,latest_waiting_reason) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT (organization_id,project_id,application_id,cluster_id,pod_uid,container_name,runtime_container_id,projection_version) DO UPDATE SET window_started_at=EXCLUDED.window_started_at,window_ended_at=EXCLUDED.window_ended_at,observed_restart_count=EXCLUDED.observed_restart_count,latest_termination=COALESCE(EXCLUDED.latest_termination,runtime_restart_loop_projections.latest_termination),latest_waiting_reason=COALESCE(EXCLUDED.latest_waiting_reason,runtime_restart_loop_projections.latest_waiting_reason),updated_at=now()")
        .bind(organization_id).bind(event.attribution.project_id).bind(event.attribution.application_id)
        .bind(cluster_id).bind(&event.attribution.pod_uid).bind(&event.attribution.container_name)
        .bind(&event.attribution.container_id).bind(version).bind(projection_start).bind(projection_end)
        .bind(observed_count).bind(restart.previous_termination.as_ref().map(serde_json::to_value).transpose().map_err(|error| sqlx::Error::Protocol(error.to_string()))?)
        .bind(&restart.waiting_reason).execute(&mut **tx).await?;
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
    let group_id: Uuid = sqlx::query_scalar("INSERT INTO runtime_event_groups (id,organization_id,project_id,cluster_id,application_id,namespace,workload_kind,workload_name,fingerprint_version,fingerprint_digest,event_kind,semantic_summary,first_seen_at,last_seen_at,occurrence_count,representative_event_id,first_seen_event_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'container.restart_loop',$11,$12,$12,1,$13,$13) ON CONFLICT (organization_id,project_id,application_id,cluster_id,namespace,workload_kind,workload_name,fingerprint_version,fingerprint_digest) DO UPDATE SET semantic_summary=EXCLUDED.semantic_summary,last_seen_at=GREATEST(runtime_event_groups.last_seen_at,EXCLUDED.last_seen_at),representative_event_id=EXCLUDED.representative_event_id,updated_at=now() RETURNING id")
        .bind(candidate).bind(organization_id).bind(event.attribution.project_id).bind(cluster_id)
        .bind(event.attribution.application_id).bind(&event.attribution.namespace).bind(&event.attribution.workload_kind)
        .bind(&event.attribution.workload_name).bind(DERIVED_GROUP_FINGERPRINT_VERSION).bind(digest.as_slice())
        .bind(&summary).bind(event.observed_at).bind(raw_event_id).fetch_one(&mut **tx).await?;
    if group_id == candidate {
        sqlx::query("INSERT INTO outbox_messages (id,organization_id,project_id,topic,aggregate_id,schema_version,source,payload) VALUES ($1,$2,$3,'runtime_group.first_seen',$4,1,'live',$5) ON CONFLICT (topic,aggregate_id,schema_version) DO NOTHING")
            .bind(Uuid::new_v4())
            .bind(organization_id)
            .bind(event.attribution.project_id)
            .bind(group_id)
            .bind(json!({
                "group_id": group_id,
                "application_id": event.attribution.application_id,
                "event_kind": "container.restart_loop",
                "semantic": summary,
                "fingerprint_version": DERIVED_GROUP_FINGERPRINT_VERSION,
            }))
            .execute(&mut **tx)
            .await?;
    }
    let membership = sqlx::query("INSERT INTO runtime_event_group_memberships (organization_id,project_id,application_id,event_id,group_id,fingerprint_version) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING")
        .bind(organization_id).bind(event.attribution.project_id).bind(event.attribution.application_id)
        .bind(raw_event_id).bind(group_id).bind(DERIVED_GROUP_FINGERPRINT_VERSION).execute(&mut **tx).await?;
    if membership.rows_affected() > 0 && group_id != candidate {
        sqlx::query(
            "UPDATE runtime_event_groups SET occurrence_count=occurrence_count+1 WHERE id=$1",
        )
        .bind(group_id)
        .execute(&mut **tx)
        .await?;
    }
    sqlx::query("INSERT INTO runtime_inventory_group_links (organization_id,project_id,application_id,item_id,group_id) SELECT $1,$2,$3,m.item_id,$4 FROM runtime_inventory_event_memberships m WHERE m.organization_id=$1 AND m.project_id=$2 AND m.application_id=$3 AND m.event_id=$5 AND m.identity_version=$6 ON CONFLICT (item_id,group_id) DO NOTHING")
        .bind(organization_id)
        .bind(event.attribution.project_id)
        .bind(event.attribution.application_id)
        .bind(group_id)
        .bind(raw_event_id)
        .bind(CURRENT_INVENTORY_IDENTITY_VERSION.get())
        .execute(&mut **tx)
        .await?;
    sqlx::query("UPDATE runtime_restart_loop_projections SET group_id=$1 WHERE organization_id=$2 AND project_id=$3 AND application_id=$4 AND cluster_id=$5 AND pod_uid=$6 AND container_name=$7 AND runtime_container_id=$8 AND projection_version=$9")
        .bind(group_id).bind(organization_id).bind(event.attribution.project_id).bind(event.attribution.application_id)
        .bind(cluster_id).bind(&event.attribution.pod_uid).bind(&event.attribution.container_name)
        .bind(&event.attribution.container_id).bind(i16::try_from(RESTART_PROJECTION_VERSION).unwrap_or(i16::MAX)).execute(&mut **tx).await?;
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
