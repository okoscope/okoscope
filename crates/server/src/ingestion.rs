use crate::repository::events::EventRepository;
use crate::repository::runtime_retention::RuntimeRetentionRepository;
use event_model::{EVENT_SCHEMA_VERSION, EventPayload, RuntimeEvent};
use serde_json::to_value;
use sqlx::{PgPool, Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

use crate::application_credentials::{ApplicationCredentialScope, remains_active};
use crate::auth::SessionScope;
use crate::grouping::{GroupingSource, TrustedGroupingScope, assign_event};
use crate::inventory::project_event;

#[derive(Clone, Copy, Debug)]
pub struct IngestionContext {
    pub scope: SessionScope,
    pub agent_id: Uuid,
}

#[derive(Debug, Error)]
pub enum IngestionError {
    #[error("unsupported event schema version {0}")]
    UnsupportedSchema(u32),
    #[error("event project/application is outside the authenticated tenant")]
    InvalidOwnership,
    #[error("application credential is revoked")]
    RevokedCredential,
    #[error("event cgroup ID exceeds PostgreSQL signed integer range")]
    CgroupOverflow,
    #[error("lifecycle counter exceeds PostgreSQL signed integer range")]
    LifecycleCounterOverflow,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("event payload serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("DNS evidence violates bounded canonical invariants")]
    InvalidDns,
    #[error("termination or lifecycle evidence violates bounded invariants")]
    InvalidTermination,
    #[error("release identity violates bounded canonical invariants")]
    InvalidReleaseIdentity,
}

pub async fn persist_application_batch(
    pool: &PgPool,
    scope: SessionScope,
    credential: ApplicationCredentialScope,
    agent_id: Uuid,
    events: &mut [RuntimeEvent],
) -> Result<u32, IngestionError> {
    Ok(
        persist_application_batch_outcome(pool, scope, credential, agent_id, events)
            .await?
            .0,
    )
}

pub async fn persist_application_batch_outcome(
    pool: &PgPool,
    scope: SessionScope,
    credential: ApplicationCredentialScope,
    agent_id: Uuid,
    events: &mut [RuntimeEvent],
) -> Result<(u32, u32), IngestionError> {
    if credential.organization_id != scope.organization_id {
        return Err(IngestionError::InvalidOwnership);
    }
    let mut tx = pool.begin().await?;
    if !remains_active(&mut tx, credential).await? {
        return Err(IngestionError::RevokedCredential);
    }
    let context = IngestionContext { scope, agent_id };
    let mut accepted = 0_u32;
    let mut expired = 0_u32;
    let closed = crate::runtime_retention::worker::lock_project(
        &mut tx,
        scope.organization_id,
        credential.project_id,
    )
    .await?;
    for event in events {
        if closed.is_some_and(|boundary| event.observed_at < boundary) {
            expired += 1;
            crate::runtime_retention::worker::EXPIRED_ARRIVALS
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            continue;
        }
        event.attribution.project_id = credential.project_id;
        event.attribution.application_id = credential.application_id;
        accepted = accepted.saturating_add(persist_event(&mut tx, context, event).await?);
    }
    tx.commit().await?;
    Ok((accepted, expired))
}

pub async fn persist_batch(
    pool: &PgPool,
    context: IngestionContext,
    events: &[RuntimeEvent],
) -> Result<u32, IngestionError> {
    let mut tx = pool.begin().await?;
    let mut accepted = 0_u32;
    let mut projects: Vec<_> = events
        .iter()
        .map(|event| event.attribution.project_id)
        .collect();
    projects.sort_unstable();
    projects.dedup();
    for project in projects {
        crate::runtime_retention::worker::lock_project(
            &mut tx,
            context.scope.organization_id,
            project,
        )
        .await
        .map_err(|error| {
            if matches!(error, sqlx::Error::RowNotFound) {
                IngestionError::InvalidOwnership
            } else {
                IngestionError::Database(error)
            }
        })?;
    }
    for event in events {
        let closed: Option<chrono::DateTime<chrono::Utc>> =
            RuntimeRetentionRepository::closed_before(&mut *tx, event.attribution.project_id)
                .await?;
        if closed.is_some_and(|boundary| event.observed_at < boundary) {
            continue;
        }
        accepted = accepted.saturating_add(persist_event(&mut tx, context, event).await?);
    }
    tx.commit().await?;
    Ok(accepted)
}

#[allow(clippy::too_many_lines)]
async fn persist_event(
    tx: &mut Transaction<'_, Postgres>,
    context: IngestionContext,
    event: &RuntimeEvent,
) -> Result<u32, IngestionError> {
    validate_dns_event(event)?;
    validate_termination_event(event)?;
    if event.schema_version != EVENT_SCHEMA_VERSION {
        return Err(IngestionError::UnsupportedSchema(event.schema_version));
    }
    let owned = crate::repository::ApplicationRepository::exists(
        &mut **tx,
        context.scope.organization_id,
        event.attribution.project_id,
        event.attribution.application_id,
    )
    .await?;
    if !owned {
        return Err(IngestionError::InvalidOwnership);
    }
    if let EventPayload::ThreadActivityWindow(window) = &event.payload {
        return persist_thread_window(tx, context, event, window).await;
    }
    let release_id = resolve_release(tx, context, event).await?;
    crate::metrics::record_release_attribution(
        event.attribution.release.is_some() || event.attribution.release_identity.is_some(),
        release_id.is_some(),
    );
    if (event.attribution.release.is_some() || event.attribution.release_identity.is_some())
        && release_id.is_none()
    {
        tracing::warn!(application_id=%event.attribution.application_id, "runtime event release attribution unresolved");
    }
    let cgroup_id =
        i64::try_from(event.process.cgroup_id).map_err(|_| IngestionError::CgroupOverflow)?;
    let raw_event_id = Uuid::new_v4();
    let inserted: Option<Uuid> = EventRepository::insert(
        &mut **tx,
        raw_event_id,
        event.id,
        context.scope.organization_id,
        event.attribution.project_id,
        context.scope.cluster_id,
        event.attribution.application_id,
        context.agent_id,
        release_id,
        event.observed_at,
        &event.attribution.node_name,
        &event.attribution.namespace,
        &event.attribution.pod_uid,
        &event.attribution.pod_name,
        &event.attribution.container_id,
        &event.attribution.container_name,
        &event.attribution.workload_uid,
        &event.attribution.workload_kind,
        &event.attribution.workload_name,
        cgroup_id,
        i64::from(event.process.pid),
        i64::from(event.process.tgid),
        &event.process.command,
        event.kind(),
        i32::try_from(event.schema_version).unwrap_or(i32::MAX),
        to_value(&event.payload)?,
    )
    .await?;
    let Some(raw_event_id) = inserted else {
        crate::metrics::record_duplicate_event();
        return Ok(0);
    };
    let scope = TrustedGroupingScope {
        organization_id: context.scope.organization_id,
        project_id: event.attribution.project_id,
        application_id: event.attribution.application_id,
        cluster_id: context.scope.cluster_id,
        namespace: &event.attribution.namespace,
        workload_kind: &event.attribution.workload_kind,
        workload_name: &event.attribution.workload_name,
    };
    let grouping = assign_event(
        tx,
        raw_event_id,
        release_id,
        &scope,
        event,
        GroupingSource::Live,
    )
    .await?;
    let inventory = project_event(
        tx,
        raw_event_id,
        grouping.group_id,
        release_id,
        context.scope.cluster_id,
        context.scope.organization_id,
        event,
    )
    .await?;
    crate::policy_projection::project_current_evaluation(
        tx,
        context.scope.organization_id,
        context.scope.cluster_id,
        grouping.group_id,
        inventory.item_id,
        event,
    )
    .await?;
    crate::termination_projection::project_durable_evidence(
        tx,
        raw_event_id,
        context.scope.organization_id,
        context.scope.cluster_id,
        event,
    )
    .await?;
    record_event_metrics(event, grouping.group_created);
    Ok(1)
}

async fn persist_thread_window(
    tx: &mut Transaction<'_, Postgres>,
    context: IngestionContext,
    event: &RuntimeEvent,
    window: &event_model::ThreadActivityWindow,
) -> Result<u32, IngestionError> {
    window
        .validate()
        .map_err(|_| IngestionError::InvalidTermination)?;
    let signed =
        |value: u64| i64::try_from(value).map_err(|_| IngestionError::LifecycleCounterOverflow);
    let cgroup_id = signed(event.process.cgroup_id)?;
    let inserted = crate::repository::thread_activity::ThreadActivityRepository::insert(
        &mut **tx,
        crate::repository::thread_activity::NewWindow {
            id: window.id,
            organization_id: context.scope.organization_id,
            project_id: event.attribution.project_id,
            application_id: event.attribution.application_id,
            cluster_id: context.scope.cluster_id,
            agent_id: context.agent_id,
            observed_at: event.observed_at,
            process_cgroup_id: cgroup_id,
            process_pid: i64::from(event.process.pid),
            process_tgid: i64::from(event.process.tgid),
            process_command: &event.process.command,
            process_generation: signed(window.generation.generation)?,
            observation_epoch: window.generation.observation_epoch,
            start_observed: window.generation.start_observed,
            window_started_at: window.window_started_at,
            window_ended_at: window.window_ended_at,
            created_count: signed(window.created)?,
            exited_count: signed(window.exited)?,
            active_at_start: signed(window.active_at_start)?,
            active_at_end: signed(window.active_at_end)?,
            peak_active: signed(window.peak_active)?,
            baseline_provenance: match window.baseline_provenance {
                event_model::BaselineProvenance::Observed => "observed",
                event_model::BaselineProvenance::Snapshot => "snapshot",
                event_model::BaselineProvenance::Unavailable => "unavailable",
            },
            baseline_complete: window.baseline_complete,
            name_overflow: signed(window.name_overflow)?,
            names: to_value(&window.names)?,
            gaps: to_value(&window.gaps)?,
        },
    )
    .await?;
    if inserted.is_none() {
        crate::metrics::record_duplicate_event();
    }
    Ok(u32::from(inserted.is_some()))
}

fn record_event_metrics(event: &RuntimeEvent, group_created: bool) {
    if matches!(&event.payload, EventPayload::NetworkConnect(_)) {
        crate::metrics::record_network_event(group_created);
        if matches!(&event.payload, EventPayload::NetworkConnect(connect) if connect.dns_context.as_ref().is_some_and(|context| context.ambiguous))
        {
            crate::metrics::record_dns_ambiguous_context();
        }
        tracing::debug!(
            outcome = "accepted",
            group_created = group_created,
            "network connect event ingested"
        );
    }
    if matches!(
        &event.payload,
        EventPayload::NetworkListen(_) | EventPayload::NetworkAccept(_)
    ) {
        crate::metrics::record_inbound_event(
            matches!(&event.payload, EventPayload::NetworkAccept(_)),
            group_created,
        );
        tracing::debug!(
            outcome = "accepted",
            group_created = group_created,
            "inbound network event ingested"
        );
    }
    if matches!(
        &event.payload,
        EventPayload::NetworkDnsQuery(_) | EventPayload::NetworkDnsResponse(_)
    ) {
        crate::metrics::record_dns_event(group_created);
        tracing::debug!(
            outcome = "accepted",
            group_created = group_created,
            "DNS event ingested"
        );
    }
    if matches!(
        &event.payload,
        EventPayload::FileCreate(_)
            | EventPayload::FileModify(_)
            | EventPayload::FileDelete(_)
            | EventPayload::FileRename(_)
    ) {
        crate::metrics::record_file_event(group_created);
        tracing::debug!(
            outcome = "accepted",
            group_created = group_created,
            "file activity event ingested"
        );
    }
}

async fn resolve_release(
    tx: &mut Transaction<'_, Postgres>,
    context: IngestionContext,
    event: &RuntimeEvent,
) -> Result<Option<Uuid>, IngestionError> {
    if let Some(identity) = &event.attribution.release_identity {
        identity
            .validate()
            .map_err(|_| IngestionError::InvalidReleaseIdentity)?;
        let release_id = crate::release_discovery::resolve_observed_release(
            tx,
            context.scope.organization_id,
            event.attribution.project_id,
            event.attribution.application_id,
            identity,
            event.observed_at,
        )
        .await?;
        tracing::debug!(application_id=%event.attribution.application_id, release_id=%release_id, source="observed", "runtime event release attribution resolved");
        return Ok(Some(release_id));
    }
    let Some(version) = event.attribution.release.as_deref() else {
        return Ok(None);
    };
    Ok(crate::repository::ReleaseRepository::id_by_version(
        &mut **tx,
        crate::repository::ApplicationScope {
            organization_id: context.scope.organization_id,
            project_id: event.attribution.project_id,
            application_id: event.attribution.application_id,
        },
        version,
    )
    .await?)
}

fn validate_dns_event(event: &RuntimeEvent) -> Result<(), IngestionError> {
    let valid = match &event.payload {
        EventPayload::NetworkDnsResponse(response) => response.validate().is_ok(),
        EventPayload::NetworkConnect(connect) => connect
            .dns_context
            .as_ref()
            .is_none_or(|context| context.validate().is_ok()),
        EventPayload::ProcessStart(_)
        | EventPayload::ThreadActivityWindow(_)
        | EventPayload::ProcessExec(_)
        | EventPayload::Syscall(_)
        | EventPayload::NetworkListen(_)
        | EventPayload::NetworkAccept(_)
        | EventPayload::NetworkDnsQuery(_)
        | EventPayload::FileCreate(_)
        | EventPayload::FileModify(_)
        | EventPayload::FileDelete(_)
        | EventPayload::FileRename(_)
        | EventPayload::ProcessExit(_)
        | EventPayload::ContainerTermination(_)
        | EventPayload::ContainerRestart(_) => true,
    };
    valid.then_some(()).ok_or(IngestionError::InvalidDns)
}

fn validate_termination_event(event: &RuntimeEvent) -> Result<(), IngestionError> {
    use event_model::{EvidenceSource, GenerationCorrelation, ProcessTermination};

    let valid = match &event.payload {
        EventPayload::ProcessStart(value) => {
            value.validate().is_ok()
                && event.process.pid > 0
                && event.process.pid == event.process.tgid
                && !event.process.command.is_empty()
                && event.process.command.len() <= event_model::MAX_THREAD_NAME_BYTES
        }
        EventPayload::ProcessExec(value) => value
            .generation
            .as_ref()
            .is_none_or(|generation| generation.validate().is_ok()),
        EventPayload::ThreadActivityWindow(value) => {
            value.validate().is_ok()
                && value.process == event.process
                && value.id == event.id
                && event.observed_at >= value.window_ended_at
        }
        EventPayload::ProcessExit(value) => {
            let termination_valid = match &value.termination {
                ProcessTermination::Exited { status } => {
                    value.raw_wait_status == i32::from(*status) << 8
                }
                ProcessTermination::Signaled {
                    signal,
                    signal_name,
                    core_dump_flag,
                } => {
                    ProcessTermination::signaled(*signal, signal_name.clone(), *core_dump_flag)
                        .is_ok()
                        && value.raw_wait_status
                            == i32::from(*signal) | if *core_dump_flag { 0x80 } else { 0 }
                }
            };
            let correlation_valid = match &value.correlation {
                GenerationCorrelation::Observed {
                    generation,
                    executable,
                    ..
                } => {
                    *generation > 0
                        && !executable.is_empty()
                        && executable.len() <= event_model::MAX_TERMINATION_TEXT_BYTES
                }
                GenerationCorrelation::Unresolved { .. } => true,
            };
            value.source == EvidenceSource::Kernel
                && termination_valid
                && correlation_valid
                && value
                    .generation
                    .as_ref()
                    .is_none_or(|generation| generation.validate().is_ok())
                && (value.classification != event_model::ProcessExitClassification::Leader
                    || (event.process.pid > 0 && event.process.pid == event.process.tgid))
        }
        EventPayload::ContainerTermination(value) => event_model::ContainerTermination::new(
            value.runtime_container_id.clone(),
            value.reason.clone(),
            value.exit_code,
            value.started_at,
            value.finished_at,
        )
        .is_ok_and(|validated| validated == *value),
        EventPayload::ContainerRestart(value) => event_model::ContainerRestart::new(
            value.runtime_container_id.clone(),
            value.restart_count,
            value.restart_delta,
            value.previous_termination.clone(),
            value.waiting_reason.clone(),
        )
        .is_ok_and(|validated| validated == *value),
        _ => true,
    };
    valid
        .then_some(())
        .ok_or(IngestionError::InvalidTermination)
}

#[cfg(test)]
mod termination_tests {
    use super::*;
    use chrono::Utc;
    use event_model::{
        EvidenceSource, GenerationCorrelation, KubernetesAttribution, ProcessExit, ProcessIdentity,
        ProcessTermination, UnresolvedGenerationReason,
    };

    #[test]
    fn process_start_rejects_nonleader_and_zero_process_identity() {
        let start = event_model::ProcessStart {
            generation: event_model::ProcessGenerationIdentity {
                generation: 1,
                observation_epoch: Uuid::new_v4(),
                start_observed: true,
            },
            parent_pid: 1,
            parent_tgid: 1,
            parent_command: "parent".into(),
        };
        let mut value = event(EventPayload::ProcessStart(start));
        assert!(validate_termination_event(&value).is_ok());
        value.process.pid = 3;
        assert!(validate_termination_event(&value).is_err());
        value.process.pid = 0;
        value.process.tgid = 0;
        assert!(validate_termination_event(&value).is_err());
    }

    fn event(payload: EventPayload) -> RuntimeEvent {
        RuntimeEvent {
            id: Uuid::new_v4(),
            observed_at: Utc::now(),
            schema_version: EVENT_SCHEMA_VERSION,
            attribution: KubernetesAttribution {
                project_id: Uuid::new_v4(),
                application_id: Uuid::new_v4(),
                node_name: "node".into(),
                namespace: "default".into(),
                pod_uid: "pod".into(),
                pod_name: "pod".into(),
                container_id: "abc".into(),
                container_name: "worker".into(),
                workload_uid: "workload".into(),
                workload_kind: "Deployment".into(),
                workload_name: "worker".into(),
                release: None,
                release_identity: None,
            },
            process: ProcessIdentity {
                cgroup_id: 1,
                pid: 2,
                tgid: 2,
                command: "worker".into(),
            },
            payload,
        }
    }

    #[test]
    fn validates_native_variants_and_rejects_contradictions() {
        let valid = event(EventPayload::ProcessExit(ProcessExit::new(
            0x8b,
            ProcessTermination::signaled(11, "SIGSEGV", true).unwrap(),
            GenerationCorrelation::Unresolved {
                reason: UnresolvedGenerationReason::BeforeObservation,
            },
        )));
        assert!(validate_termination_event(&valid).is_ok());
        let mut invalid = valid;
        if let EventPayload::ProcessExit(exit) = &mut invalid.payload {
            exit.raw_wait_status = 11;
        }
        assert!(matches!(
            validate_termination_event(&invalid),
            Err(IngestionError::InvalidTermination)
        ));
        if let EventPayload::ProcessExit(exit) = &mut invalid.payload {
            exit.raw_wait_status = 0x8b;
            exit.source = EvidenceSource::Kubernetes;
        }
        assert!(matches!(
            validate_termination_event(&invalid),
            Err(IngestionError::InvalidTermination)
        ));
    }

    #[test]
    fn rejects_invalid_lifecycle_delta_after_deserialization() {
        let mut restart = event_model::ContainerRestart::new("abc", 3, 1, None, None).unwrap();
        restart.restart_delta = 0;
        let invalid = event(EventPayload::ContainerRestart(restart));
        assert!(matches!(
            validate_termination_event(&invalid),
            Err(IngestionError::InvalidTermination)
        ));
    }
}
