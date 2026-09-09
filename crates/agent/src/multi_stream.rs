use std::{collections::BTreeMap, sync::Arc, time::Duration};

use chrono::Utc;
use event_model::{ResourceAggregate, RuntimeEvent};
use protocol::v1::{AgentHello, AgentMessage, Heartbeat, agent_message, server_message};
use tokio::sync::{mpsc, watch};
use uuid::Uuid;

use crate::{
    attribution::{KubernetesWatchState, ReleaseObservation},
    config::{LoadedApplicationCredential, ResourceObservationConfig, SafetyLimits, ServerConfig},
    counters::Counters,
    delivery::EventBuffer,
    session::{connect_with_backoff, handle_control},
};

#[derive(Clone, Debug)]
enum StreamItem {
    Event(Box<RuntimeEvent>),
    Release(Box<ReleaseObservation>),
    Resource(Box<ResourceAggregate>),
}

#[derive(Debug)]
pub struct ApplicationStreams {
    routes: BTreeMap<Uuid, mpsc::Sender<StreamItem>>,
    shutdown: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    counters: Arc<Counters>,
}

impl ApplicationStreams {
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        server: &ServerConfig,
        credentials: Vec<LoadedApplicationCredential>,
        hello: &AgentHello,
        safety: &SafetyLimits,
        resources: &ResourceObservationConfig,
        counters: Arc<Counters>,
        watch_ready: &watch::Receiver<KubernetesWatchState>,
        kernel_degraded: bool,
    ) -> Self {
        let (shutdown, _) = watch::channel(false);
        let mut routes = BTreeMap::new();
        let mut tasks = Vec::with_capacity(credentials.len());
        for credential in credentials {
            let (sender, receiver) = mpsc::channel(safety.queue_capacity);
            routes.insert(credential.route_id, sender);
            tasks.push(tokio::spawn(run_stream(
                server.clone(),
                credential,
                hello.clone(),
                safety.queue_capacity,
                safety.batch_size,
                resources.queue_capacity,
                resources.batch_size,
                receiver,
                shutdown.subscribe(),
                counters.clone(),
                watch_ready.clone(),
                kernel_degraded,
            )));
        }
        Self {
            routes,
            shutdown,
            tasks,
            counters,
        }
    }

    pub fn route(&self, event: RuntimeEvent) -> bool {
        let route_id = event.attribution.application_id;
        let Some(sender) = self.routes.get(&route_id) else {
            self.counters
                .unattributed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return false;
        };
        match sender.try_send(StreamItem::Event(Box::new(event))) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.counters
                    .capacity_dropped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    pub fn route_release_observation(&self, observation: ReleaseObservation) -> bool {
        let route_id = match &observation {
            ReleaseObservation::Evidence { route_id, .. }
            | ReleaseObservation::Snapshot { route_id, .. } => *route_id,
        };
        let Some(sender) = self.routes.get(&route_id) else {
            self.counters
                .release_evidence_dropped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return false;
        };
        if sender
            .try_send(StreamItem::Release(Box::new(observation)))
            .is_ok()
        {
            self.counters
                .release_evidence_sent
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            true
        } else {
            self.counters
                .release_evidence_dropped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            false
        }
    }

    pub fn route_resource(&self, route_id: Uuid, aggregate: ResourceAggregate) -> bool {
        let Some(sender) = self.routes.get(&route_id) else {
            self.counters
                .resource_attribution_failed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return false;
        };
        if sender
            .try_send(StreamItem::Resource(Box::new(aggregate)))
            .is_ok()
        {
            true
        } else {
            self.counters
                .resource_queue_dropped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            false
        }
    }

    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        for task in self.tasks {
            let _ = task.await;
        }
    }

    pub fn route_count(&self) -> usize {
        self.routes.len()
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_stream(
    server: ServerConfig,
    credential: LoadedApplicationCredential,
    hello: AgentHello,
    queue_capacity: usize,
    batch_size: usize,
    resource_queue_capacity: usize,
    resource_batch_size: usize,
    mut receiver: mpsc::Receiver<StreamItem>,
    mut shutdown: watch::Receiver<bool>,
    counters: Arc<Counters>,
    watch_ready: watch::Receiver<KubernetesWatchState>,
    kernel_degraded: bool,
) {
    let mut buffer = EventBuffer::new(queue_capacity, batch_size);
    let mut release_pending = BTreeMap::<String, ReleaseObservation>::new();
    let mut resource_queued = Vec::<ResourceAggregate>::new();
    let mut resource_pending = BTreeMap::<u64, Vec<ResourceAggregate>>::new();
    let mut resource_sequence = 1_u64;
    loop {
        if *shutdown.borrow() {
            return;
        }
        let session = connect_with_backoff(&server, credential.token.trim(), hello.clone()).await;
        let mut session = match session {
            Ok(session) => session,
            Err(error) => {
                tracing::warn!(
                    route_id=%credential.route_id,
                    credential_path=%credential.canonical_path,
                    %error,
                    "Application stream connection failed"
                );
                continue;
            }
        };
        for batch in buffer.replay_pending(&counters) {
            if send_batch(&session.sender, batch).await.is_err() {
                break;
            }
        }
        let _ = replay_resource_batches(&session.sender, &resource_pending, &counters).await;
        let mut flush = tokio::time::interval(Duration::from_millis(10));
        let mut heartbeat = tokio::time::interval(Duration::from_secs(30));
        let mut release_dirty = true;
        loop {
            tokio::select! {
                item = receiver.recv() => {
                    let Some(item) = item else { return };
                    buffer_stream_item(item, &mut buffer, &mut release_pending,
                        &mut resource_queued, queue_capacity, resource_queue_capacity,
                        &mut release_dirty, &counters);
                }
                _ = flush.tick() => {
                    flush_release_observations(&session.sender, &release_pending,
                        &mut release_dirty, &counters).await;
                    if let Some(batch) = buffer.next_batch(&counters)
                        && send_batch(&session.sender, batch).await.is_err()
                    {
                        break;
                    }
                    if flush_resource_queue(
                        &session.sender, &mut resource_queued, &mut resource_pending,
                        &mut resource_sequence, resource_queue_capacity, resource_batch_size,
                        &counters,
                    ).await.is_err() { break; }
                }
                _ = heartbeat.tick() => {
                    let message = AgentMessage {
                        protocol_version: event_model::PROTOCOL_VERSION,
                        message: Some(agent_message::Message::Heartbeat(Heartbeat {
                            sent_at_unix_nanos: Utc::now().timestamp_nanos_opt().unwrap_or_default(),
                            drop_counters: Some(counters.snapshot().into()),
                            resource_counters: Some(counters.resource_snapshot()),
                        })),
                    };
                    if session.sender.send(message).await.is_err() { break; }
                    let selector_matched = !release_pending.is_empty();
                    let kubernetes_watch_state = *watch_ready.borrow();
                    if session.sender.send(onboarding_heartbeat(
                        kubernetes_watch_state, selector_matched, kernel_degraded,
                    )).await.is_err() { break; }
                }
                incoming = session.incoming.message() => {
                    match incoming {
                        Ok(Some(message)) => if handle_server_message(
                            message, &mut buffer, &mut resource_pending, &counters,
                            credential.route_id, &session.sender,
                        ).await.is_err() { break; },
                        Ok(None) => {
                            tracing::warn!(route_id=%credential.route_id, "server closed Application stream");
                            break;
                        }
                        Err(error) => {
                            tracing::warn!(route_id=%credential.route_id, %error, "Application stream receive failed");
                            break;
                        }
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { return; }
                }
            }
        }
        tracing::warn!(route_id=%credential.route_id, "Application stream disconnected; reconnecting");
    }
}

async fn replay_resource_batches(
    sender: &mpsc::Sender<AgentMessage>,
    pending: &BTreeMap<u64, Vec<ResourceAggregate>>,
    counters: &Counters,
) -> Result<(), mpsc::error::SendError<AgentMessage>> {
    for (&sequence, aggregates) in pending {
        counters.resource_retried.fetch_add(
            aggregates.len() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        send_resource_batch(sender, sequence, aggregates.clone()).await?;
    }
    Ok(())
}

async fn flush_resource_queue(
    sender: &mpsc::Sender<AgentMessage>,
    queued: &mut Vec<ResourceAggregate>,
    pending: &mut BTreeMap<u64, Vec<ResourceAggregate>>,
    sequence: &mut u64,
    capacity: usize,
    batch_size: usize,
    counters: &Counters,
) -> Result<(), mpsc::error::SendError<AgentMessage>> {
    if queued.is_empty() {
        return Ok(());
    }
    let pending_count = pending.values().map(Vec::len).sum::<usize>();
    let available = capacity.saturating_sub(pending_count);
    if available == 0 {
        counters
            .resource_queue_dropped
            .fetch_add(queued.len() as u64, std::sync::atomic::Ordering::Relaxed);
        queued.clear();
        return Ok(());
    }
    let split_at = queued.len().min(batch_size).min(available);
    let aggregates = queued.drain(..split_at).collect::<Vec<_>>();
    pending.insert(*sequence, aggregates.clone());
    send_resource_batch(sender, *sequence, aggregates).await?;
    *sequence = sequence.saturating_add(1);
    Ok(())
}

async fn handle_server_message(
    message: protocol::v1::ServerMessage,
    buffer: &mut EventBuffer,
    resource_pending: &mut BTreeMap<u64, Vec<ResourceAggregate>>,
    counters: &Counters,
    route_id: Uuid,
    sender: &mpsc::Sender<AgentMessage>,
) -> Result<(), mpsc::error::SendError<AgentMessage>> {
    match message.message {
        Some(server_message::Message::BatchAcknowledgement(ack)) => {
            acknowledge_batch(buffer, counters, &ack);
        }
        Some(server_message::Message::ResourceBatchAcknowledgement(ack)) => {
            if let Some(values) = resource_pending.remove(&ack.sequence) {
                counters
                    .resource_acknowledged
                    .fetch_add(values.len() as u64, std::sync::atomic::Ordering::Relaxed);
                counters.resource_expired.fetch_add(
                    u64::from(ack.retention_expired_aggregates),
                    std::sync::atomic::Ordering::Relaxed,
                );
            }
        }
        Some(server_message::Message::Control(control)) => {
            sender
                .send(AgentMessage {
                    protocol_version: event_model::PROTOCOL_VERSION,
                    message: Some(agent_message::Message::ControlResult(handle_control(
                        control,
                    ))),
                })
                .await?;
        }
        Some(server_message::Message::SessionAccepted(accepted)) => {
            tracing::info!(
                %route_id,
                application_id=%accepted.application_id,
                cluster_id=%accepted.cluster_id,
                "Application stream accepted"
            );
        }
        None => tracing::warn!(%route_id, "unsupported server message"),
    }
    Ok(())
}

fn onboarding_heartbeat(
    watch_state: KubernetesWatchState,
    selector_matched: bool,
    kernel_degraded: bool,
) -> AgentMessage {
    use protocol::v1::{OnboardingReason, OnboardingState};
    let (state, reason) = if kernel_degraded {
        (
            OnboardingState::KernelUnsupported,
            OnboardingReason::EbpfUnavailable,
        )
    } else if watch_state == KubernetesWatchState::PermissionDenied {
        (
            OnboardingState::PermissionDenied,
            OnboardingReason::KubernetesWatchForbidden,
        )
    } else if watch_state == KubernetesWatchState::Ready && !selector_matched {
        (
            OnboardingState::WorkloadNotMatched,
            OnboardingReason::SelectorNoMatch,
        )
    } else if selector_matched {
        (
            OnboardingState::WaitingForEvent,
            OnboardingReason::EventNotObserved,
        )
    } else {
        (
            OnboardingState::AgentAuthenticated,
            OnboardingReason::Unspecified,
        )
    };
    AgentMessage {
        protocol_version: event_model::PROTOCOL_VERSION,
        message: Some(agent_message::Message::OnboardingStatus(
            protocol::v1::OnboardingStatus {
                observed_at_unix_nanos: Utc::now().timestamp_nanos_opt().unwrap_or_default(),
                state: state.into(),
                reason: reason.into(),
            },
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn buffer_stream_item(
    item: StreamItem,
    buffer: &mut EventBuffer,
    release_pending: &mut BTreeMap<String, ReleaseObservation>,
    resource_queued: &mut Vec<ResourceAggregate>,
    queue_capacity: usize,
    resource_queue_capacity: usize,
    release_dirty: &mut bool,
    counters: &Counters,
) {
    match item {
        StreamItem::Event(event) => {
            buffer.push(*event, counters);
        }
        StreamItem::Release(observation) => {
            let observation = *observation;
            let key = release_observation_key(&observation);
            if release_pending.contains_key(&key) {
                counters
                    .release_evidence_duplicate
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            if release_pending.len() < queue_capacity || release_pending.contains_key(&key) {
                release_pending.insert(key, observation);
                *release_dirty = true;
            } else {
                counters
                    .release_evidence_dropped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        StreamItem::Resource(aggregate) => {
            if resource_queued.len() < resource_queue_capacity {
                resource_queued.push(*aggregate);
            } else {
                counters
                    .resource_queue_dropped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

async fn send_resource_batch(
    sender: &mpsc::Sender<AgentMessage>,
    sequence: u64,
    aggregates: Vec<ResourceAggregate>,
) -> Result<(), mpsc::error::SendError<AgentMessage>> {
    sender
        .send(AgentMessage {
            protocol_version: event_model::PROTOCOL_VERSION,
            message: Some(agent_message::Message::ResourceSampleBatch(
                protocol::v1::ResourceSampleBatch {
                    sequence,
                    aggregates: aggregates.into_iter().map(Into::into).collect(),
                },
            )),
        })
        .await
}

async fn flush_release_observations(
    sender: &mpsc::Sender<AgentMessage>,
    pending: &BTreeMap<String, ReleaseObservation>,
    dirty: &mut bool,
    counters: &Counters,
) {
    if !*dirty {
        return;
    }
    for observation in pending.values().cloned() {
        if send_release_observation(sender, observation).await.is_err() {
            return;
        }
        counters
            .release_evidence_replayed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    *dirty = false;
}

fn release_observation_key(value: &ReleaseObservation) -> String {
    match value {
        ReleaseObservation::Evidence { value, .. } => format!("e:{}", value.evidence_id),
        ReleaseObservation::Snapshot { value, .. } => {
            format!("s:{}", hex::encode(value.revision_digest))
        }
    }
}

async fn send_release_observation(
    sender: &mpsc::Sender<AgentMessage>,
    value: ReleaseObservation,
) -> Result<(), mpsc::error::SendError<AgentMessage>> {
    let message = match value {
        ReleaseObservation::Evidence { value, .. } => {
            agent_message::Message::RevisionEvidence((*value).into())
        }
        ReleaseObservation::Snapshot { value, .. } => {
            agent_message::Message::ReadinessSnapshot(value.into())
        }
    };
    sender
        .send(AgentMessage {
            protocol_version: event_model::PROTOCOL_VERSION,
            message: Some(message),
        })
        .await
}

async fn send_batch(
    sender: &mpsc::Sender<AgentMessage>,
    batch: crate::delivery::PendingBatch,
) -> Result<(), mpsc::error::SendError<AgentMessage>> {
    sender
        .send(AgentMessage {
            protocol_version: event_model::PROTOCOL_VERSION,
            message: Some(agent_message::Message::EventBatch(
                protocol::v1::EventBatch {
                    sequence: batch.sequence,
                    events: batch.events.into_iter().map(Into::into).collect(),
                },
            )),
        })
        .await
}

fn acknowledge_batch(
    buffer: &mut EventBuffer,
    counters: &Counters,
    ack: &protocol::v1::BatchAcknowledgement,
) {
    if ack.retention_expired_events > 0 {
        tracing::info!(
            expired_events = ack.retention_expired_events,
            "server discarded events outside retention coverage"
        );
    }
    buffer.acknowledge(ack.sequence, counters);
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use event_model::{
        EVENT_SCHEMA_VERSION, EventPayload, KubernetesAttribution, ProcessExec, ProcessIdentity,
    };

    #[test]
    fn mixed_retention_ack_drops_sequence_without_replaying_eligible_events() {
        let counters = Counters::default();
        let mut buffer = EventBuffer::new(2, 2);
        buffer.push(event(Uuid::new_v4()), &counters);
        buffer.push(event(Uuid::new_v4()), &counters);
        let batch = buffer.next_batch(&counters).unwrap();
        acknowledge_batch(
            &mut buffer,
            &counters,
            &protocol::v1::BatchAcknowledgement {
                sequence: batch.sequence,
                accepted_events: 1,
                retention_expired_events: 1,
            },
        );
        assert!(buffer.replay_pending(&counters).is_empty());
        assert_eq!(counters.snapshot().acknowledged, 2);
    }

    fn event(route_id: Uuid) -> RuntimeEvent {
        RuntimeEvent {
            id: Uuid::new_v4(),
            observed_at: Utc::now(),
            schema_version: EVENT_SCHEMA_VERSION,
            attribution: KubernetesAttribution {
                project_id: Uuid::nil(),
                application_id: route_id,
                node_name: "node".into(),
                namespace: "ns".into(),
                pod_uid: "pod".into(),
                pod_name: "pod".into(),
                container_id: "container".into(),
                container_name: "container".into(),
                workload_uid: "workload".into(),
                workload_kind: "Deployment".into(),
                workload_name: "app".into(),
                release: None,
                release_identity: None,
            },
            process: ProcessIdentity {
                cgroup_id: 1,
                pid: 1,
                tgid: 1,
                command: "app".into(),
            },
            payload: EventPayload::ProcessExec(ProcessExec {
                executable: "/app".into(),
                parent_command: None,
            }),
        }
    }

    #[test]
    fn unknown_route_is_isolated_and_counted() {
        let streams = ApplicationStreams {
            routes: BTreeMap::new(),
            shutdown: watch::channel(false).0,
            tasks: Vec::new(),
            counters: Arc::new(Counters::default()),
        };
        assert!(!streams.route(event(Uuid::new_v4())));
        assert_eq!(streams.counters.snapshot().unattributed, 1);
    }

    #[test]
    fn distinct_routes_do_not_cross_deliver_or_share_failure() {
        let healthy_route = Uuid::new_v4();
        let failed_route = Uuid::new_v4();
        let (healthy_sender, mut healthy_receiver) = mpsc::channel(1);
        let (failed_sender, failed_receiver) = mpsc::channel(1);
        drop(failed_receiver);
        let streams = ApplicationStreams {
            routes: BTreeMap::from([
                (healthy_route, healthy_sender),
                (failed_route, failed_sender),
            ]),
            shutdown: watch::channel(false).0,
            tasks: Vec::new(),
            counters: Arc::new(Counters::default()),
        };

        assert!(!streams.route(event(failed_route)));
        assert!(streams.route(event(healthy_route)));
        let StreamItem::Event(received) = healthy_receiver.try_recv().unwrap() else {
            panic!("event")
        };
        assert_eq!(received.attribution.application_id, healthy_route);
        assert!(healthy_receiver.try_recv().is_err());
    }

    #[test]
    fn full_route_drops_only_that_route_and_counts_capacity() {
        let full_route = Uuid::new_v4();
        let healthy_route = Uuid::new_v4();
        let (full_sender, _full_receiver) = mpsc::channel(1);
        let (healthy_sender, mut healthy_receiver) = mpsc::channel(1);
        let streams = ApplicationStreams {
            routes: BTreeMap::from([(full_route, full_sender), (healthy_route, healthy_sender)]),
            shutdown: watch::channel(false).0,
            tasks: Vec::new(),
            counters: Arc::new(Counters::default()),
        };

        assert!(streams.route(event(full_route)));
        assert!(!streams.route(event(full_route)));
        assert!(streams.route(event(healthy_route)));
        assert_eq!(streams.counters.snapshot().capacity_dropped, 1);
        let StreamItem::Event(received) = healthy_receiver.try_recv().unwrap() else {
            panic!("event")
        };
        assert_eq!(received.attribution.application_id, healthy_route);
    }

    #[test]
    fn onboarding_heartbeat_uses_only_bounded_reliable_states() {
        use protocol::v1::{OnboardingReason, OnboardingState};
        for (ready, matched, degraded, expected_state, expected_reason) in [
            (
                false,
                false,
                false,
                OnboardingState::AgentAuthenticated,
                OnboardingReason::Unspecified,
            ),
            (
                true,
                false,
                false,
                OnboardingState::WorkloadNotMatched,
                OnboardingReason::SelectorNoMatch,
            ),
            (
                true,
                true,
                false,
                OnboardingState::WaitingForEvent,
                OnboardingReason::EventNotObserved,
            ),
            (
                true,
                true,
                true,
                OnboardingState::KernelUnsupported,
                OnboardingReason::EbpfUnavailable,
            ),
        ] {
            let state = if ready {
                KubernetesWatchState::Ready
            } else {
                KubernetesWatchState::Starting
            };
            let message = onboarding_heartbeat(state, matched, degraded)
                .message
                .unwrap();
            let agent_message::Message::OnboardingStatus(status) = message else {
                panic!("status")
            };
            assert_eq!(status.state, i32::from(expected_state));
            assert_eq!(status.reason, i32::from(expected_reason));
        }
        let message = onboarding_heartbeat(KubernetesWatchState::PermissionDenied, false, false)
            .message
            .unwrap();
        let agent_message::Message::OnboardingStatus(status) = message else {
            panic!("status")
        };
        assert_eq!(status.state, i32::from(OnboardingState::PermissionDenied));
        assert_eq!(
            status.reason,
            i32::from(OnboardingReason::KubernetesWatchForbidden)
        );
    }
}
