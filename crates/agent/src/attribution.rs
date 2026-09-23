use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use dashmap::DashMap;
use event_model::{
    ContainerCategory, KubernetesAttribution, ReleaseIdentity, RevisionReadinessSnapshot,
    WorkloadRevisionEvidence, revision_digest,
};
use futures::{StreamExt, TryStreamExt};
use k8s_openapi::api::{
    apps::v1::{Deployment, ReplicaSet},
    core::v1::Pod,
};
use kube::{
    Api, Client, Resource, ResourceExt,
    runtime::watcher::{self, Event},
};
use thiserror::Error;
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, sleep};
use uuid::Uuid;

use crate::config::{WorkloadMetadata, WorkloadSelector};
use crate::counters::Counters;

#[derive(Clone, Debug)]
struct Owner {
    uid: String,
    kind: String,
    name: String,
}

#[derive(Clone, Debug)]
struct Controller {
    uid: String,
    owner: Option<Owner>,
    labels: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
struct ContainerRecord {
    pod_uid: String,
    pod_name: String,
    namespace: String,
    container_name: String,
    owner: Owner,
    release_identity: Option<ReleaseIdentity>,
    expires_at: Option<Instant>,
}

#[derive(Clone, Debug)]
struct PodRevisionRecord {
    route_id: Uuid,
    revision_digest: [u8; 32],
    ready: bool,
}

#[derive(Clone, Debug)]
pub enum ReleaseObservation {
    Evidence {
        route_id: Uuid,
        value: Box<WorkloadRevisionEvidence>,
    },
    Snapshot {
        route_id: Uuid,
        value: RevisionReadinessSnapshot,
    },
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AttributionError {
    #[error("container is not present in the attribution cache")]
    UnknownContainer,
    #[error("pod owner chain is incomplete")]
    IncompleteOwnerChain,
    #[error("resolved workload does not match configured scope")]
    NotSelected,
}

#[derive(Debug)]
pub struct AttributionCache {
    containers: DashMap<String, ContainerRecord>,
    replica_sets: DashMap<(String, String), Controller>,
    deployments: DashMap<(String, String), Controller>,
    revision_pods: DashMap<String, PodRevisionRecord>,
    known_revisions: DashMap<(Uuid, [u8; 32]), ()>,
    terminated_ttl: Duration,
}

impl AttributionCache {
    #[must_use]
    pub fn new(terminated_ttl: Duration) -> Self {
        Self {
            containers: DashMap::new(),
            replica_sets: DashMap::new(),
            deployments: DashMap::new(),
            revision_pods: DashMap::new(),
            known_revisions: DashMap::new(),
            terminated_ttl,
        }
    }

    pub fn apply_pod(&self, pod: &Pod) {
        let Some(uid) = pod.meta().uid.clone() else {
            return;
        };
        let Some(namespace) = pod.namespace() else {
            return;
        };
        let Some(owner) = controller_owner(&pod.metadata.owner_references) else {
            return;
        };
        let statuses = pod
            .status
            .as_ref()
            .and_then(|status| status.container_statuses.as_ref());
        let release_identity = pod_release_identity(pod);
        for status in statuses.into_iter().flatten() {
            let Some(container_id) = status.container_id.as_deref() else {
                continue;
            };
            self.containers.insert(
                normalize_container_id(container_id),
                ContainerRecord {
                    pod_uid: uid.clone(),
                    pod_name: pod.name_any(),
                    namespace: namespace.clone(),
                    container_name: status.name.clone(),
                    owner: owner.clone(),
                    release_identity: release_identity.clone(),
                    expires_at: None,
                },
            );
        }
    }

    pub fn delete_pod(&self, pod: &Pod) {
        let Some(uid) = pod.meta().uid.as_deref() else {
            return;
        };
        let expires = Instant::now() + self.terminated_ttl;
        for mut record in self.containers.iter_mut() {
            if record.pod_uid == uid {
                record.expires_at = Some(expires);
            }
        }
        self.revision_pods.remove(uid);
    }

    pub fn release_evidence(
        &self,
        pod: &Pod,
        selectors: &[WorkloadSelector],
    ) -> Option<ReleaseObservation> {
        let namespace = pod.namespace()?;
        let pod_uid = pod.meta().uid.clone()?;
        let owner = controller_owner(&pod.metadata.owner_references)?;
        if owner.kind != "ReplicaSet" {
            return None;
        }
        let replica_set = self
            .replica_sets
            .get(&(namespace.clone(), owner.name.clone()))?;
        let deployment_owner = replica_set
            .owner
            .as_ref()
            .filter(|value| value.kind == "Deployment")?;
        let deployment = self
            .deployments
            .get(&(namespace.clone(), deployment_owner.name.clone()))?;
        let metadata = WorkloadMetadata {
            namespace: namespace.clone(),
            kind: "Deployment".into(),
            name: deployment_owner.name.clone(),
            labels: deployment.labels.clone(),
        };
        let selector = selectors.iter().find(|value| value.matches(&metadata))?;
        let release_identity = pod_release_identity(pod)?;
        let ready = pod
            .status
            .as_ref()
            .and_then(|value| value.conditions.as_ref())
            .is_some_and(|conditions| {
                conditions
                    .iter()
                    .any(|condition| condition.type_ == "Ready" && condition.status == "True")
            });
        let value = WorkloadRevisionEvidence {
            evidence_id: format!("{}:{}", pod_uid, hex::encode(release_identity.digest)),
            observed_at: chrono::Utc::now(),
            namespace,
            workload_uid: deployment.uid.clone(),
            workload_kind: "Deployment".into(),
            workload_name: deployment_owner.name.clone(),
            replica_set_uid: replica_set.uid.clone(),
            replica_set_name: owner.name,
            pod_uid: pod_uid.clone(),
            pod_template_hash: pod
                .metadata
                .labels
                .as_ref()
                .and_then(|values| values.get("pod-template-hash").cloned()),
            release_identity,
            ready,
        };
        self.revision_pods.insert(
            pod_uid,
            PodRevisionRecord {
                route_id: selector.route_id,
                revision_digest: revision_digest(&value),
                ready,
            },
        );
        self.known_revisions
            .insert((selector.route_id, revision_digest(&value)), ());
        Some(ReleaseObservation::Evidence {
            route_id: selector.route_id,
            value: Box::new(value),
        })
    }

    pub fn readiness_snapshots(
        &self,
        initialized: bool,
        continuous: bool,
    ) -> Vec<ReleaseObservation> {
        let mut totals = BTreeMap::<Uuid, u32>::new();
        let mut revisions = BTreeMap::<(Uuid, [u8; 32]), (u32, u32)>::new();
        for revision in &self.known_revisions {
            revisions.entry(*revision.key()).or_default();
        }
        for pod in &self.revision_pods {
            let ready = u32::from(pod.ready);
            *totals.entry(pod.route_id).or_default() += ready;
            let counts = revisions
                .entry((pod.route_id, pod.revision_digest))
                .or_default();
            counts.0 += 1;
            counts.1 += ready;
        }
        let observed_at = chrono::Utc::now();
        revisions
            .into_iter()
            .map(|((route_id, digest), (pod_count, ready_pod_count))| {
                let workload_ready_pod_count = totals.get(&route_id).copied().unwrap_or_default();
                let snapshot_id = format!(
                    "{}:{pod_count}:{ready_pod_count}:{workload_ready_pod_count}",
                    hex::encode(digest)
                );
                ReleaseObservation::Snapshot {
                    route_id,
                    value: RevisionReadinessSnapshot {
                        snapshot_id,
                        observed_at,
                        initialized,
                        continuous,
                        revision_digest: digest,
                        pod_count,
                        ready_pod_count,
                        workload_ready_pod_count,
                    },
                }
            })
            .collect()
    }

    pub fn apply_replica_set(&self, replica_set: &ReplicaSet) {
        let Some(namespace) = replica_set.namespace() else {
            return;
        };
        let Some(uid) = replica_set.meta().uid.clone() else {
            return;
        };
        self.replica_sets.insert(
            (namespace, replica_set.name_any()),
            Controller {
                uid,
                owner: controller_owner(&replica_set.metadata.owner_references),
                labels: labels(&replica_set.metadata.labels),
            },
        );
    }

    pub fn apply_deployment(&self, deployment: &Deployment) {
        let Some(namespace) = deployment.namespace() else {
            return;
        };
        let Some(uid) = deployment.meta().uid.clone() else {
            return;
        };
        self.deployments.insert(
            (namespace, deployment.name_any()),
            Controller {
                uid,
                owner: None,
                labels: labels(&deployment.metadata.labels),
            },
        );
    }

    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        self.containers
            .retain(|_, record| record.expires_at.is_none_or(|expires| expires > now));
    }

    pub fn resolve(
        &self,
        container_id: &str,
        node_name: &str,
        selectors: &[WorkloadSelector],
    ) -> Result<KubernetesAttribution, AttributionError> {
        self.cleanup_expired();
        let container = self
            .containers
            .get(&normalize_container_id(container_id))
            .ok_or(AttributionError::UnknownContainer)?;
        let (workload_uid, workload_kind, workload_name, workload_labels) =
            match container.owner.kind.as_str() {
                "ReplicaSet" => {
                    let rs = self
                        .replica_sets
                        .get(&(container.namespace.clone(), container.owner.name.clone()))
                        .ok_or(AttributionError::IncompleteOwnerChain)?;
                    let deployment_owner = rs
                        .owner
                        .as_ref()
                        .filter(|owner| owner.kind == "Deployment")
                        .ok_or(AttributionError::IncompleteOwnerChain)?;
                    let deployment = self
                        .deployments
                        .get(&(container.namespace.clone(), deployment_owner.name.clone()))
                        .ok_or(AttributionError::IncompleteOwnerChain)?;
                    (
                        deployment.uid.clone(),
                        "Deployment".to_owned(),
                        deployment_owner.name.clone(),
                        deployment.labels.clone(),
                    )
                }
                kind => (
                    container.owner.uid.clone(),
                    kind.to_owned(),
                    container.owner.name.clone(),
                    BTreeMap::new(),
                ),
            };
        let metadata = WorkloadMetadata {
            namespace: container.namespace.clone(),
            kind: workload_kind.clone(),
            name: workload_name.clone(),
            labels: workload_labels,
        };
        let selector = selectors
            .iter()
            .find(|selector| selector.matches(&metadata))
            .ok_or(AttributionError::NotSelected)?;
        if let (Some(configured), Some(observed)) = (&selector.release, &container.release_identity)
            && let Some(configured_digest) = configured.strip_prefix("sha256:")
            && configured_digest != hex::encode(observed.digest)
        {
            tracing::warn!(
                workload_name,
                "deprecated configured release conflicts with observed image digest; using observed identity"
            );
        }
        Ok(KubernetesAttribution {
            project_id: Uuid::nil(),
            application_id: selector.route_id,
            node_name: node_name.into(),
            namespace: container.namespace.clone(),
            pod_uid: container.pod_uid.clone(),
            pod_name: container.pod_name.clone(),
            container_id: normalize_container_id(container_id),
            container_name: container.container_name.clone(),
            workload_uid,
            workload_kind,
            workload_name,
            release: selector.release.clone(),
            release_identity: container.release_identity.clone(),
        })
    }
}

fn pod_release_identity(pod: &Pod) -> Option<ReleaseIdentity> {
    let spec = pod.spec.as_ref()?;
    let status = pod.status.as_ref()?;
    let application_statuses = status.container_statuses.as_ref()?;
    let init_statuses = status
        .init_container_statuses
        .as_deref()
        .unwrap_or_default();
    let mut components = Vec::with_capacity(
        spec.containers.len() + spec.init_containers.as_ref().map_or(0, Vec::len),
    );
    for container in spec.init_containers.as_deref().unwrap_or_default() {
        let image_id = init_statuses
            .iter()
            .find(|value| value.name == container.name)?
            .image_id
            .as_str();
        components.push((
            ContainerCategory::Init,
            container.name.as_str(),
            container.image.as_deref().unwrap_or_default(),
            image_id,
        ));
    }
    for container in &spec.containers {
        let image_id = application_statuses
            .iter()
            .find(|value| value.name == container.name)?
            .image_id
            .as_str();
        components.push((
            ContainerCategory::Application,
            container.name.as_str(),
            container.image.as_deref().unwrap_or_default(),
            image_id,
        ));
    }
    ReleaseIdentity::from_images(components).ok()
}

pub fn resolve_and_count(
    cache: &AttributionCache,
    counters: &Counters,
    container_id: Option<&str>,
    node_name: &str,
    selectors: &[WorkloadSelector],
) -> Option<KubernetesAttribution> {
    let result = container_id
        .ok_or(AttributionError::UnknownContainer)
        .and_then(|id| cache.resolve(id, node_name, selectors));
    match result {
        Ok(attribution) => {
            if attribution.release_identity.is_some() {
                counters
                    .release_evidence_complete
                    .fetch_add(1, Ordering::Relaxed);
            } else {
                counters
                    .release_evidence_incomplete
                    .fetch_add(1, Ordering::Relaxed);
            }
            if let (Some(configured), Some(observed)) =
                (&attribution.release, &attribution.release_identity)
                && configured
                    .strip_prefix("sha256:")
                    .is_some_and(|digest| digest != hex::encode(observed.digest))
            {
                counters
                    .release_evidence_conflict
                    .fetch_add(1, Ordering::Relaxed);
            }
            Some(attribution)
        }
        Err(AttributionError::NotSelected) => {
            tracing::debug!(container_id, "event belongs to a non-selected workload");
            counters.filtered.fetch_add(1, Ordering::Relaxed);
            None
        }
        Err(
            error @ (AttributionError::UnknownContainer | AttributionError::IncompleteOwnerChain),
        ) => {
            tracing::debug!(container_id, %error, "Kubernetes attribution failed");
            counters.unattributed.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

pub async fn run_watches(
    client: Client,
    cache: Arc<AttributionCache>,
    lifecycle_sender: mpsc::Sender<crate::lifecycle::LifecycleObservation>,
    counters: Arc<Counters>,
    readiness: watch::Sender<KubernetesWatchState>,
    release_sender: mpsc::Sender<ReleaseObservation>,
    selectors: Arc<Vec<WorkloadSelector>>,
) -> anyhow::Result<()> {
    let pods: Api<Pod> = Api::all(client.clone());
    let replicas: Api<ReplicaSet> = Api::all(client.clone());
    let deployments: Api<Deployment> = Api::all(client);
    let initialized = Arc::new(AtomicU8::new(0));
    let forbidden = Arc::new(AtomicU8::new(0));
    let pod_context = Arc::new(PodWatchContext {
        cache: cache.clone(),
        lifecycle_sender,
        counters,
        initialized: initialized.clone(),
        forbidden: forbidden.clone(),
        readiness: readiness.clone(),
        release_sender,
        selectors,
    });
    tokio::join!(
        supervise_pods(pods, pod_context),
        supervise_replica_sets(
            replicas,
            cache.clone(),
            initialized.clone(),
            forbidden.clone(),
            readiness.clone(),
        ),
        supervise_deployments(deployments, cache, initialized, forbidden, readiness),
    );
    Ok(())
}

#[derive(Debug)]
struct PodWatchContext {
    cache: Arc<AttributionCache>,
    lifecycle_sender: mpsc::Sender<crate::lifecycle::LifecycleObservation>,
    counters: Arc<Counters>,
    initialized: Arc<AtomicU8>,
    forbidden: Arc<AtomicU8>,
    readiness: watch::Sender<KubernetesWatchState>,
    release_sender: mpsc::Sender<ReleaseObservation>,
    selectors: Arc<Vec<WorkloadSelector>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KubernetesWatchState {
    Starting,
    Ready,
    PermissionDenied,
}

const WATCH_RETRY_MIN: Duration = Duration::from_secs(1);
const WATCH_RETRY_MAX: Duration = Duration::from_secs(30);

fn source_unavailable(
    initialized: &AtomicU8,
    forbidden: &AtomicU8,
    bit: u8,
    result: &anyhow::Result<()>,
    readiness: &watch::Sender<KubernetesWatchState>,
) -> bool {
    let was_initialized = initialized.fetch_and(!bit, Ordering::AcqRel) & bit != 0;
    let denied = result.as_ref().is_err_and(is_permission_denied);
    if denied {
        forbidden.fetch_or(bit, Ordering::AcqRel);
    } else {
        forbidden.fetch_and(!bit, Ordering::AcqRel);
    }
    publish_watch_state(initialized, forbidden, readiness);
    was_initialized
}

fn is_permission_denied(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<kube::Error>()
            .is_some_and(|error| matches!(error, kube::Error::Api(response) if matches!(response.code, 401 | 403)))
    })
}

fn publish_watch_state(
    initialized: &AtomicU8,
    forbidden: &AtomicU8,
    readiness: &watch::Sender<KubernetesWatchState>,
) {
    let state = if forbidden.load(Ordering::Acquire) != 0 {
        KubernetesWatchState::PermissionDenied
    } else if initialized.load(Ordering::Acquire) == 0b111 {
        KubernetesWatchState::Ready
    } else {
        KubernetesWatchState::Starting
    };
    readiness.send_replace(state);
}

fn next_retry(current: Duration) -> Duration {
    current.saturating_mul(2).min(WATCH_RETRY_MAX)
}

async fn retry_watch(
    source: &'static str,
    result: anyhow::Result<()>,
    was_initialized: bool,
    retry: &mut Duration,
) {
    let delay = if was_initialized {
        *retry = WATCH_RETRY_MIN;
        WATCH_RETRY_MIN
    } else {
        let delay = *retry;
        *retry = next_retry(*retry);
        delay
    };
    match result {
        Ok(()) => tracing::warn!(
            source,
            retry_seconds = delay.as_secs(),
            "Kubernetes watch ended; retrying"
        ),
        Err(error) => {
            tracing::warn!(source, %error, retry_seconds = delay.as_secs(), "Kubernetes watch failed; retrying");
        }
    }
    sleep(delay).await;
}

async fn supervise_pods(api: Api<Pod>, context: Arc<PodWatchContext>) {
    let mut retry = WATCH_RETRY_MIN;
    loop {
        let result = watch_pods(api.clone(), &context).await;
        let was_initialized = source_unavailable(
            &context.initialized,
            &context.forbidden,
            0b001,
            &result,
            &context.readiness,
        );
        retry_watch("pods", result, was_initialized, &mut retry).await;
    }
}

async fn supervise_replica_sets(
    api: Api<ReplicaSet>,
    cache: Arc<AttributionCache>,
    initialized: Arc<AtomicU8>,
    forbidden: Arc<AtomicU8>,
    readiness: watch::Sender<KubernetesWatchState>,
) {
    let mut retry = WATCH_RETRY_MIN;
    loop {
        let result = watch_replica_sets(
            api.clone(),
            cache.clone(),
            initialized.clone(),
            forbidden.clone(),
            readiness.clone(),
        )
        .await;
        let was_initialized =
            source_unavailable(&initialized, &forbidden, 0b010, &result, &readiness);
        retry_watch("replicasets", result, was_initialized, &mut retry).await;
    }
}

async fn supervise_deployments(
    api: Api<Deployment>,
    cache: Arc<AttributionCache>,
    initialized: Arc<AtomicU8>,
    forbidden: Arc<AtomicU8>,
    readiness: watch::Sender<KubernetesWatchState>,
) {
    let mut retry = WATCH_RETRY_MIN;
    loop {
        let result = watch_deployments(
            api.clone(),
            cache.clone(),
            initialized.clone(),
            forbidden.clone(),
            readiness.clone(),
        )
        .await;
        let was_initialized =
            source_unavailable(&initialized, &forbidden, 0b100, &result, &readiness);
        retry_watch("deployments", result, was_initialized, &mut retry).await;
    }
}

fn source_initialized(
    initialized: &AtomicU8,
    forbidden: &AtomicU8,
    bit: u8,
    readiness: &watch::Sender<KubernetesWatchState>,
) {
    initialized.fetch_or(bit, Ordering::AcqRel);
    forbidden.fetch_and(!bit, Ordering::AcqRel);
    publish_watch_state(initialized, forbidden, readiness);
}

async fn watch_pods(api: Api<Pod>, context: &PodWatchContext) -> anyhow::Result<()> {
    let mut stream = watcher::watcher(api, watcher::Config::default()).boxed();
    let mut lifecycle = crate::lifecycle::ContainerLifecycleStore::new(8192);
    let mut snapshot_interval = tokio::time::interval(Duration::from_secs(15));
    loop {
        tokio::select! {
            event = stream.try_next() => {
                let Some(event) = event? else { return Ok(()) };
                handle_pod_event(context, &mut lifecycle, event);
            }
            _ = snapshot_interval.tick() => {
                emit_readiness_snapshots(context);
            }
        }
    }
}

fn emit_readiness_snapshots(context: &PodWatchContext) {
    let ready = context.initialized.load(Ordering::Acquire) == 0b111;
    for snapshot in context.cache.readiness_snapshots(ready, true) {
        let _ = context.release_sender.try_send(snapshot);
    }
}

fn handle_pod_event(
    context: &PodWatchContext,
    lifecycle: &mut crate::lifecycle::ContainerLifecycleStore,
    event: Event<Pod>,
) {
    match event {
        Event::Apply(pod) | Event::InitApply(pod) => {
            context.cache.apply_pod(&pod);
            if let Some(evidence) = context.cache.release_evidence(&pod, &context.selectors) {
                let _ = context.release_sender.try_send(evidence);
            }
            emit_readiness_snapshots(context);
            let capacity_before = lifecycle.capacity_drops;
            let invalid_before = lifecycle.invalid_statuses;
            let dedup_before = lifecycle.deduplicated;
            for observation in lifecycle.observe_pod(&pod) {
                if context.lifecycle_sender.try_send(observation).is_err() {
                    context
                        .counters
                        .lifecycle_capacity
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            context.counters.lifecycle_capacity.fetch_add(
                lifecycle.capacity_drops.saturating_sub(capacity_before),
                Ordering::Relaxed,
            );
            context.counters.lifecycle_invalid_status.fetch_add(
                lifecycle.invalid_statuses.saturating_sub(invalid_before),
                Ordering::Relaxed,
            );
            context.counters.lifecycle_deduplicated.fetch_add(
                lifecycle.deduplicated.saturating_sub(dedup_before),
                Ordering::Relaxed,
            );
        }
        Event::Delete(pod) => {
            context.cache.delete_pod(&pod);
            emit_readiness_snapshots(context);
        }
        Event::Init => {
            let ended = Ok(());
            source_unavailable(
                &context.initialized,
                &context.forbidden,
                0b001,
                &ended,
                &context.readiness,
            );
        }
        Event::InitDone => {
            source_initialized(
                &context.initialized,
                &context.forbidden,
                0b001,
                &context.readiness,
            );
            emit_readiness_snapshots(context);
        }
    }
}

async fn watch_replica_sets(
    api: Api<ReplicaSet>,
    cache: Arc<AttributionCache>,
    initialized: Arc<AtomicU8>,
    forbidden: Arc<AtomicU8>,
    readiness: watch::Sender<KubernetesWatchState>,
) -> anyhow::Result<()> {
    let mut stream = watcher::watcher(api, watcher::Config::default()).boxed();
    while let Some(event) = stream.try_next().await? {
        match event {
            Event::Apply(resource) | Event::InitApply(resource) => {
                cache.apply_replica_set(&resource);
            }
            Event::InitDone => source_initialized(&initialized, &forbidden, 0b010, &readiness),
            Event::Init => {
                let ended = Ok(());
                source_unavailable(&initialized, &forbidden, 0b010, &ended, &readiness);
            }
            Event::Delete(_) => {}
        }
    }
    Ok(())
}

async fn watch_deployments(
    api: Api<Deployment>,
    cache: Arc<AttributionCache>,
    initialized: Arc<AtomicU8>,
    forbidden: Arc<AtomicU8>,
    readiness: watch::Sender<KubernetesWatchState>,
) -> anyhow::Result<()> {
    let mut stream = watcher::watcher(api, watcher::Config::default()).boxed();
    while let Some(event) = stream.try_next().await? {
        match event {
            Event::Apply(resource) | Event::InitApply(resource) => {
                cache.apply_deployment(&resource);
            }
            Event::InitDone => source_initialized(&initialized, &forbidden, 0b100, &readiness),
            Event::Init => {
                let ended = Ok(());
                source_unavailable(&initialized, &forbidden, 0b100, &ended, &readiness);
            }
            Event::Delete(_) => {}
        }
    }
    Ok(())
}

fn controller_owner(
    owners: &Option<Vec<k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference>>,
) -> Option<Owner> {
    owners
        .as_ref()?
        .iter()
        .find(|owner| owner.controller.unwrap_or(false))
        .map(|owner| Owner {
            uid: owner.uid.clone(),
            kind: owner.kind.clone(),
            name: owner.name.clone(),
        })
}

fn labels(values: &Option<BTreeMap<String, String>>) -> BTreeMap<String, String> {
    values.clone().unwrap_or_default()
}

fn normalize_container_id(value: &str) -> String {
    value
        .rsplit_once("://")
        .map_or(value, |(_, id)| id)
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::{
        api::core::v1::{Container, ContainerStatus, PodSpec, PodStatus},
        apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference},
    };
    use uuid::Uuid;

    #[test]
    fn lifecycle_readiness_requires_every_source_and_can_be_withheld() {
        let initialized = AtomicU8::new(0);
        let forbidden = AtomicU8::new(0);
        let (readiness, receiver) = watch::channel(KubernetesWatchState::Starting);
        source_initialized(&initialized, &forbidden, 0b001, &readiness);
        source_initialized(&initialized, &forbidden, 0b100, &readiness);
        assert_eq!(*receiver.borrow(), KubernetesWatchState::Starting);
        source_initialized(&initialized, &forbidden, 0b010, &readiness);
        assert_eq!(*receiver.borrow(), KubernetesWatchState::Ready);
        let ended = Ok(());
        assert!(source_unavailable(
            &initialized,
            &forbidden,
            0b001,
            &ended,
            &readiness
        ));
        assert_eq!(*receiver.borrow(), KubernetesWatchState::Starting);
        assert_eq!(initialized.load(Ordering::Acquire), 0b110);
        assert!(!source_unavailable(
            &initialized,
            &forbidden,
            0b001,
            &ended,
            &readiness
        ));
    }

    #[test]
    fn watch_retry_is_exponential_and_bounded() {
        let mut retry = WATCH_RETRY_MIN;
        for expected in [2, 4, 8, 16, 30, 30] {
            retry = next_retry(retry);
            assert_eq!(retry, Duration::from_secs(expected));
        }
    }

    fn owner(kind: &str, name: &str, uid: &str) -> OwnerReference {
        OwnerReference {
            api_version: "apps/v1".into(),
            kind: kind.into(),
            name: name.into(),
            uid: uid.into(),
            controller: Some(true),
            block_owner_deletion: None,
        }
    }

    #[test]
    fn resolves_deployment_and_filters_non_selected_workload() {
        let cache = AttributionCache::new(Duration::from_secs(30));
        let deployment = Deployment {
            metadata: ObjectMeta {
                namespace: Some("production".into()),
                name: Some("payment-api".into()),
                uid: Some("deployment-uid".into()),
                labels: Some(BTreeMap::from([("app".into(), "payment-api".into())])),
                ..Default::default()
            },
            ..Default::default()
        };
        let replica_set = ReplicaSet {
            metadata: ObjectMeta {
                namespace: Some("production".into()),
                name: Some("payment-api-abc".into()),
                uid: Some("rs-uid".into()),
                owner_references: Some(vec![owner("Deployment", "payment-api", "deployment-uid")]),
                ..Default::default()
            },
            ..Default::default()
        };
        let pod = Pod {
            metadata: ObjectMeta {
                namespace: Some("production".into()),
                name: Some("payment-api-1".into()),
                uid: Some("pod-uid".into()),
                owner_references: Some(vec![owner("ReplicaSet", "payment-api-abc", "rs-uid")]),
                ..Default::default()
            },
            spec: Some(PodSpec {
                containers: vec![Container {
                    name: "payment-api".into(),
                    image: Some("registry/payment-api:latest".into()),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            status: Some(PodStatus {
                container_statuses: Some(vec![ContainerStatus {
                    name: "payment-api".into(),
                    container_id: Some("containerd://abc".into()),
                    image_id: format!("registry/payment-api@sha256:{}", "ab".repeat(32)),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
        };
        cache.apply_deployment(&deployment);
        cache.apply_replica_set(&replica_set);
        cache.apply_pod(&pod);
        let selector = WorkloadSelector {
            application_credential_file: "/secrets/payment-api".into(),
            route_id: Uuid::new_v4(),
            namespace: "production".into(),
            kind: "Deployment".into(),
            name: "payment-api".into(),
            release: Some("1.7.2".into()),
            labels: BTreeMap::from([("app".into(), "payment-api".into())]),
        };
        let result = cache
            .resolve("abc", "node-1", std::slice::from_ref(&selector))
            .unwrap();
        assert_eq!(result.workload_uid, "deployment-uid");
        assert_eq!(result.container_name, "payment-api");
        assert_eq!(result.release.as_deref(), Some("1.7.2"));
        assert!(result.release_identity.is_some());
        let ReleaseObservation::Evidence { route_id, value } = cache
            .release_evidence(&pod, std::slice::from_ref(&selector))
            .unwrap()
        else {
            panic!("revision evidence")
        };
        assert_eq!(route_id, selector.route_id);
        assert_eq!(value.replica_set_uid, "rs-uid");
        assert_eq!(value.release_identity.containers.len(), 1);
        let snapshots = cache.readiness_snapshots(true, true);
        let ReleaseObservation::Snapshot { value, .. } = &snapshots[0] else {
            panic!("snapshot")
        };
        assert!(value.initialized && value.continuous);
        assert_eq!((value.pod_count, value.ready_pod_count), (1, 0));
        let other = WorkloadSelector {
            name: "other".into(),
            ..selector
        };
        assert_eq!(
            cache.resolve("abc", "node-1", &[other]).unwrap_err(),
            AttributionError::NotSelected
        );
    }

    #[test]
    fn missing_container_is_counted_as_unattributed() {
        let cache = AttributionCache::new(Duration::ZERO);
        let counters = Counters::default();
        assert!(resolve_and_count(&cache, &counters, Some("missing"), "node-1", &[]).is_none());
        assert_eq!(counters.snapshot().unattributed, 1);
    }
}
