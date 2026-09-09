use std::collections::HashMap;

use event_model::{ContainerRestart, ContainerTermination, EventPayload};
use k8s_openapi::api::core::v1::{ContainerStateTerminated, ContainerStatus, Pod};
use kube::Resource;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LifecycleObservation {
    pub container_id: String,
    pub payload: EventPayload,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TransitionState {
    /// Stable identity for the Pod/container slot. Kubernetes assigns a new
    /// runtime container ID after every restart, but `restart_count` spans
    /// those IDs. Anchor restart occurrences to the first observed ID so the
    /// server can project one bounded restart window for the slot.
    lifetime_id: String,
    restart_count: u32,
    termination_key: Option<TerminationKey>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TerminationKey {
    reason: String,
    exit_code: i32,
    started_at_nanos: Option<i64>,
    finished_at_nanos: Option<i64>,
}

#[derive(Debug)]
pub struct ContainerLifecycleStore {
    capacity: usize,
    states: HashMap<(String, String), TransitionState>,
    pub capacity_drops: u64,
    pub invalid_statuses: u64,
    pub deduplicated: u64,
}

impl ContainerLifecycleStore {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            states: HashMap::with_capacity(capacity),
            capacity_drops: 0,
            invalid_statuses: 0,
            deduplicated: 0,
        }
    }

    /// Observes regular app containers. Init and ephemeral containers are
    /// intentionally excluded from `container.lifecycle/v1`.
    pub fn observe_pod(&mut self, pod: &Pod) -> Vec<LifecycleObservation> {
        let Some(pod_uid) = pod.meta().uid.clone() else {
            self.invalid_statuses += 1;
            return Vec::new();
        };
        let statuses = pod
            .status
            .as_ref()
            .and_then(|status| status.container_statuses.as_ref())
            .cloned()
            .unwrap_or_default();
        statuses
            .iter()
            .flat_map(|status| self.observe_status(&pod_uid, status))
            .collect()
    }

    fn observe_status(
        &mut self,
        pod_uid: &str,
        status: &ContainerStatus,
    ) -> Vec<LifecycleObservation> {
        let Some(container_id) = status.container_id.as_deref().map(normalize_container_id) else {
            self.invalid_statuses += 1;
            return Vec::new();
        };
        let Ok(restart_count) = u32::try_from(status.restart_count) else {
            self.invalid_statuses += 1;
            return Vec::new();
        };
        let termination = status
            .state
            .as_ref()
            .and_then(|state| state.terminated.as_ref())
            .or_else(|| {
                status
                    .last_state
                    .as_ref()
                    .and_then(|state| state.terminated.as_ref())
            });
        let waiting_reason = status
            .state
            .as_ref()
            .and_then(|state| state.waiting.as_ref())
            .and_then(|waiting| waiting.reason.clone());
        let parsed_termination = termination.and_then(|value| {
            Self::parse_termination(&container_id, value)
                .inspect_err(|_| self.invalid_statuses += 1)
                .ok()
        });
        let termination_key = parsed_termination.as_ref().map(termination_key);
        let key = (pod_uid.to_owned(), status.name.clone());
        let Some(previous) = self.states.get(&key).cloned() else {
            if self.states.len() >= self.capacity {
                self.capacity_drops += 1;
                return Vec::new();
            }
            self.states.insert(
                key,
                TransitionState {
                    lifetime_id: container_id.clone(),
                    restart_count,
                    termination_key,
                },
            );
            return parsed_termination
                .map(|payload| LifecycleObservation {
                    container_id,
                    payload: EventPayload::ContainerTermination(payload),
                })
                .into_iter()
                .collect();
        };

        if restart_count < previous.restart_count {
            self.invalid_statuses += 1;
            return Vec::new();
        }
        let mut observations = Vec::new();
        if let Some(termination) = parsed_termination.clone() {
            if termination_key == previous.termination_key {
                self.deduplicated += 1;
            } else {
                observations.push(LifecycleObservation {
                    container_id: container_id.clone(),
                    payload: EventPayload::ContainerTermination(termination),
                });
            }
        }
        let delta = restart_count - previous.restart_count;
        if delta > 0 {
            if let Ok(restart) = ContainerRestart::new(
                previous.lifetime_id.clone(),
                restart_count,
                delta,
                parsed_termination,
                waiting_reason,
            ) {
                observations.push(LifecycleObservation {
                    container_id: previous.lifetime_id.clone(),
                    payload: EventPayload::ContainerRestart(restart),
                });
            } else {
                self.invalid_statuses += 1;
            }
        }
        self.states.insert(
            key,
            TransitionState {
                lifetime_id: previous.lifetime_id,
                restart_count,
                termination_key,
            },
        );
        observations
    }

    fn parse_termination(
        container_id: &str,
        value: &ContainerStateTerminated,
    ) -> Result<ContainerTermination, event_model::TerminationValidationError> {
        ContainerTermination::new(
            container_id,
            value.reason.clone().unwrap_or_else(|| "Unknown".into()),
            value.exit_code,
            value.started_at.as_ref().map(|time| time.0),
            value.finished_at.as_ref().map(|time| time.0),
        )
    }
}

fn termination_key(value: &ContainerTermination) -> TerminationKey {
    TerminationKey {
        reason: value.reason.clone(),
        exit_code: value.exit_code,
        started_at_nanos: value.started_at.and_then(|time| time.timestamp_nanos_opt()),
        finished_at_nanos: value
            .finished_at
            .and_then(|time| time.timestamp_nanos_opt()),
    }
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
        api::core::v1::{ContainerState, ContainerStateWaiting, PodStatus},
        apimachinery::pkg::apis::meta::v1::ObjectMeta,
    };

    fn pod(restarts: i32, reason: &str, waiting: Option<&str>, id: &str) -> Pod {
        Pod {
            metadata: ObjectMeta {
                uid: Some("pod-1".into()),
                ..Default::default()
            },
            status: Some(PodStatus {
                container_statuses: Some(vec![ContainerStatus {
                    container_id: Some(format!("containerd://{id}")),
                    image: "image".into(),
                    image_id: "image-id".into(),
                    last_state: Some(ContainerState {
                        terminated: Some(ContainerStateTerminated {
                            exit_code: match reason {
                                "OOMKilled" => 137,
                                "Completed" => 0,
                                _ => 1,
                            },
                            reason: Some(reason.into()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    name: "worker".into(),
                    ready: false,
                    restart_count: restarts,
                    started: Some(false),
                    state: waiting.map(|reason| ContainerState {
                        waiting: Some(ContainerStateWaiting {
                            reason: Some(reason.into()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn baseline_dedup_increment_jump_and_new_lifetime_are_bounded() {
        let mut store = ContainerLifecycleStore::new(4);
        assert_eq!(store.observe_pod(&pod(4, "Error", None, "one")).len(), 1);
        assert!(store.observe_pod(&pod(4, "Error", None, "one")).is_empty());
        let increment = store.observe_pod(&pod(5, "OOMKilled", Some("CrashLoopBackOff"), "one"));
        assert_eq!(increment.len(), 2);
        let EventPayload::ContainerRestart(restart) = &increment[1].payload else {
            panic!("expected restart");
        };
        assert_eq!(restart.restart_delta, 1);
        assert_eq!(restart.runtime_container_id, "one");
        assert!(!restart.observation_gap);
        let jump = store.observe_pod(&pod(7, "OOMKilled", Some("CrashLoopBackOff"), "one"));
        let EventPayload::ContainerRestart(restart) = &jump[0].payload else {
            panic!("expected restart");
        };
        assert_eq!(restart.restart_delta, 2);
        assert!(restart.observation_gap);
        let next_runtime = store.observe_pod(&pod(8, "Completed", None, "two"));
        assert_eq!(next_runtime.len(), 2);
        let EventPayload::ContainerRestart(restart) = &next_runtime[1].payload else {
            panic!("expected restart across runtime container IDs");
        };
        assert_eq!(restart.restart_delta, 1);
        assert_eq!(restart.runtime_container_id, "one");
    }

    #[test]
    fn capacity_and_counter_regression_do_not_fabricate_restarts() {
        let mut store = ContainerLifecycleStore::new(1);
        store.observe_pod(&pod(3, "Error", None, "one"));
        assert!(store.observe_pod(&pod(2, "Error", None, "one")).is_empty());
        assert_eq!(store.invalid_statuses, 1);
        let mut replacement_pod = pod(0, "Error", None, "two");
        replacement_pod.metadata.uid = Some("pod-2".into());
        assert!(store.observe_pod(&replacement_pod).is_empty());
        assert_eq!(store.capacity_drops, 1);
    }

    #[test]
    fn completed_crash_and_replacement_pod_fixtures_preserve_runtime_evidence() {
        let mut store = ContainerLifecycleStore::new(8);
        let completed = store.observe_pod(&pod(0, "Completed", None, "job"));
        let EventPayload::ContainerTermination(completed) = &completed[0].payload else {
            panic!("expected termination");
        };
        assert_eq!(completed.reason, "Completed");
        assert_eq!(completed.exit_code, 0);

        let crashed = store.observe_pod(&pod(0, "Error", None, "segv"));
        let EventPayload::ContainerTermination(crashed) = &crashed[0].payload else {
            panic!("expected termination");
        };
        assert_eq!(crashed.reason, "Error");

        let mut replacement = pod(0, "Error", None, "segv");
        replacement.metadata.uid = Some("pod-2".into());
        assert_eq!(store.observe_pod(&replacement).len(), 1);
    }

    #[test]
    fn init_and_ephemeral_statuses_are_out_of_scope_for_v1() {
        let mut value = pod(0, "Error", None, "regular");
        let status = value
            .status
            .as_mut()
            .and_then(|status| status.container_statuses.take())
            .unwrap();
        value.status.as_mut().unwrap().init_container_statuses = Some(status.clone());
        value.status.as_mut().unwrap().ephemeral_container_statuses = Some(status);
        let mut store = ContainerLifecycleStore::new(8);
        assert!(store.observe_pod(&value).is_empty());
    }
}
