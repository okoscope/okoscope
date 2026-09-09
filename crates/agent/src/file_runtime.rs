use std::{collections::HashMap, time::Instant};

use event_model::{
    EventPayload, FILE_MODIFY_AGGREGATION_WINDOW, FileCreate, FileDelete, FileRename, RuntimeEvent,
};

pub const FILE_MODIFY_AGGREGATION_CAPACITY: usize = 4096;

/// Applies rename scope without retaining a path from an unobservable side.
pub fn translate_rename_scope(
    value: FileRename,
    old_observed: bool,
    new_observed: bool,
) -> Option<EventPayload> {
    match (old_observed, new_observed) {
        (true, true) => Some(EventPayload::FileRename(value)),
        (true, false) => Some(EventPayload::FileDelete(FileDelete {
            path: value.old_path,
        })),
        (false, true) => Some(EventPayload::FileCreate(FileCreate {
            path: value.new_path,
        })),
        (false, false) => None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ModifyKey {
    workload_uid: String,
    container_id: String,
    tgid: u32,
    fd: i32,
    generation: u64,
}

#[derive(Debug)]
struct PendingModify {
    event: RuntimeEvent,
    deadline: Instant,
}

#[derive(Debug)]
pub struct FileModifyAggregator {
    pending: HashMap<ModifyKey, PendingModify>,
    capacity: usize,
}

impl Default for FileModifyAggregator {
    fn default() -> Self {
        Self::new(FILE_MODIFY_AGGREGATION_CAPACITY)
    }
}

impl FileModifyAggregator {
    pub fn new(capacity: usize) -> Self {
        Self {
            pending: HashMap::with_capacity(capacity.min(1024)),
            capacity,
        }
    }

    /// Returns events ready for delivery and whether a new modification was dropped for capacity.
    pub fn observe(
        &mut self,
        event: RuntimeEvent,
        fd: i32,
        generation: u64,
        now: Instant,
    ) -> (Vec<RuntimeEvent>, bool) {
        if matches!(event.payload, EventPayload::FileModify(_)) {
            let key = ModifyKey {
                workload_uid: event.attribution.workload_uid.clone(),
                container_id: event.attribution.container_id.clone(),
                tgid: event.process.tgid,
                fd,
                generation,
            };
            if let Some(pending) = self.pending.get_mut(&key) {
                pending.event = event;
                return (Vec::new(), false);
            }
            if self.pending.len() >= self.capacity {
                return (Vec::new(), true);
            }
            self.pending.insert(
                key,
                PendingModify {
                    event,
                    deadline: now + FILE_MODIFY_AGGREGATION_WINDOW,
                },
            );
            return (Vec::new(), false);
        }

        let structural_path = structural_path(&event.payload);
        let mut ready = Vec::new();
        if let Some(path) = structural_path {
            let matching = self
                .pending
                .iter()
                .filter(|(_, pending)| {
                    pending.event.attribution.workload_uid == event.attribution.workload_uid
                        && pending.event.attribution.container_id == event.attribution.container_id
                        && modify_path(&pending.event.payload) == Some(path)
                })
                .map(|(key, _)| key.clone())
                .collect::<Vec<_>>();
            for key in matching {
                if let Some(pending) = self.pending.remove(&key) {
                    ready.push(pending.event);
                }
            }
        }
        ready.push(event);
        (ready, false)
    }

    pub fn drain_expired(&mut self, now: Instant) -> Vec<RuntimeEvent> {
        let expired = self
            .pending
            .iter()
            .filter(|(_, pending)| pending.deadline <= now)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        expired
            .into_iter()
            .filter_map(|key| self.pending.remove(&key).map(|pending| pending.event))
            .collect()
    }

    pub fn drain_all(&mut self) -> Vec<RuntimeEvent> {
        self.pending.drain().map(|(_, value)| value.event).collect()
    }
}

fn modify_path(payload: &EventPayload) -> Option<&str> {
    match payload {
        EventPayload::FileModify(value) => Some(value.path.as_str()),
        _ => None,
    }
}

fn structural_path(payload: &EventPayload) -> Option<&str> {
    match payload {
        EventPayload::FileDelete(value) => Some(value.path.as_str()),
        EventPayload::FileRename(value) => Some(value.old_path.as_str()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use event_model::{
        EVENT_SCHEMA_VERSION, FileActivityPath, FileDelete, FileModify, KubernetesAttribution,
        ProcessIdentity,
    };
    use uuid::Uuid;

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
                container_id: "container".into(),
                container_name: "container".into(),
                workload_uid: "workload".into(),
                workload_kind: "Deployment".into(),
                workload_name: "api".into(),
                release: None,
                release_identity: None,
            },
            process: ProcessIdentity {
                cgroup_id: 1,
                pid: 2,
                tgid: 2,
                command: "api".into(),
            },
            payload,
        }
    }

    #[test]
    fn aggregates_for_five_seconds_and_flushes_before_delete() {
        let now = Instant::now();
        let path = FileActivityPath::new("/app/data/report").unwrap();
        let mut aggregator = FileModifyAggregator::new(2);
        let first = event(EventPayload::FileModify(FileModify { path: path.clone() }));
        assert!(aggregator.observe(first, 7, 9, now).0.is_empty());
        let latest = event(EventPayload::FileModify(FileModify { path: path.clone() }));
        assert!(aggregator.observe(latest.clone(), 7, 9, now).0.is_empty());
        assert!(
            aggregator
                .drain_expired(
                    now + FILE_MODIFY_AGGREGATION_WINDOW
                        .checked_sub(std::time::Duration::from_millis(1))
                        .unwrap()
                )
                .is_empty()
        );
        assert_eq!(
            aggregator.drain_expired(now + FILE_MODIFY_AGGREGATION_WINDOW),
            vec![latest]
        );

        let pending = event(EventPayload::FileModify(FileModify { path: path.clone() }));
        aggregator.observe(pending.clone(), 7, 10, now);
        let delete = event(EventPayload::FileDelete(FileDelete { path }));
        let (ready, dropped) = aggregator.observe(delete.clone(), -1, 0, now);
        assert!(!dropped);
        assert_eq!(ready, vec![pending, delete]);
    }

    #[test]
    fn capacity_drop_does_not_evict_existing_evidence() {
        let now = Instant::now();
        let mut aggregator = FileModifyAggregator::new(1);
        let first = event(EventPayload::FileModify(FileModify {
            path: FileActivityPath::new("/one").unwrap(),
        }));
        aggregator.observe(first.clone(), 1, 1, now);
        let second = event(EventPayload::FileModify(FileModify {
            path: FileActivityPath::new("/two").unwrap(),
        }));
        assert!(aggregator.observe(second, 2, 2, now).1);
        assert_eq!(aggregator.drain_all(), vec![first]);
    }

    #[test]
    fn rename_scope_crossings_never_retain_the_hidden_side() {
        let old = FileActivityPath::new("/included/old").unwrap();
        let new = FileActivityPath::new("/excluded/new").unwrap();
        let rename = FileRename {
            old_path: old.clone(),
            new_path: new.clone(),
            replaced: None,
        };
        assert_eq!(
            translate_rename_scope(rename.clone(), true, false),
            Some(EventPayload::FileDelete(FileDelete { path: old }))
        );
        assert_eq!(
            translate_rename_scope(rename.clone(), false, true),
            Some(EventPayload::FileCreate(FileCreate { path: new }))
        );
        assert_eq!(translate_rename_scope(rename, false, false), None);
    }
}
