use std::collections::{HashMap, HashSet};
use std::fs;

use chrono::{DateTime, Duration, Timelike, Utc};
use event_model::{
    BaselineProvenance, EVENT_SCHEMA_VERSION, EventPayload, KubernetesAttribution,
    MAX_THREAD_NAMES, ProcessGenerationIdentity, ProcessIdentity, ProcessStart, RuntimeEvent,
    ThreadActivityWindow, ThreadGapReason, ThreadNameAggregate,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct ProcessKey {
    cgroup_id: u64,
    tgid: u32,
}

#[derive(Clone, Debug)]
struct TaskState {
    name: String,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct TaskKey {
    tid: u32,
    generation: u64,
    started_at_ns: u64,
}

#[derive(Clone, Debug, Default)]
struct NameState {
    created: u64,
    exited: u64,
    active: u64,
}

#[derive(Clone, Debug)]
struct ProcessState {
    attribution: KubernetesAttribution,
    process: ProcessIdentity,
    generation: ProcessGenerationIdentity,
    tasks: HashMap<TaskKey, TaskState>,
    names: HashMap<String, NameState>,
    active_at_start: u64,
    peak_active: u64,
    created: u64,
    exited: u64,
    overflow: u64,
    gaps: HashSet<ThreadGapReason>,
    window_start: DateTime<Utc>,
    baseline_provenance: BaselineProvenance,
    baseline_complete: bool,
}

#[derive(Debug)]
pub struct TaskLifecycleStore {
    capacity: usize,
    states: HashMap<ProcessKey, ProcessState>,
    task_index: HashMap<(u32, u32), (ProcessKey, TaskKey)>,
    next_task_generation: u64,
}

#[derive(Clone, Debug)]
pub struct TaskStart {
    pub tid: u32,
    pub observed_at_ns: u64,
    pub name: String,
}

impl TaskLifecycleStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            states: HashMap::with_capacity(capacity),
            task_index: HashMap::with_capacity(capacity),
            next_task_generation: 1,
        }
    }

    pub fn observe_process_start(
        &mut self,
        observed_at: DateTime<Utc>,
        attribution: KubernetesAttribution,
        process: ProcessIdentity,
        start: ProcessStart,
    ) -> Option<RuntimeEvent> {
        let key = ProcessKey {
            cgroup_id: process.cgroup_id,
            tgid: process.tgid,
        };
        self.observe_process_exit(key.cgroup_id, key.tgid);
        start.validate().ok()?;
        self.states.insert(
            key,
            ProcessState::new(
                attribution.clone(),
                process.clone(),
                start.generation.clone(),
                observed_at,
            ),
        );
        Some(RuntimeEvent {
            id: Uuid::new_v4(),
            observed_at,
            schema_version: EVENT_SCHEMA_VERSION,
            attribution,
            process,
            payload: EventPayload::ProcessStart(start),
        })
    }

    pub fn observe_thread_start(
        &mut self,
        observed_at: DateTime<Utc>,
        attribution: KubernetesAttribution,
        process: ProcessIdentity,
        generation: ProcessGenerationIdentity,
        task: TaskStart,
    ) {
        let key = ProcessKey {
            cgroup_id: process.cgroup_id,
            tgid: process.tgid,
        };
        if !self.ensure_state(&key, observed_at, attribution, process, generation) {
            return;
        }
        let locator = (key.tgid, task.tid);
        if self
            .task_index
            .get(&locator)
            .is_some_and(|(_, current)| current.started_at_ns >= task.observed_at_ns)
        {
            return;
        }
        self.retire_reused_task(locator);
        if self.task_index.len() >= self.capacity {
            if let Some(state) = self.states.get_mut(&key) {
                state.gaps.insert(ThreadGapReason::StateCapacity);
            }
            return;
        }
        let task_key = self.next_task_key(task.tid, task.observed_at_ns);
        let Some(state) = self.states.get_mut(&key) else {
            return;
        };
        let name = state.bucket_name(task.name);
        state
            .tasks
            .insert(task_key, TaskState { name: name.clone() });
        state.created = state.created.saturating_add(1);
        let entry = state.names.entry(name).or_default();
        entry.created = entry.created.saturating_add(1);
        entry.active = entry.active.saturating_add(1);
        state.peak_active = state.peak_active.max(state.tasks.len() as u64);
        self.task_index.insert(locator, (key, task_key));
    }

    pub fn bootstrap_process(
        &mut self,
        observed_at: DateTime<Utc>,
        attribution: KubernetesAttribution,
        process: &ProcessIdentity,
        generation: ProcessGenerationIdentity,
    ) {
        let key = ProcessKey {
            cgroup_id: process.cgroup_id,
            tgid: process.tgid,
        };
        if self.states.contains_key(&key) || self.states.len() >= self.capacity {
            return;
        }
        let mut state = ProcessState::new(attribution, process.clone(), generation, observed_at);
        state.baseline_provenance = BaselineProvenance::Snapshot;
        let task_dir = format!("/proc/{}/task", process.tgid);
        if let Ok(entries) = fs::read_dir(task_dir) {
            self.seed_snapshot(&key, &mut state, entries);
        } else {
            state.baseline_provenance = BaselineProvenance::Unavailable;
            state.gaps.insert(ThreadGapReason::SnapshotPermission);
        }
        state.active_at_start = state.tasks.len() as u64;
        state.peak_active = state.active_at_start;
        state.baseline_complete = state.gaps.is_empty();
        self.states.insert(key, state);
    }

    fn seed_snapshot(&mut self, key: &ProcessKey, state: &mut ProcessState, entries: fs::ReadDir) {
        for entry in entries {
            let Ok(entry) = entry else {
                state.gaps.insert(ThreadGapReason::SnapshotRace);
                continue;
            };
            let Some(task_id) = entry
                .file_name()
                .to_str()
                .and_then(|value| value.parse::<u32>().ok())
            else {
                state.gaps.insert(ThreadGapReason::SnapshotRace);
                continue;
            };
            if task_id == state.process.tgid {
                continue;
            }
            if self.task_index.len() >= self.capacity {
                state.gaps.insert(ThreadGapReason::SnapshotTruncated);
                break;
            }
            let name = fs::read_to_string(entry.path().join("comm"))
                .ok()
                .map(|value| value.trim_end().to_owned())
                .filter(|value| valid_snapshot_name(value))
                .unwrap_or_else(|| {
                    state.gaps.insert(ThreadGapReason::SnapshotRace);
                    "unknown".to_owned()
                });
            let name = state.bucket_name(name);
            let task_key = self.next_task_key(task_id, 0);
            state
                .tasks
                .insert(task_key, TaskState { name: name.clone() });
            state.names.entry(name).or_default().active += 1;
            self.task_index
                .insert((key.tgid, task_id), (key.clone(), task_key));
        }
    }

    pub fn observe_rename(
        &mut self,
        process_id: u32,
        task_id: u32,
        observed_at_ns: u64,
        name: String,
    ) {
        let locator = (process_id, task_id);
        let Some((key, task_key)) = self.task_index.get(&locator).cloned() else {
            return;
        };
        if observed_at_ns < task_key.started_at_ns {
            return;
        }
        let Some(state) = self.states.get_mut(&key) else {
            return;
        };
        let new_name = state.bucket_name(name);
        let Some(task) = state.tasks.get_mut(&task_key) else {
            return;
        };
        if task.name == new_name {
            return;
        }
        if let Some(old) = state.names.get_mut(&task.name) {
            old.active = old.active.saturating_sub(1);
        }
        state.names.entry(new_name.clone()).or_default().active = state
            .names
            .get(&new_name)
            .map_or(1, |entry| entry.active.saturating_add(1));
        task.name = new_name;
    }

    pub fn observe_thread_exit(
        &mut self,
        cgroup_id: u64,
        process_id: u32,
        thread_id: u32,
        observed_at_ns: u64,
    ) {
        let key = ProcessKey {
            cgroup_id,
            tgid: process_id,
        };
        let locator = (process_id, thread_id);
        let Some((indexed_key, task_key)) = self.task_index.get(&locator).cloned() else {
            return;
        };
        if indexed_key != key || observed_at_ns < task_key.started_at_ns {
            return;
        }
        let Some(state) = self.states.get_mut(&key) else {
            return;
        };
        let Some(task) = state.tasks.remove(&task_key) else {
            state.gaps.insert(ThreadGapReason::StateCapacity);
            return;
        };
        state.exited = state.exited.saturating_add(1);
        if let Some(entry) = state.names.get_mut(&task.name) {
            entry.exited = entry.exited.saturating_add(1);
            entry.active = entry.active.saturating_sub(1);
        }
        self.task_index.remove(&locator);
    }

    pub fn observe_process_exit(&mut self, cgroup_id: u64, tgid: u32) {
        let key = ProcessKey { cgroup_id, tgid };
        if let Some(state) = self.states.remove(&key) {
            for task in state.tasks.keys() {
                self.task_index.remove(&(tgid, task.tid));
            }
        }
    }

    pub fn flush_due(&mut self, now: DateTime<Utc>) -> Vec<RuntimeEvent> {
        self.states
            .values_mut()
            .filter_map(|state| state.flush(now))
            .collect()
    }

    fn ensure_state(
        &mut self,
        key: &ProcessKey,
        observed_at: DateTime<Utc>,
        attribution: KubernetesAttribution,
        process: ProcessIdentity,
        generation: ProcessGenerationIdentity,
    ) -> bool {
        if let Some(state) = self.states.get(key) {
            if state.generation == generation {
                return true;
            }
            let tasks = state.tasks.keys().copied().collect::<Vec<_>>();
            self.states.remove(key);
            for task in tasks {
                self.task_index.remove(&(key.tgid, task.tid));
            }
        }
        if self.states.len() >= self.capacity {
            return false;
        }
        self.states.insert(
            key.clone(),
            ProcessState::new(attribution, process, generation, observed_at),
        );
        true
    }

    fn next_task_key(&mut self, tid: u32, started_at_ns: u64) -> TaskKey {
        let generation = self.next_task_generation;
        self.next_task_generation = self.next_task_generation.saturating_add(1).max(1);
        TaskKey {
            tid,
            generation,
            started_at_ns,
        }
    }

    fn retire_reused_task(&mut self, locator: (u32, u32)) {
        let Some((key, task_key)) = self.task_index.remove(&locator) else {
            return;
        };
        let Some(state) = self.states.get_mut(&key) else {
            return;
        };
        let Some(task) = state.tasks.remove(&task_key) else {
            return;
        };
        if let Some(name) = state.names.get_mut(&task.name) {
            name.active = name.active.saturating_sub(1);
            name.exited = name.exited.saturating_add(1);
        }
        state.exited = state.exited.saturating_add(1);
        state.gaps.insert(ThreadGapReason::KernelLoss);
        state.baseline_complete = false;
    }
}

impl ProcessState {
    fn new(
        attribution: KubernetesAttribution,
        process: ProcessIdentity,
        generation: ProcessGenerationIdentity,
        observed_at: DateTime<Utc>,
    ) -> Self {
        let start_observed = generation.start_observed;
        Self {
            attribution,
            process,
            generation,
            tasks: HashMap::new(),
            names: HashMap::new(),
            active_at_start: 0,
            peak_active: 0,
            created: 0,
            exited: 0,
            overflow: 0,
            gaps: HashSet::new(),
            window_start: minute_start(observed_at),
            baseline_provenance: if start_observed {
                BaselineProvenance::Observed
            } else {
                BaselineProvenance::Unavailable
            },
            baseline_complete: start_observed,
        }
    }

    fn bucket_name(&mut self, name: String) -> String {
        if self.names.contains_key(&name) || self.names.len() < MAX_THREAD_NAMES {
            return name;
        }
        self.overflow = self.overflow.saturating_add(1);
        "other".into()
    }

    fn flush(&mut self, now: DateTime<Utc>) -> Option<RuntimeEvent> {
        let end = self.window_start + Duration::seconds(60);
        if now < end {
            return None;
        }
        let names = self
            .names
            .iter()
            .map(|(name, value)| ThreadNameAggregate {
                name: name.clone(),
                created: value.created,
                exited: value.exited,
                active: value.active,
            })
            .collect::<Vec<_>>();
        let id = deterministic_window_id(&self.process, &self.generation, self.window_start);
        let window = ThreadActivityWindow {
            id,
            process: self.process.clone(),
            generation: self.generation.clone(),
            window_started_at: self.window_start,
            window_ended_at: end,
            created: self.created,
            exited: self.exited,
            active_at_start: self.active_at_start,
            active_at_end: self.tasks.len() as u64,
            peak_active: self.peak_active,
            names,
            baseline_provenance: self.baseline_provenance,
            baseline_complete: self.baseline_complete && self.gaps.is_empty(),
            name_overflow: self.overflow,
            gaps: self.gaps.iter().copied().collect(),
        };
        self.reset_window(end);
        Some(RuntimeEvent {
            id,
            observed_at: end,
            schema_version: EVENT_SCHEMA_VERSION,
            attribution: self.attribution.clone(),
            process: self.process.clone(),
            payload: EventPayload::ThreadActivityWindow(window),
        })
    }

    fn reset_window(&mut self, start: DateTime<Utc>) {
        self.window_start = start;
        self.active_at_start = self.tasks.len() as u64;
        self.peak_active = self.active_at_start;
        self.created = 0;
        self.exited = 0;
        self.overflow = 0;
        self.gaps.clear();
        for value in self.names.values_mut() {
            value.created = 0;
            value.exited = 0;
        }
    }
}

fn valid_snapshot_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= event_model::MAX_THREAD_NAME_BYTES
        && !value.chars().any(char::is_control)
}

fn minute_start(value: DateTime<Utc>) -> DateTime<Utc> {
    value
        .with_second(0)
        .and_then(|v| v.with_nanosecond(0))
        .unwrap_or(value)
}

fn deterministic_window_id(
    process: &ProcessIdentity,
    generation: &ProcessGenerationIdentity,
    start: DateTime<Utc>,
) -> Uuid {
    let mut digest = Sha256::new();
    digest.update(process.cgroup_id.to_be_bytes());
    digest.update(process.tgid.to_be_bytes());
    digest.update(generation.generation.to_be_bytes());
    digest.update(generation.observation_epoch.as_bytes());
    digest.update(
        start
            .timestamp_nanos_opt()
            .unwrap_or_default()
            .to_be_bytes(),
    );
    let mut bytes: [u8; 16] = digest.finalize()[..16].try_into().expect("fixed digest");
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attribution() -> KubernetesAttribution {
        KubernetesAttribution {
            project_id: Uuid::new_v4(),
            application_id: Uuid::new_v4(),
            node_name: "node".into(),
            namespace: "default".into(),
            pod_uid: "pod".into(),
            pod_name: "pod".into(),
            container_id: "container".into(),
            container_name: "app".into(),
            workload_uid: "workload".into(),
            workload_kind: "Deployment".into(),
            workload_name: "app".into(),
            release: None,
            release_identity: None,
        }
    }

    fn process(pid: u32) -> ProcessIdentity {
        ProcessIdentity {
            cgroup_id: 7,
            pid,
            tgid: 10,
            command: "app".into(),
        }
    }

    fn generation() -> ProcessGenerationIdentity {
        ProcessGenerationIdentity {
            generation: 1,
            observation_epoch: Uuid::from_u128(1),
            start_observed: false,
        }
    }

    fn task(tid: u32, observed_at_ns: u64, name: &str) -> TaskStart {
        TaskStart {
            tid,
            observed_at_ns,
            name: name.into(),
        }
    }

    #[test]
    fn rename_moves_active_without_inflating_lifecycle_totals() {
        let start = minute_start(Utc::now());
        let mut store = TaskLifecycleStore::new(4);
        store.observe_thread_start(
            start,
            attribution(),
            process(11),
            generation(),
            task(11, 100, "app"),
        );
        store.observe_rename(10, 11, 101, "tokio-worker".into());
        let event = store
            .flush_due(start + Duration::seconds(60))
            .pop()
            .unwrap();
        let EventPayload::ThreadActivityWindow(window) = event.payload else {
            panic!()
        };
        assert_eq!(
            (window.created, window.exited, window.active_at_end),
            (1, 0, 1)
        );
        assert_eq!(
            window.names.iter().map(|entry| entry.active).sum::<u64>(),
            1
        );
        assert_eq!(
            window
                .names
                .iter()
                .find(|entry| entry.name == "tokio-worker")
                .unwrap()
                .active,
            1
        );
    }

    #[test]
    fn non_leader_exit_updates_window_and_deterministic_identity() {
        let start = minute_start(Utc::now());
        let mut store = TaskLifecycleStore::new(4);
        store.observe_thread_start(
            start,
            attribution(),
            process(11),
            generation(),
            task(11, 100, "worker"),
        );
        store.observe_thread_exit(7, 10, 11, 101);
        let first = store
            .flush_due(start + Duration::seconds(60))
            .pop()
            .unwrap();
        let mut other = TaskLifecycleStore::new(4);
        other.observe_thread_start(
            start,
            attribution(),
            process(11),
            generation(),
            task(11, 100, "worker"),
        );
        other.observe_thread_exit(7, 10, 11, 101);
        let second = other
            .flush_due(start + Duration::seconds(60))
            .pop()
            .unwrap();
        assert_eq!(first.id, second.id);
        let EventPayload::ThreadActivityWindow(window) = first.payload else {
            panic!()
        };
        assert_eq!(
            (window.created, window.exited, window.active_at_end),
            (1, 1, 0)
        );
    }

    #[test]
    fn task_capacity_marks_window_incomplete_without_overcounting() {
        let start = minute_start(Utc::now());
        let mut store = TaskLifecycleStore::new(1);
        store.observe_thread_start(
            start,
            attribution(),
            process(11),
            generation(),
            task(11, 100, "one"),
        );
        store.observe_thread_start(
            start,
            attribution(),
            process(12),
            generation(),
            task(12, 101, "two"),
        );
        let event = store
            .flush_due(start + Duration::seconds(60))
            .pop()
            .unwrap();
        let EventPayload::ThreadActivityWindow(window) = event.payload else {
            panic!()
        };
        assert_eq!((window.created, window.active_at_end), (1, 1));
        assert!(window.gaps.contains(&ThreadGapReason::StateCapacity));
        assert!(!window.baseline_complete);
    }

    #[test]
    fn tid_reuse_rejects_stale_rename_and_exit_for_the_prior_task_generation() {
        let start = minute_start(Utc::now());
        let mut store = TaskLifecycleStore::new(4);
        store.observe_thread_start(
            start,
            attribution(),
            process(11),
            generation(),
            task(11, 100, "old"),
        );
        store.observe_thread_start(
            start,
            attribution(),
            process(11),
            generation(),
            task(11, 200, "new"),
        );
        store.observe_rename(10, 11, 150, "stale".into());
        store.observe_thread_exit(7, 10, 11, 150);
        store.observe_rename(10, 11, 201, "current".into());
        store.observe_thread_exit(7, 10, 11, 202);
        let event = store
            .flush_due(start + Duration::seconds(60))
            .pop()
            .unwrap();
        let EventPayload::ThreadActivityWindow(window) = event.payload else {
            panic!()
        };
        assert_eq!(
            (window.created, window.exited, window.active_at_end),
            (2, 2, 0)
        );
        assert!(window.names.iter().all(|name| name.name != "stale"));
        assert!(window.gaps.contains(&ThreadGapReason::KernelLoss));
        assert!(!window.baseline_complete);
    }

    #[test]
    fn failed_snapshot_is_explicit_and_never_fabricates_starts() {
        let start = minute_start(Utc::now());
        let mut store = TaskLifecycleStore::new(4);
        let mut existing = process(4_000_000_000);
        existing.tgid = 4_000_000_000;
        store.bootstrap_process(start, attribution(), &existing, generation());
        let event = store
            .flush_due(start + Duration::seconds(60))
            .pop()
            .unwrap();
        let EventPayload::ThreadActivityWindow(window) = event.payload else {
            panic!()
        };
        assert_eq!((window.created, window.exited), (0, 0));
        assert_eq!(window.baseline_provenance, BaselineProvenance::Unavailable);
        assert!(!window.baseline_complete);
        assert!(window.gaps.contains(&ThreadGapReason::SnapshotPermission));
    }

    #[test]
    fn fork_storm_shared_names_repeated_rename_and_short_lived_tasks_reconcile() {
        let start = minute_start(Utc::now());
        let mut store = TaskLifecycleStore::new(8_192);
        for tid in 11..=4_010 {
            store.observe_thread_start(
                start,
                attribution(),
                process(tid),
                generation(),
                task(tid, u64::from(tid), "worker"),
            );
            store.observe_rename(10, tid, u64::from(tid) + 1, "renamed".into());
            store.observe_rename(10, tid, u64::from(tid) + 2, "renamed".into());
            if tid % 2 == 0 {
                store.observe_thread_exit(7, 10, tid, u64::from(tid) + 3);
            }
        }
        let event = store
            .flush_due(start + Duration::seconds(60))
            .pop()
            .unwrap();
        let EventPayload::ThreadActivityWindow(window) = event.payload else {
            panic!()
        };
        assert_eq!((window.created, window.exited), (4_000, 2_000));
        assert_eq!((window.active_at_end, window.peak_active), (2_000, 2_001));
        assert_eq!(
            window.names.iter().map(|name| name.created).sum::<u64>(),
            4_000
        );
        assert_eq!(
            window.names.iter().map(|name| name.exited).sum::<u64>(),
            2_000
        );
        assert_eq!(
            window.names.iter().map(|name| name.active).sum::<u64>(),
            2_000
        );
    }
}
