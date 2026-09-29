use std::collections::{HashMap, HashSet, VecDeque};

use event_model::{GenerationCorrelation, ProcessGenerationIdentity, UnresolvedGenerationReason};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct ProcessKey {
    cgroup_id: u64,
    tgid: u32,
}

#[derive(Clone, Debug)]
struct ProcessGeneration {
    identity: ProcessGenerationIdentity,
    observed_at_ns: u64,
    exec: Option<ExecEvidence>,
}

#[derive(Clone, Debug)]
struct ExecEvidence {
    event_id: Uuid,
    executable: String,
}

#[derive(Clone, Debug)]
pub struct ConsumedGeneration {
    pub identity: Option<ProcessGenerationIdentity>,
    pub correlation: GenerationCorrelation,
}

#[derive(Debug)]
pub struct ProcessGenerationStore {
    capacity: usize,
    epoch: Uuid,
    next_generation: u64,
    entries: HashMap<ProcessKey, ProcessGeneration>,
    lru: VecDeque<(ProcessKey, u64)>,
    evicted: HashSet<ProcessKey>,
}

impl ProcessGenerationStore {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            epoch: Uuid::new_v4(),
            next_generation: 1,
            entries: HashMap::with_capacity(capacity),
            lru: VecDeque::with_capacity(capacity),
            evicted: HashSet::with_capacity(capacity),
        }
    }

    pub fn observe_start(
        &mut self,
        cgroup_id: u64,
        tgid: u32,
        at: u64,
    ) -> ProcessGenerationIdentity {
        self.allocate(ProcessKey { cgroup_id, tgid }, at, true)
    }

    pub fn ensure_generation(
        &mut self,
        cgroup_id: u64,
        tgid: u32,
        at: u64,
    ) -> ProcessGenerationIdentity {
        let key = ProcessKey { cgroup_id, tgid };
        if let Some(entry) = self.entries.get(&key) {
            return entry.identity.clone();
        }
        self.allocate(key, at, false)
    }

    pub fn observe_exec(
        &mut self,
        cgroup_id: u64,
        tgid: u32,
        at: u64,
        event_id: Uuid,
        executable: String,
    ) -> ProcessGenerationIdentity {
        let identity = self.ensure_generation(cgroup_id, tgid, at);
        let key = ProcessKey { cgroup_id, tgid };
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.exec = Some(ExecEvidence {
                event_id,
                executable,
            });
        }
        identity
    }

    pub fn consume_exit(&mut self, cgroup_id: u64, tgid: u32, at: u64) -> ConsumedGeneration {
        let key = ProcessKey { cgroup_id, tgid };
        if self.evicted.contains(&key) && !self.entries.contains_key(&key) {
            return unresolved(None, UnresolvedGenerationReason::Evicted);
        }
        self.ensure_generation(cgroup_id, tgid, at);
        let Some(entry) = self.entries.get(&key) else {
            return unresolved(None, UnresolvedGenerationReason::BeforeObservation);
        };
        if entry.observed_at_ns > at {
            return unresolved(None, UnresolvedGenerationReason::GenerationMismatch);
        }
        let entry = self.entries.remove(&key).expect("entry was present");
        let correlation = entry.exec.map_or(
            GenerationCorrelation::Unresolved {
                reason: UnresolvedGenerationReason::BeforeObservation,
            },
            |exec| {
                GenerationCorrelation::observed(
                    entry.identity.generation,
                    exec.event_id,
                    exec.executable,
                )
                .expect("stored exec evidence is valid")
            },
        );
        ConsumedGeneration {
            identity: Some(entry.identity),
            correlation,
        }
    }

    fn allocate(
        &mut self,
        key: ProcessKey,
        at: u64,
        start_observed: bool,
    ) -> ProcessGenerationIdentity {
        let generation = self.next_generation;
        self.next_generation = self.next_generation.saturating_add(1).max(1);
        let identity = ProcessGenerationIdentity {
            generation,
            observation_epoch: self.epoch,
            start_observed,
        };
        self.entries.insert(
            key,
            ProcessGeneration {
                identity: identity.clone(),
                observed_at_ns: at,
                exec: None,
            },
        );
        self.evicted.remove(&key);
        self.lru.push_back((key, generation));
        self.enforce_capacity();
        identity
    }

    fn enforce_capacity(&mut self) {
        while self.entries.len() > self.capacity {
            let Some((key, generation)) = self.lru.pop_front() else {
                break;
            };
            if self
                .entries
                .get(&key)
                .is_some_and(|entry| entry.identity.generation == generation)
            {
                self.entries.remove(&key);
                self.evicted.insert(key);
            }
        }
        while self.evicted.len() > self.capacity.max(1) {
            if let Some(key) = self.evicted.iter().next().copied() {
                self.evicted.remove(&key);
            }
        }
    }
}

fn unresolved(
    identity: Option<ProcessGenerationIdentity>,
    reason: UnresolvedGenerationReason,
) -> ConsumedGeneration {
    ConsumedGeneration {
        identity,
        correlation: GenerationCorrelation::Unresolved { reason },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_exec_repeated_exec_and_exit_share_one_generation() {
        let mut store = ProcessGenerationStore::new(2);
        let start = store.observe_start(20, 10, 100);
        let first = Uuid::new_v4();
        assert_eq!(store.observe_exec(20, 10, 101, first, "/one".into()), start);
        let second = Uuid::new_v4();
        assert_eq!(
            store.observe_exec(20, 10, 102, second, "/two".into()),
            start
        );
        let exit = store.consume_exit(20, 10, 103);
        assert_eq!(exit.identity, Some(start));
        assert!(
            matches!(exit.correlation, GenerationCorrelation::Observed { exec_event_id, executable, .. } if exec_event_id == second && executable == "/two")
        );
    }

    #[test]
    fn exec_first_is_synthetic_and_pid_reuse_allocates_new_generation() {
        let mut store = ProcessGenerationStore::new(2);
        let first = store.observe_exec(20, 10, 100, Uuid::new_v4(), "/one".into());
        assert!(!first.start_observed);
        store.consume_exit(20, 10, 101);
        let reused = store.observe_start(20, 10, 200);
        assert!(reused.start_observed);
        assert_eq!(reused.generation, first.generation + 1);
    }

    #[test]
    fn exit_first_is_synthetic_and_eviction_is_not_rejoined() {
        let mut store = ProcessGenerationStore::new(1);
        let exit = store.consume_exit(20, 10, 100);
        assert!(exit.identity.is_some_and(|value| !value.start_observed));
        store.observe_start(20, 10, 101);
        store.observe_start(20, 11, 102);
        let evicted = store.consume_exit(20, 10, 103);
        assert!(evicted.identity.is_none());
        assert!(matches!(
            evicted.correlation,
            GenerationCorrelation::Unresolved {
                reason: UnresolvedGenerationReason::Evicted
            }
        ));
    }

    #[test]
    fn delayed_exit_cannot_consume_a_reused_pid_generation() {
        let mut store = ProcessGenerationStore::new(2);
        store.observe_start(20, 10, 100);
        let current = store.observe_start(20, 10, 200);
        let delayed = store.consume_exit(20, 10, 150);
        assert_eq!(delayed.identity, None);
        assert!(matches!(
            delayed.correlation,
            GenerationCorrelation::Unresolved {
                reason: UnresolvedGenerationReason::GenerationMismatch
            }
        ));
        assert_eq!(store.consume_exit(20, 10, 201).identity, Some(current));
    }

    #[test]
    fn agent_restart_uses_a_distinct_observation_epoch() {
        let mut first = ProcessGenerationStore::new(1);
        let mut restarted = ProcessGenerationStore::new(1);
        let before = first.observe_start(20, 10, 100);
        let after = restarted.ensure_generation(20, 10, 101);
        assert_ne!(before.observation_epoch, after.observation_epoch);
        assert!(!after.start_observed);
    }
}
