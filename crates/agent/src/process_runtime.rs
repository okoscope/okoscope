use std::collections::{HashMap, HashSet, VecDeque};

use event_model::{GenerationCorrelation, UnresolvedGenerationReason};
use uuid::Uuid;

#[derive(Clone, Debug)]
struct ExecGeneration {
    cgroup_id: u64,
    observed_at_ns: u64,
    generation: u64,
    event_id: Uuid,
    executable: String,
}

#[derive(Debug)]
pub struct ProcessGenerationStore {
    capacity: usize,
    entries: HashMap<u64, ExecGeneration>,
    last_generation: HashMap<u64, u64>,
    lru: VecDeque<(u64, u64)>,
    evicted: HashSet<u64>,
}

impl ProcessGenerationStore {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: HashMap::with_capacity(capacity),
            last_generation: HashMap::with_capacity(capacity),
            lru: VecDeque::with_capacity(capacity),
            evicted: HashSet::with_capacity(capacity),
        }
    }

    pub fn observe_exec(
        &mut self,
        pid_tgid: u64,
        cgroup_id: u64,
        observed_at_ns: u64,
        event_id: Uuid,
        executable: String,
    ) -> u64 {
        let generation = self
            .last_generation
            .get(&pid_tgid)
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
        self.last_generation.insert(pid_tgid, generation);
        self.entries.insert(
            pid_tgid,
            ExecGeneration {
                cgroup_id,
                observed_at_ns,
                generation,
                event_id,
                executable,
            },
        );
        self.evicted.remove(&pid_tgid);
        self.lru.push_back((pid_tgid, generation));
        self.enforce_capacity();
        generation
    }

    pub fn consume_exit(
        &mut self,
        pid_tgid: u64,
        cgroup_id: u64,
        observed_at_ns: u64,
    ) -> GenerationCorrelation {
        let Some(entry) = self.entries.get(&pid_tgid) else {
            return GenerationCorrelation::Unresolved {
                reason: if self.evicted.contains(&pid_tgid) {
                    UnresolvedGenerationReason::Evicted
                } else {
                    UnresolvedGenerationReason::BeforeObservation
                },
            };
        };
        if entry.cgroup_id != cgroup_id {
            return GenerationCorrelation::Unresolved {
                reason: UnresolvedGenerationReason::ContainerLifetimeMismatch,
            };
        }
        if entry.observed_at_ns > observed_at_ns {
            return GenerationCorrelation::Unresolved {
                reason: UnresolvedGenerationReason::GenerationMismatch,
            };
        }
        let entry = self.entries.remove(&pid_tgid).expect("entry was present");
        GenerationCorrelation::observed(entry.generation, entry.event_id, entry.executable)
            .expect("store admits only valid observed generations")
    }

    fn enforce_capacity(&mut self) {
        while self.entries.len() > self.capacity {
            let Some((pid_tgid, generation)) = self.lru.pop_front() else {
                break;
            };
            if self
                .entries
                .get(&pid_tgid)
                .is_some_and(|entry| entry.generation == generation)
            {
                self.entries.remove(&pid_tgid);
                self.evicted.insert(pid_tgid);
                while self.evicted.len() > self.capacity.max(1) {
                    if let Some(value) = self.evicted.iter().next().copied() {
                        self.evicted.remove(&value);
                    }
                }
            }
        }
        while self.last_generation.len() > self.capacity.max(1) * 2 {
            if let Some(key) = self
                .last_generation
                .keys()
                .find(|key| !self.entries.contains_key(key))
                .copied()
            {
                self.last_generation.remove(&key);
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_generation_is_consumed_once() {
        let mut store = ProcessGenerationStore::new(2);
        let event_id = Uuid::new_v4();
        assert_eq!(
            store.observe_exec(10, 20, 100, event_id, "/app/worker".into()),
            1
        );
        assert!(matches!(
            store.consume_exit(10, 20, 101),
            GenerationCorrelation::Observed {
                generation: 1,
                exec_event_id,
                ..
            } if exec_event_id == event_id
        ));
        assert!(matches!(
            store.consume_exit(10, 20, 102),
            GenerationCorrelation::Unresolved {
                reason: UnresolvedGenerationReason::BeforeObservation
            }
        ));
    }

    #[test]
    fn delayed_exit_cannot_attach_a_reused_pid_generation() {
        let mut store = ProcessGenerationStore::new(2);
        store.observe_exec(10, 20, 100, Uuid::new_v4(), "/old".into());
        store.observe_exec(10, 20, 200, Uuid::new_v4(), "/new".into());
        assert!(matches!(
            store.consume_exit(10, 20, 150),
            GenerationCorrelation::Unresolved {
                reason: UnresolvedGenerationReason::GenerationMismatch
            }
        ));
    }

    #[test]
    fn eviction_and_container_mismatch_are_explicit() {
        let mut store = ProcessGenerationStore::new(1);
        store.observe_exec(10, 20, 100, Uuid::new_v4(), "/one".into());
        store.observe_exec(11, 20, 101, Uuid::new_v4(), "/two".into());
        assert!(matches!(
            store.consume_exit(10, 20, 102),
            GenerationCorrelation::Unresolved {
                reason: UnresolvedGenerationReason::Evicted
            }
        ));
        assert!(matches!(
            store.consume_exit(11, 99, 102),
            GenerationCorrelation::Unresolved {
                reason: UnresolvedGenerationReason::ContainerLifetimeMismatch
            }
        ));
    }
}
