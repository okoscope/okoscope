use std::{
    collections::{BTreeMap, VecDeque},
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

use event_model::RuntimeEvent;

use crate::counters::Counters;

#[derive(Clone, Debug)]
pub struct PendingBatch {
    pub sequence: u64,
    pub events: Vec<RuntimeEvent>,
}

#[derive(Debug)]
pub struct EventRateLimiter {
    max_events_per_second: u32,
    window_started: Instant,
    accepted: u32,
}

impl EventRateLimiter {
    #[must_use]
    pub fn new(max_events_per_second: u32) -> Self {
        assert!(max_events_per_second > 0);
        Self {
            max_events_per_second,
            window_started: Instant::now(),
            accepted: 0,
        }
    }

    pub fn allow(&mut self) -> bool {
        self.allow_at(Instant::now())
    }

    fn allow_at(&mut self, now: Instant) -> bool {
        if now.duration_since(self.window_started) >= Duration::from_secs(1) {
            self.window_started = now;
            self.accepted = 0;
        }
        if self.accepted >= self.max_events_per_second {
            return false;
        }
        self.accepted += 1;
        true
    }
}

#[derive(Debug)]
pub struct EventBuffer {
    capacity: usize,
    batch_size: usize,
    next_sequence: u64,
    queued: VecDeque<RuntimeEvent>,
    pending: BTreeMap<u64, PendingBatch>,
}

impl EventBuffer {
    #[must_use]
    pub fn new(capacity: usize, batch_size: usize) -> Self {
        assert!(capacity > 0 && batch_size > 0 && batch_size <= capacity);
        Self {
            capacity,
            batch_size,
            next_sequence: 1,
            queued: VecDeque::new(),
            pending: BTreeMap::new(),
        }
    }

    pub fn push(&mut self, event: RuntimeEvent, counters: &Counters) -> bool {
        let occupied = self.queued.len()
            + self
                .pending
                .values()
                .map(|batch| batch.events.len())
                .sum::<usize>();
        if occupied >= self.capacity {
            counters.capacity_dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        self.queued.push_back(event);
        true
    }

    pub fn next_batch(&mut self, counters: &Counters) -> Option<PendingBatch> {
        if self.queued.is_empty() {
            return None;
        }
        let count = self.batch_size.min(self.queued.len());
        let events = self.queued.drain(..count).collect();
        let batch = PendingBatch {
            sequence: self.next_sequence,
            events,
        };
        self.next_sequence = self.next_sequence.saturating_add(1);
        counters
            .sent
            .fetch_add(batch.events.len() as u64, Ordering::Relaxed);
        self.pending.insert(batch.sequence, batch.clone());
        Some(batch)
    }

    pub fn acknowledge(&mut self, sequence: u64, counters: &Counters) -> bool {
        let Some(batch) = self.pending.remove(&sequence) else {
            return false;
        };
        counters
            .acknowledged
            .fetch_add(batch.events.len() as u64, Ordering::Relaxed);
        true
    }

    #[must_use]
    pub fn replay_pending(&self, counters: &Counters) -> Vec<PendingBatch> {
        let batches: Vec<_> = self.pending.values().cloned().collect();
        counters.retried.fetch_add(
            batches.iter().map(|batch| batch.events.len() as u64).sum(),
            Ordering::Relaxed,
        );
        batches
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use event_model::{
        EVENT_SCHEMA_VERSION, EventPayload, KubernetesAttribution, ProcessExec, ProcessIdentity,
    };
    use uuid::Uuid;

    #[cfg(unix)]
    fn resident_kib() -> u64 {
        let output = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .unwrap();
        String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    fn event() -> RuntimeEvent {
        RuntimeEvent {
            id: Uuid::new_v4(),
            observed_at: Utc::now(),
            schema_version: EVENT_SCHEMA_VERSION,
            attribution: KubernetesAttribution {
                project_id: Uuid::new_v4(),
                application_id: Uuid::new_v4(),
                node_name: "node".into(),
                namespace: "ns".into(),
                pod_uid: "p".into(),
                pod_name: "p".into(),
                container_id: "c".into(),
                container_name: "c".into(),
                workload_uid: "w".into(),
                workload_kind: "Deployment".into(),
                workload_name: "app".into(),
                release: None,
                release_identity: None,
            },
            process: ProcessIdentity {
                cgroup_id: 1,
                pid: 1,
                tgid: 1,
                command: "sh".into(),
            },
            payload: EventPayload::ProcessExec(ProcessExec {
                executable: "/bin/sh".into(),
                parent_command: None,
            }),
        }
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "acceptance benchmark; set OKOSCOPE_BENCHMARK_STREAMS"]
    fn application_queue_memory_is_bounded() {
        let streams = std::env::var("OKOSCOPE_BENCHMARK_STREAMS")
            .unwrap_or_else(|_| "32".into())
            .parse::<usize>()
            .unwrap();
        let capacity = 4096;
        let before = resident_kib();
        let counters = Counters::default();
        let mut buffers: Vec<_> = (0..streams)
            .map(|_| EventBuffer::new(capacity, 256))
            .collect();
        for buffer in &mut buffers {
            for _ in 0..capacity {
                assert!(buffer.push(event(), &counters));
            }
            assert!(!buffer.push(event(), &counters));
        }
        let after = resident_kib();
        println!(
            "application queue benchmark: streams={streams} capacity={capacity} queued={} rss_delta_kib={}",
            streams * capacity,
            after.saturating_sub(before)
        );
        assert_eq!(counters.snapshot().capacity_dropped, streams as u64);
    }

    #[test]
    fn bounds_batches_retries_and_acknowledges() {
        let counters = Counters::default();
        let mut buffer = EventBuffer::new(2, 2);
        assert!(buffer.push(event(), &counters));
        assert!(buffer.push(event(), &counters));
        assert!(!buffer.push(event(), &counters));
        let batch = buffer.next_batch(&counters).unwrap();
        assert_eq!(batch.events.len(), 2);
        assert_eq!(buffer.replay_pending(&counters).len(), 1);
        assert!(buffer.acknowledge(batch.sequence, &counters));
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.capacity_dropped, 1);
        assert_eq!(snapshot.acknowledged, 2);
        assert_eq!(snapshot.retried, 2);
    }

    #[test]
    fn rate_limiter_bounds_each_one_second_window() {
        let start = Instant::now();
        let mut limiter = EventRateLimiter {
            max_events_per_second: 2,
            window_started: start,
            accepted: 0,
        };
        assert!(limiter.allow_at(start));
        assert!(limiter.allow_at(start + Duration::from_millis(500)));
        assert!(!limiter.allow_at(start + Duration::from_millis(999)));
        assert!(limiter.allow_at(start + Duration::from_secs(1)));
    }
}
