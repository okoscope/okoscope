use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct Counters {
    pub filtered: AtomicU64,
    pub unattributed: AtomicU64,
    pub unsupported: AtomicU64,
    pub decode_failed: AtomicU64,
    pub capacity_dropped: AtomicU64,
    pub kernel_lost: AtomicU64,
    pub connect_correlation_capacity: AtomicU64,
    pub connect_correlation_miss: AtomicU64,
    pub connect_decode_failed: AtomicU64,
    pub connect_unsupported_family: AtomicU64,
    pub connect_kernel_lost: AtomicU64,
    pub inbound_decode_failed: AtomicU64,
    pub inbound_attribution_failed: AtomicU64,
    pub inbound_unsupported_family: AtomicU64,
    pub inbound_kernel_lost: AtomicU64,
    pub inbound_rate_limited: AtomicU64,
    pub inbound_correlation_miss: AtomicU64,
    pub dns_packet_decode_failed: AtomicU64,
    pub dns_malformed_compression: AtomicU64,
    pub dns_truncated: AtomicU64,
    pub dns_unsupported_record: AtomicU64,
    pub dns_correlation_miss: AtomicU64,
    pub dns_correlation_capacity: AtomicU64,
    pub dns_tcp_reassembly: AtomicU64,
    pub dns_rate_limited: AtomicU64,
    pub dns_capacity: AtomicU64,
    pub dns_kernel_lost: AtomicU64,
    pub dns_kernel_unsupported_framing: AtomicU64,
    pub dns_attribution_failed: AtomicU64,
    pub dns_oversize: AtomicU64,
    pub file_correlation_capacity: AtomicU64,
    pub file_correlation_miss: AtomicU64,
    pub file_path_read_failed: AtomicU64,
    pub file_path_relative: AtomicU64,
    pub file_path_invalid: AtomicU64,
    pub file_path_oversize: AtomicU64,
    pub file_fd_miss: AtomicU64,
    pub file_filtered: AtomicU64,
    pub file_kernel_lost: AtomicU64,
    pub file_aggregation_capacity: AtomicU64,
    pub file_decode_failed: AtomicU64,
    pub file_attribution_failed: AtomicU64,
    pub file_rate_limited: AtomicU64,
    pub file_unsupported_object: AtomicU64,
    pub exit_decode_failed: AtomicU64,
    pub exit_kernel_lost: AtomicU64,
    pub exit_attribution_failed: AtomicU64,
    pub exit_rate_limited: AtomicU64,
    pub exit_correlation_before_observation: AtomicU64,
    pub exit_correlation_evicted: AtomicU64,
    pub exit_correlation_generation_mismatch: AtomicU64,
    pub exit_correlation_container_mismatch: AtomicU64,
    pub lifecycle_capacity: AtomicU64,
    pub lifecycle_invalid_status: AtomicU64,
    pub lifecycle_deduplicated: AtomicU64,
    pub lifecycle_attribution_failed: AtomicU64,
    pub sent: AtomicU64,
    pub retried: AtomicU64,
    pub acknowledged: AtomicU64,
    pub release_evidence_complete: AtomicU64,
    pub release_evidence_incomplete: AtomicU64,
    pub release_evidence_duplicate: AtomicU64,
    pub release_evidence_conflict: AtomicU64,
    pub release_evidence_sent: AtomicU64,
    pub release_evidence_replayed: AtomicU64,
    pub release_evidence_dropped: AtomicU64,
    pub resource_discovered: AtomicU64,
    pub resource_parse_failed: AtomicU64,
    pub resource_counter_reset: AtomicU64,
    pub resource_attribution_failed: AtomicU64,
    pub resource_state_capacity_dropped: AtomicU64,
    pub resource_aggregate_capacity_dropped: AtomicU64,
    pub resource_queue_dropped: AtomicU64,
    pub resource_expired: AtomicU64,
    pub resource_retried: AtomicU64,
    pub resource_acknowledged: AtomicU64,
    pub resource_unsupported_sources: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CounterSnapshot {
    pub filtered: u64,
    pub unattributed: u64,
    pub unsupported: u64,
    pub decode_failed: u64,
    pub capacity_dropped: u64,
    pub kernel_lost: u64,
    pub connect_correlation_capacity: u64,
    pub connect_correlation_miss: u64,
    pub connect_decode_failed: u64,
    pub connect_unsupported_family: u64,
    pub connect_kernel_lost: u64,
    pub inbound_decode_failed: u64,
    pub inbound_attribution_failed: u64,
    pub inbound_unsupported_family: u64,
    pub inbound_kernel_lost: u64,
    pub inbound_rate_limited: u64,
    pub inbound_correlation_miss: u64,
    pub dns_packet_decode_failed: u64,
    pub dns_malformed_compression: u64,
    pub dns_truncated: u64,
    pub dns_unsupported_record: u64,
    pub dns_correlation_miss: u64,
    pub dns_correlation_capacity: u64,
    pub dns_tcp_reassembly: u64,
    pub dns_rate_limited: u64,
    pub dns_capacity: u64,
    pub dns_kernel_lost: u64,
    pub dns_kernel_unsupported_framing: u64,
    pub dns_attribution_failed: u64,
    pub dns_oversize: u64,
    pub file_correlation_capacity: u64,
    pub file_correlation_miss: u64,
    pub file_path_read_failed: u64,
    pub file_path_relative: u64,
    pub file_path_invalid: u64,
    pub file_path_oversize: u64,
    pub file_fd_miss: u64,
    pub file_filtered: u64,
    pub file_kernel_lost: u64,
    pub file_aggregation_capacity: u64,
    pub file_decode_failed: u64,
    pub file_attribution_failed: u64,
    pub file_rate_limited: u64,
    pub file_unsupported_object: u64,
    pub exit_decode_failed: u64,
    pub exit_kernel_lost: u64,
    pub exit_attribution_failed: u64,
    pub exit_rate_limited: u64,
    pub exit_correlation_before_observation: u64,
    pub exit_correlation_evicted: u64,
    pub exit_correlation_generation_mismatch: u64,
    pub exit_correlation_container_mismatch: u64,
    pub lifecycle_capacity: u64,
    pub lifecycle_invalid_status: u64,
    pub lifecycle_deduplicated: u64,
    pub lifecycle_attribution_failed: u64,
    pub sent: u64,
    pub retried: u64,
    pub acknowledged: u64,
    pub release_evidence_complete: u64,
    pub release_evidence_incomplete: u64,
    pub release_evidence_duplicate: u64,
    pub release_evidence_conflict: u64,
    pub release_evidence_sent: u64,
    pub release_evidence_replayed: u64,
    pub release_evidence_dropped: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetworkKernelCounters {
    pub correlation_capacity: u64,
    pub correlation_miss: u64,
    pub decode_failed: u64,
    pub unsupported_family: u64,
    pub kernel_lost: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DnsKernelCounters {
    pub unsupported_framing: u64,
    pub attribution_failed: u64,
    pub decode_failed: u64,
    pub oversize: u64,
    pub ring_lost: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InboundKernelCounters {
    pub decode_failed: u64,
    pub attribution_failed: u64,
    pub unsupported_family: u64,
    pub kernel_lost: u64,
    pub correlation_miss: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileKernelCounters {
    pub correlation_capacity: u64,
    pub correlation_miss: u64,
    pub path_read_failed: u64,
    pub path_relative: u64,
    pub path_invalid: u64,
    pub path_oversize: u64,
    pub fd_miss: u64,
    pub filtered: u64,
    pub kernel_lost: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExitKernelCounters {
    pub ring_lost: u64,
}

impl Counters {
    #[must_use]
    pub fn resource_snapshot(&self) -> protocol::v1::ResourceCounters {
        let load = |value: &AtomicU64| value.load(Ordering::Relaxed);
        protocol::v1::ResourceCounters {
            discovered: load(&self.resource_discovered),
            parse_failed: load(&self.resource_parse_failed),
            counter_reset: load(&self.resource_counter_reset),
            attribution_failed: load(&self.resource_attribution_failed),
            state_capacity_dropped: load(&self.resource_state_capacity_dropped),
            aggregate_capacity_dropped: load(&self.resource_aggregate_capacity_dropped),
            queue_dropped: load(&self.resource_queue_dropped),
            expired: load(&self.resource_expired),
            retried: load(&self.resource_retried),
            acknowledged: load(&self.resource_acknowledged),
            unsupported_sources: load(&self.resource_unsupported_sources),
        }
    }

    pub fn update_exit_kernel(&self, value: ExitKernelCounters) {
        self.exit_kernel_lost
            .store(value.ring_lost, Ordering::Relaxed);
    }

    pub fn update_file_kernel(&self, value: FileKernelCounters) {
        self.file_correlation_capacity
            .store(value.correlation_capacity, Ordering::Relaxed);
        self.file_correlation_miss
            .store(value.correlation_miss, Ordering::Relaxed);
        self.file_path_read_failed
            .store(value.path_read_failed, Ordering::Relaxed);
        self.file_path_relative
            .store(value.path_relative, Ordering::Relaxed);
        // Invalid normalized paths and configured filtering are enforced in userspace.
        // Keep those monotonic counters independent from the kernel snapshot.
        self.file_path_oversize
            .store(value.path_oversize, Ordering::Relaxed);
        self.file_fd_miss.store(value.fd_miss, Ordering::Relaxed);
        self.file_kernel_lost
            .store(value.kernel_lost, Ordering::Relaxed);
    }

    pub fn update_inbound_kernel(&self, value: InboundKernelCounters) {
        self.inbound_decode_failed
            .store(value.decode_failed, Ordering::Relaxed);
        self.inbound_attribution_failed
            .store(value.attribution_failed, Ordering::Relaxed);
        self.inbound_unsupported_family
            .store(value.unsupported_family, Ordering::Relaxed);
        self.inbound_kernel_lost
            .store(value.kernel_lost, Ordering::Relaxed);
        self.inbound_correlation_miss
            .store(value.correlation_miss, Ordering::Relaxed);
    }

    pub fn update_dns_kernel(&self, value: DnsKernelCounters) {
        self.dns_packet_decode_failed
            .store(value.decode_failed, Ordering::Relaxed);
        self.dns_kernel_unsupported_framing
            .store(value.unsupported_framing, Ordering::Relaxed);
        self.dns_oversize.store(value.oversize, Ordering::Relaxed);
        self.dns_kernel_lost
            .store(value.ring_lost, Ordering::Relaxed);
        self.dns_attribution_failed
            .store(value.attribution_failed, Ordering::Relaxed);
    }

    pub fn update_network_kernel(&self, value: NetworkKernelCounters) {
        self.connect_correlation_capacity
            .store(value.correlation_capacity, Ordering::Relaxed);
        self.connect_correlation_miss
            .store(value.correlation_miss, Ordering::Relaxed);
        self.connect_decode_failed
            .store(value.decode_failed, Ordering::Relaxed);
        self.connect_unsupported_family
            .store(value.unsupported_family, Ordering::Relaxed);
        self.connect_kernel_lost
            .store(value.kernel_lost, Ordering::Relaxed);
    }

    #[must_use]
    pub fn snapshot(&self) -> CounterSnapshot {
        let load = |value: &AtomicU64| value.load(Ordering::Relaxed);
        CounterSnapshot {
            filtered: load(&self.filtered),
            unattributed: load(&self.unattributed),
            unsupported: load(&self.unsupported),
            decode_failed: load(&self.decode_failed),
            capacity_dropped: load(&self.capacity_dropped),
            kernel_lost: load(&self.kernel_lost),
            connect_correlation_capacity: load(&self.connect_correlation_capacity),
            connect_correlation_miss: load(&self.connect_correlation_miss),
            connect_decode_failed: load(&self.connect_decode_failed),
            connect_unsupported_family: load(&self.connect_unsupported_family),
            connect_kernel_lost: load(&self.connect_kernel_lost),
            inbound_decode_failed: load(&self.inbound_decode_failed),
            inbound_attribution_failed: load(&self.inbound_attribution_failed),
            inbound_unsupported_family: load(&self.inbound_unsupported_family),
            inbound_kernel_lost: load(&self.inbound_kernel_lost),
            inbound_rate_limited: load(&self.inbound_rate_limited),
            inbound_correlation_miss: load(&self.inbound_correlation_miss),
            dns_packet_decode_failed: load(&self.dns_packet_decode_failed),
            dns_malformed_compression: load(&self.dns_malformed_compression),
            dns_truncated: load(&self.dns_truncated),
            dns_unsupported_record: load(&self.dns_unsupported_record),
            dns_correlation_miss: load(&self.dns_correlation_miss),
            dns_correlation_capacity: load(&self.dns_correlation_capacity),
            dns_tcp_reassembly: load(&self.dns_tcp_reassembly),
            dns_rate_limited: load(&self.dns_rate_limited),
            dns_capacity: load(&self.dns_capacity),
            dns_kernel_lost: load(&self.dns_kernel_lost),
            dns_kernel_unsupported_framing: load(&self.dns_kernel_unsupported_framing),
            dns_attribution_failed: load(&self.dns_attribution_failed),
            dns_oversize: load(&self.dns_oversize),
            file_correlation_capacity: load(&self.file_correlation_capacity),
            file_correlation_miss: load(&self.file_correlation_miss),
            file_path_read_failed: load(&self.file_path_read_failed),
            file_path_relative: load(&self.file_path_relative),
            file_path_invalid: load(&self.file_path_invalid),
            file_path_oversize: load(&self.file_path_oversize),
            file_fd_miss: load(&self.file_fd_miss),
            file_filtered: load(&self.file_filtered),
            file_kernel_lost: load(&self.file_kernel_lost),
            file_aggregation_capacity: load(&self.file_aggregation_capacity),
            file_decode_failed: load(&self.file_decode_failed),
            file_attribution_failed: load(&self.file_attribution_failed),
            file_rate_limited: load(&self.file_rate_limited),
            file_unsupported_object: load(&self.file_unsupported_object),
            exit_decode_failed: load(&self.exit_decode_failed),
            exit_kernel_lost: load(&self.exit_kernel_lost),
            exit_attribution_failed: load(&self.exit_attribution_failed),
            exit_rate_limited: load(&self.exit_rate_limited),
            exit_correlation_before_observation: load(&self.exit_correlation_before_observation),
            exit_correlation_evicted: load(&self.exit_correlation_evicted),
            exit_correlation_generation_mismatch: load(&self.exit_correlation_generation_mismatch),
            exit_correlation_container_mismatch: load(&self.exit_correlation_container_mismatch),
            lifecycle_capacity: load(&self.lifecycle_capacity),
            lifecycle_invalid_status: load(&self.lifecycle_invalid_status),
            lifecycle_deduplicated: load(&self.lifecycle_deduplicated),
            lifecycle_attribution_failed: load(&self.lifecycle_attribution_failed),
            sent: load(&self.sent),
            retried: load(&self.retried),
            acknowledged: load(&self.acknowledged),
            release_evidence_complete: load(&self.release_evidence_complete),
            release_evidence_incomplete: load(&self.release_evidence_incomplete),
            release_evidence_duplicate: load(&self.release_evidence_duplicate),
            release_evidence_conflict: load(&self.release_evidence_conflict),
            release_evidence_sent: load(&self.release_evidence_sent),
            release_evidence_replayed: load(&self.release_evidence_replayed),
            release_evidence_dropped: load(&self.release_evidence_dropped),
        }
    }
}
