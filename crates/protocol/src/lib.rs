//! Versioned agent/server wire protocol.

#[allow(clippy::all, clippy::pedantic)]
pub mod v1 {
    tonic::include_proto!("okoscope.v1");
}

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Utc};
use event_model::{
    ContainerCategory, ContainerImageIdentity, ContainerRestart, ContainerTermination,
    DnsAddressAnswer, DnsCname, DnsContext, DnsDirection, DnsName, DnsQueryType, DnsResponseCode,
    DnsTransport, EVENT_SCHEMA_VERSION, EventPayload, EvidenceSource, FileActivityPath, FileCreate,
    FileDelete, FileModify, FileRename, GenerationCorrelation, KubernetesAttribution,
    NetworkAccept, NetworkAddressFamily, NetworkConnect, NetworkConnectOutcome, NetworkDnsQuery,
    NetworkDnsResponse, NetworkListen, PROTOCOL_VERSION, ProcessExec, ProcessExit, ProcessIdentity,
    ProcessTermination, ReleaseIdentity, ResourceAggregate, ResourceValues,
    RevisionReadinessSnapshot, RuntimeEvent, SyscallEvent, UnresolvedGenerationReason,
    WorkloadRevisionEvidence,
};
use thiserror::Error;
use uuid::Uuid;

pub const NETWORK_CONNECT_CAPABILITY: &str = "network.connect/v1";
pub const NETWORK_LISTEN_CAPABILITY: &str = "network.listen/v1";
pub const NETWORK_ACCEPT_CAPABILITY: &str = "network.accept/v1";
pub const NETWORK_DNS_UDP_CAPABILITY: &str = "network.dns.udp/v1";
pub const NETWORK_DNS_TCP_CAPABILITY: &str = "network.dns.tcp/v1";
pub const FILE_ACTIVITY_CAPABILITY: &str = "file.activity.syscall-path/v1";
pub const PROCESS_EXIT_CAPABILITY: &str = "process.exit/v1";
pub const CONTAINER_LIFECYCLE_CAPABILITY: &str = "container.lifecycle/v1";
pub const KUBERNETES_RELEASE_DISCOVERY_CAPABILITY: &str = "kubernetes.release-discovery/v1";
pub const ONBOARDING_STATUS_CAPABILITY: &str = "onboarding.status/v1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("unsupported protocol version {0}")]
    UnsupportedProtocol(u32),
    #[error("unsupported event schema version {0}")]
    UnsupportedEventSchema(u32),
    #[error("missing field: {0}")]
    Missing(&'static str),
    #[error("invalid UUID in {field}: {value}")]
    InvalidUuid { field: &'static str, value: String },
    #[error("invalid observation timestamp")]
    InvalidTimestamp,
    #[error("invalid network field: {0}")]
    InvalidNetwork(&'static str),
    #[error("invalid DNS field: {0}")]
    InvalidDns(&'static str),
    #[error("invalid file activity field: {0}")]
    InvalidFile(&'static str),
    #[error("invalid termination or lifecycle field: {0}")]
    InvalidTermination(&'static str),
    #[error("invalid release identity")]
    InvalidReleaseIdentity,
    #[error("invalid resource aggregate: {0}")]
    InvalidResource(String),
}

fn encode_release_identity(identity: ReleaseIdentity) -> v1::ReleaseIdentity {
    v1::ReleaseIdentity {
        version: u32::from(identity.version),
        digest: identity.digest.to_vec(),
        containers: identity
            .containers
            .into_iter()
            .map(|value| v1::ContainerImageIdentity {
                category: match value.category {
                    ContainerCategory::Init => v1::ContainerCategory::Init.into(),
                    ContainerCategory::Application => v1::ContainerCategory::Application.into(),
                },
                name: value.name,
                digest: value.digest.to_vec(),
                image: value.image,
            })
            .collect(),
    }
}

fn decode_release_identity(value: v1::ReleaseIdentity) -> Result<ReleaseIdentity, ProtocolError> {
    let digest: [u8; 32] = value
        .digest
        .try_into()
        .map_err(|_| ProtocolError::InvalidReleaseIdentity)?;
    let containers = value
        .containers
        .into_iter()
        .map(|component| {
            let category = match v1::ContainerCategory::try_from(component.category).ok() {
                Some(v1::ContainerCategory::Init) => ContainerCategory::Init,
                Some(v1::ContainerCategory::Application) => ContainerCategory::Application,
                _ => return Err(ProtocolError::InvalidReleaseIdentity),
            };
            Ok(ContainerImageIdentity {
                category,
                name: component.name,
                image: component.image,
                digest: component
                    .digest
                    .try_into()
                    .map_err(|_| ProtocolError::InvalidReleaseIdentity)?,
            })
        })
        .collect::<Result<Vec<_>, ProtocolError>>()?;
    let identity = ReleaseIdentity {
        version: u16::try_from(value.version).map_err(|_| ProtocolError::InvalidReleaseIdentity)?,
        digest,
        containers,
    };
    identity
        .validate()
        .map_err(|_| ProtocolError::InvalidReleaseIdentity)?;
    Ok(identity)
}

impl TryFrom<v1::WorkloadRevisionEvidence> for WorkloadRevisionEvidence {
    type Error = ProtocolError;

    fn try_from(value: v1::WorkloadRevisionEvidence) -> Result<Self, Self::Error> {
        require_bounded("evidence_id", &value.evidence_id, 200)?;
        require_bounded("namespace", &value.namespace, 253)?;
        require_bounded("workload_uid", &value.workload_uid, 253)?;
        require_bounded("workload_kind", &value.workload_kind, 64)?;
        require_bounded("workload_name", &value.workload_name, 253)?;
        require_bounded("replica_set_uid", &value.replica_set_uid, 253)?;
        require_bounded("replica_set_name", &value.replica_set_name, 253)?;
        require_bounded("pod_uid", &value.pod_uid, 253)?;
        if value
            .pod_template_hash
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > 253)
        {
            return Err(ProtocolError::InvalidReleaseIdentity);
        }
        Ok(Self {
            evidence_id: value.evidence_id,
            observed_at: timestamp(value.observed_at_unix_nanos)?,
            namespace: value.namespace,
            workload_uid: value.workload_uid,
            workload_kind: value.workload_kind,
            workload_name: value.workload_name,
            replica_set_uid: value.replica_set_uid,
            replica_set_name: value.replica_set_name,
            pod_uid: value.pod_uid,
            pod_template_hash: value.pod_template_hash,
            release_identity: decode_release_identity(
                value
                    .release_identity
                    .ok_or(ProtocolError::Missing("release_identity"))?,
            )?,
            ready: value.ready,
        })
    }
}

impl From<WorkloadRevisionEvidence> for v1::WorkloadRevisionEvidence {
    fn from(value: WorkloadRevisionEvidence) -> Self {
        Self {
            evidence_id: value.evidence_id,
            observed_at_unix_nanos: value.observed_at.timestamp_nanos_opt().unwrap_or_default(),
            namespace: value.namespace,
            workload_uid: value.workload_uid,
            workload_kind: value.workload_kind,
            workload_name: value.workload_name,
            replica_set_uid: value.replica_set_uid,
            replica_set_name: value.replica_set_name,
            pod_uid: value.pod_uid,
            pod_template_hash: value.pod_template_hash,
            release_identity: Some(encode_release_identity(value.release_identity)),
            ready: value.ready,
        }
    }
}

impl TryFrom<v1::RevisionReadinessSnapshot> for RevisionReadinessSnapshot {
    type Error = ProtocolError;

    fn try_from(value: v1::RevisionReadinessSnapshot) -> Result<Self, Self::Error> {
        require_bounded("snapshot_id", &value.snapshot_id, 200)?;
        if value.ready_pod_count > value.pod_count
            || value.ready_pod_count > value.workload_ready_pod_count
        {
            return Err(ProtocolError::InvalidReleaseIdentity);
        }
        Ok(Self {
            snapshot_id: value.snapshot_id,
            observed_at: timestamp(value.observed_at_unix_nanos)?,
            initialized: value.initialized,
            continuous: value.continuous,
            revision_digest: value
                .revision_digest
                .try_into()
                .map_err(|_| ProtocolError::InvalidReleaseIdentity)?,
            pod_count: value.pod_count,
            ready_pod_count: value.ready_pod_count,
            workload_ready_pod_count: value.workload_ready_pod_count,
        })
    }
}

impl From<RevisionReadinessSnapshot> for v1::RevisionReadinessSnapshot {
    fn from(value: RevisionReadinessSnapshot) -> Self {
        Self {
            snapshot_id: value.snapshot_id,
            observed_at_unix_nanos: value.observed_at.timestamp_nanos_opt().unwrap_or_default(),
            initialized: value.initialized,
            continuous: value.continuous,
            revision_digest: value.revision_digest.to_vec(),
            pod_count: value.pod_count,
            ready_pod_count: value.ready_pod_count,
            workload_ready_pod_count: value.workload_ready_pod_count,
        }
    }
}

fn require_bounded(field: &'static str, value: &str, max: usize) -> Result<(), ProtocolError> {
    if value.is_empty() || value.len() > max || value.trim() != value {
        Err(ProtocolError::Missing(field))
    } else {
        Ok(())
    }
}

fn timestamp(value: i64) -> Result<DateTime<Utc>, ProtocolError> {
    let nanos = u32::try_from(value.rem_euclid(1_000_000_000))
        .map_err(|_| ProtocolError::InvalidTimestamp)?;
    DateTime::from_timestamp(value.div_euclid(1_000_000_000), nanos)
        .ok_or(ProtocolError::InvalidTimestamp)
}

/// Validates the wire protocol version.
///
/// # Errors
///
/// Returns [`ProtocolError::UnsupportedProtocol`] when the peer version is not supported.
pub fn validate_protocol(version: u32) -> Result<(), ProtocolError> {
    if version == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(ProtocolError::UnsupportedProtocol(version))
    }
}

pub const RESOURCE_UTILIZATION_CAPABILITY: &str = "resource.utilization/v1";

impl TryFrom<v1::ResourceAggregate> for ResourceAggregate {
    type Error = ProtocolError;

    fn try_from(value: v1::ResourceAggregate) -> Result<Self, Self::Error> {
        let values = value
            .values
            .ok_or(ProtocolError::Missing("resource.values"))?;
        let aggregate = Self {
            id: Uuid::parse_str(&value.aggregate_id).map_err(|_| ProtocolError::InvalidUuid {
                field: "aggregate_id",
                value: value.aggregate_id,
            })?,
            schema_version: u16::try_from(value.schema_version)
                .map_err(|error| ProtocolError::InvalidResource(error.to_string()))?,
            interval_start: timestamp(value.interval_start_unix_nanos)?,
            interval_end: timestamp(value.interval_end_unix_nanos)?,
            covered_usec: value.covered_usec,
            sample_count: value.sample_count,
            contributing_containers: value.contributing_containers,
            ready_containers: value.ready_containers,
            namespace: value.namespace,
            workload_uid: value.workload_uid,
            workload_kind: value.workload_kind,
            workload_name: value.workload_name,
            container_name: value.container_name,
            node_name: value.node_name,
            release_identity: value
                .release_identity
                .map(decode_release_identity)
                .transpose()?,
            unavailable_sources: value.unavailable_sources,
            values: decode_resource_values(&values),
        };
        aggregate
            .validate()
            .map_err(|error| ProtocolError::InvalidResource(error.to_string()))?;
        Ok(aggregate)
    }
}

impl From<ResourceAggregate> for v1::ResourceAggregate {
    fn from(value: ResourceAggregate) -> Self {
        Self {
            aggregate_id: value.id.to_string(),
            schema_version: u32::from(value.schema_version),
            interval_start_unix_nanos: value
                .interval_start
                .timestamp_nanos_opt()
                .unwrap_or_default(),
            interval_end_unix_nanos: value.interval_end.timestamp_nanos_opt().unwrap_or_default(),
            covered_usec: value.covered_usec,
            sample_count: value.sample_count,
            contributing_containers: value.contributing_containers,
            ready_containers: value.ready_containers,
            namespace: value.namespace,
            workload_uid: value.workload_uid,
            workload_kind: value.workload_kind,
            workload_name: value.workload_name,
            container_name: value.container_name,
            node_name: value.node_name,
            release_identity: value.release_identity.map(encode_release_identity),
            unavailable_sources: value.unavailable_sources,
            values: Some(encode_resource_values(&value.values)),
        }
    }
}

fn decode_resource_values(value: &v1::ResourceValues) -> ResourceValues {
    ResourceValues {
        cpu_usage_usec: value.cpu_usage_usec,
        cpu_nr_periods: value.cpu_nr_periods,
        cpu_nr_throttled: value.cpu_nr_throttled,
        cpu_throttled_usec: value.cpu_throttled_usec,
        cpu_quota_usec: value.cpu_quota_usec,
        cpu_period_usec: value.cpu_period_usec,
        memory_current_sum_bytes: value.memory_current_sum_bytes,
        memory_current_min_bytes: value.memory_current_min_bytes,
        memory_current_max_bytes: value.memory_current_max_bytes,
        memory_anon_sum_bytes: value.memory_anon_sum_bytes,
        memory_file_sum_bytes: value.memory_file_sum_bytes,
        memory_limit_bytes: value.memory_limit_bytes,
        memory_high_events: value.memory_high_events,
        memory_max_events: value.memory_max_events,
        memory_oom_events: value.memory_oom_events,
        memory_oom_kill_events: value.memory_oom_kill_events,
        cpu_psi_some_usec: value.cpu_psi_some_usec,
        cpu_psi_full_usec: value.cpu_psi_full_usec,
        memory_psi_some_usec: value.memory_psi_some_usec,
        memory_psi_full_usec: value.memory_psi_full_usec,
        io_psi_some_usec: value.io_psi_some_usec,
        io_psi_full_usec: value.io_psi_full_usec,
        io_read_bytes: value.io_read_bytes,
        io_write_bytes: value.io_write_bytes,
        io_read_operations: value.io_read_operations,
        io_write_operations: value.io_write_operations,
        pids_current_sum: value.pids_current_sum,
        pids_current_max: value.pids_current_max,
        pids_limit: value.pids_limit,
        pids_max_events: value.pids_max_events,
    }
}

fn encode_resource_values(value: &ResourceValues) -> v1::ResourceValues {
    v1::ResourceValues {
        cpu_usage_usec: value.cpu_usage_usec,
        cpu_nr_periods: value.cpu_nr_periods,
        cpu_nr_throttled: value.cpu_nr_throttled,
        cpu_throttled_usec: value.cpu_throttled_usec,
        cpu_quota_usec: value.cpu_quota_usec,
        cpu_period_usec: value.cpu_period_usec,
        memory_current_sum_bytes: value.memory_current_sum_bytes,
        memory_current_min_bytes: value.memory_current_min_bytes,
        memory_current_max_bytes: value.memory_current_max_bytes,
        memory_anon_sum_bytes: value.memory_anon_sum_bytes,
        memory_file_sum_bytes: value.memory_file_sum_bytes,
        memory_limit_bytes: value.memory_limit_bytes,
        memory_high_events: value.memory_high_events,
        memory_max_events: value.memory_max_events,
        memory_oom_events: value.memory_oom_events,
        memory_oom_kill_events: value.memory_oom_kill_events,
        cpu_psi_some_usec: value.cpu_psi_some_usec,
        cpu_psi_full_usec: value.cpu_psi_full_usec,
        memory_psi_some_usec: value.memory_psi_some_usec,
        memory_psi_full_usec: value.memory_psi_full_usec,
        io_psi_some_usec: value.io_psi_some_usec,
        io_psi_full_usec: value.io_psi_full_usec,
        io_read_bytes: value.io_read_bytes,
        io_write_bytes: value.io_write_bytes,
        io_read_operations: value.io_read_operations,
        io_write_operations: value.io_write_operations,
        pids_current_sum: value.pids_current_sum,
        pids_current_max: value.pids_current_max,
        pids_limit: value.pids_limit,
        pids_max_events: value.pids_max_events,
    }
}

impl From<RuntimeEvent> for v1::RuntimeEvent {
    fn from(event: RuntimeEvent) -> Self {
        let payload = encode_payload(event.payload);
        let a = event.attribution;
        let p = event.process;
        Self {
            event_id: event.id.to_string(),
            observed_at_unix_nanos: event.observed_at.timestamp_nanos_opt().unwrap_or_default(),
            schema_version: event.schema_version,
            attribution: Some(v1::KubernetesAttribution {
                node_name: a.node_name,
                namespace: a.namespace,
                pod_uid: a.pod_uid,
                pod_name: a.pod_name,
                container_id: a.container_id,
                container_name: a.container_name,
                workload_uid: a.workload_uid,
                workload_kind: a.workload_kind,
                workload_name: a.workload_name,
                release: a.release,
                release_identity: a.release_identity.map(encode_release_identity),
            }),
            process: Some(v1::ProcessIdentity {
                cgroup_id: p.cgroup_id,
                pid: p.pid,
                tgid: p.tgid,
                command: p.command,
            }),
            payload: Some(payload),
        }
    }
}

fn encode_payload(payload: EventPayload) -> v1::runtime_event::Payload {
    match payload {
        EventPayload::ProcessExec(exec) => {
            v1::runtime_event::Payload::ProcessExec(v1::ProcessExec {
                executable: exec.executable,
                parent_command: exec.parent_command.unwrap_or_default(),
            })
        }
        EventPayload::Syscall(syscall) => {
            v1::runtime_event::Payload::Syscall(v1::Syscall { name: syscall.name })
        }
        EventPayload::NetworkConnect(network) => {
            let (address_family, destination_address) = match network.destination_address {
                IpAddr::V4(address) => (v1::NetworkAddressFamily::Ipv4, address.octets().to_vec()),
                IpAddr::V6(address) => (v1::NetworkAddressFamily::Ipv6, address.octets().to_vec()),
            };
            let outcome = match network.outcome {
                NetworkConnectOutcome::Succeeded => v1::NetworkConnectOutcome::Succeeded,
                NetworkConnectOutcome::InProgress => v1::NetworkConnectOutcome::InProgress,
                NetworkConnectOutcome::Failed => v1::NetworkConnectOutcome::Failed,
            };
            v1::runtime_event::Payload::NetworkConnect(v1::NetworkConnect {
                address_family: address_family.into(),
                destination_address,
                destination_port: u32::from(network.destination_port),
                outcome: outcome.into(),
                errno: network.errno.map(u32::from),
                dns_context: network.dns_context.map(encode_dns_context),
            })
        }
        EventPayload::NetworkListen(network) => {
            let (address_family, local_address) = encode_network_ip(network.local_address);
            v1::runtime_event::Payload::NetworkListen(v1::NetworkListen {
                transport: v1::NetworkTransport::Tcp.into(),
                address_family: address_family.into(),
                local_address,
                local_port: u32::from(network.local_port),
            })
        }
        EventPayload::NetworkAccept(network) => {
            let (address_family, local_address) = encode_network_ip(network.local_address);
            v1::runtime_event::Payload::NetworkAccept(v1::NetworkAccept {
                transport: v1::NetworkTransport::Tcp.into(),
                address_family: address_family.into(),
                local_address,
                local_port: u32::from(network.local_port),
                remote_address: encode_ip(network.remote_address),
                remote_port: u32::from(network.remote_port),
            })
        }
        EventPayload::NetworkDnsQuery(query) => {
            v1::runtime_event::Payload::NetworkDnsQuery(encode_dns_query(query))
        }
        EventPayload::NetworkDnsResponse(response) => {
            v1::runtime_event::Payload::NetworkDnsResponse(encode_dns_response(response))
        }
        EventPayload::FileCreate(value) => v1::runtime_event::Payload::FileCreate(v1::FileCreate {
            path: value.path.into(),
        }),
        EventPayload::FileModify(value) => v1::runtime_event::Payload::FileModify(v1::FileModify {
            path: value.path.into(),
        }),
        EventPayload::FileDelete(value) => v1::runtime_event::Payload::FileDelete(v1::FileDelete {
            path: value.path.into(),
        }),
        EventPayload::FileRename(value) => v1::runtime_event::Payload::FileRename(v1::FileRename {
            old_path: value.old_path.into(),
            new_path: value.new_path.into(),
            replaced: value.replaced,
        }),
        EventPayload::ProcessExit(value) => {
            v1::runtime_event::Payload::ProcessExit(encode_process_exit(value))
        }
        EventPayload::ContainerTermination(value) => {
            v1::runtime_event::Payload::ContainerTermination(encode_container_termination(value))
        }
        EventPayload::ContainerRestart(value) => {
            v1::runtime_event::Payload::ContainerRestart(encode_container_restart(value))
        }
    }
}

fn encode_source(source: EvidenceSource) -> i32 {
    match source {
        EvidenceSource::Kernel => v1::EvidenceSource::Kernel.into(),
        EvidenceSource::Kubernetes => v1::EvidenceSource::Kubernetes.into(),
        EvidenceSource::Derived => v1::EvidenceSource::Derived.into(),
    }
}

fn decode_source(source: i32) -> Result<EvidenceSource, ProtocolError> {
    match v1::EvidenceSource::try_from(source).ok() {
        Some(v1::EvidenceSource::Kernel) => Ok(EvidenceSource::Kernel),
        Some(v1::EvidenceSource::Kubernetes) => Ok(EvidenceSource::Kubernetes),
        Some(v1::EvidenceSource::Derived) => Ok(EvidenceSource::Derived),
        _ => Err(ProtocolError::InvalidTermination("source")),
    }
}

fn encode_process_exit(value: ProcessExit) -> v1::ProcessExit {
    let termination = match value.termination {
        ProcessTermination::Exited { status } => {
            v1::process_exit::Termination::Exited(v1::ProcessExited {
                status: u32::from(status),
            })
        }
        ProcessTermination::Signaled {
            signal,
            signal_name,
            core_dump_flag,
        } => v1::process_exit::Termination::Signaled(v1::ProcessSignaled {
            signal: u32::from(signal),
            signal_name,
            core_dump_flag,
        }),
    };
    let result = match value.correlation {
        GenerationCorrelation::Observed {
            generation,
            exec_event_id,
            executable,
        } => v1::generation_correlation::Result::Observed(v1::ObservedGeneration {
            generation,
            exec_event_id: exec_event_id.to_string(),
            executable,
        }),
        GenerationCorrelation::Unresolved { reason } => {
            let reason = match reason {
                UnresolvedGenerationReason::BeforeObservation => {
                    v1::UnresolvedGenerationReason::BeforeObservation
                }
                UnresolvedGenerationReason::Evicted => v1::UnresolvedGenerationReason::Evicted,
                UnresolvedGenerationReason::GenerationMismatch => {
                    v1::UnresolvedGenerationReason::GenerationMismatch
                }
                UnresolvedGenerationReason::ContainerLifetimeMismatch => {
                    v1::UnresolvedGenerationReason::ContainerLifetimeMismatch
                }
            };
            v1::generation_correlation::Result::Unresolved(v1::UnresolvedGeneration {
                reason: reason.into(),
            })
        }
    };
    v1::ProcessExit {
        source: encode_source(value.source),
        raw_wait_status: value.raw_wait_status,
        termination: Some(termination),
        correlation: Some(v1::GenerationCorrelation {
            result: Some(result),
        }),
    }
}

fn encode_container_termination(value: ContainerTermination) -> v1::ContainerTermination {
    v1::ContainerTermination {
        source: encode_source(value.source),
        runtime_container_id: value.runtime_container_id,
        reason: value.reason,
        exit_code: value.exit_code,
        started_at_unix_nanos: value
            .started_at
            .and_then(|value| value.timestamp_nanos_opt()),
        finished_at_unix_nanos: value
            .finished_at
            .and_then(|value| value.timestamp_nanos_opt()),
    }
}

fn encode_container_restart(value: ContainerRestart) -> v1::ContainerRestart {
    v1::ContainerRestart {
        source: encode_source(value.source),
        runtime_container_id: value.runtime_container_id,
        restart_count: value.restart_count,
        restart_delta: value.restart_delta,
        observation_gap: value.observation_gap,
        previous_termination: value.previous_termination.map(encode_container_termination),
        waiting_reason: value.waiting_reason,
    }
}

fn decode_process_exit(value: v1::ProcessExit) -> Result<ProcessExit, ProtocolError> {
    if decode_source(value.source)? != EvidenceSource::Kernel {
        return Err(ProtocolError::InvalidTermination("process_exit.source"));
    }
    let termination = match value
        .termination
        .ok_or(ProtocolError::Missing("process_exit.termination"))?
    {
        v1::process_exit::Termination::Exited(exited) => {
            let status = u8::try_from(exited.status)
                .map_err(|_| ProtocolError::InvalidTermination("exit.status"))?;
            if value.raw_wait_status != i32::from(status) << 8 {
                return Err(ProtocolError::InvalidTermination("exit.raw_wait_status"));
            }
            ProcessTermination::exited(status)
        }
        v1::process_exit::Termination::Signaled(signaled) => {
            let signal = u8::try_from(signaled.signal)
                .map_err(|_| ProtocolError::InvalidTermination("signal"))?;
            let expected = i32::from(signal) | if signaled.core_dump_flag { 0x80 } else { 0 };
            if value.raw_wait_status != expected {
                return Err(ProtocolError::InvalidTermination("signal.raw_wait_status"));
            }
            ProcessTermination::signaled(signal, signaled.signal_name, signaled.core_dump_flag)
                .map_err(|_| ProtocolError::InvalidTermination("signal"))?
        }
    };
    let correlation = decode_generation_correlation(
        value
            .correlation
            .ok_or(ProtocolError::Missing("process_exit.correlation"))?,
    )?;
    Ok(ProcessExit::new(
        value.raw_wait_status,
        termination,
        correlation,
    ))
}

fn decode_generation_correlation(
    value: v1::GenerationCorrelation,
) -> Result<GenerationCorrelation, ProtocolError> {
    match value
        .result
        .ok_or(ProtocolError::Missing("generation_correlation.result"))?
    {
        v1::generation_correlation::Result::Observed(observed) => GenerationCorrelation::observed(
            observed.generation,
            parse_uuid("exec_event_id", &observed.exec_event_id)?,
            observed.executable,
        )
        .map_err(|_| ProtocolError::InvalidTermination("generation_correlation.observed")),
        v1::generation_correlation::Result::Unresolved(unresolved) => {
            let reason = match v1::UnresolvedGenerationReason::try_from(unresolved.reason).ok() {
                Some(v1::UnresolvedGenerationReason::BeforeObservation) => {
                    UnresolvedGenerationReason::BeforeObservation
                }
                Some(v1::UnresolvedGenerationReason::Evicted) => {
                    UnresolvedGenerationReason::Evicted
                }
                Some(v1::UnresolvedGenerationReason::GenerationMismatch) => {
                    UnresolvedGenerationReason::GenerationMismatch
                }
                Some(v1::UnresolvedGenerationReason::ContainerLifetimeMismatch) => {
                    UnresolvedGenerationReason::ContainerLifetimeMismatch
                }
                _ => {
                    return Err(ProtocolError::InvalidTermination(
                        "generation_correlation.reason",
                    ));
                }
            };
            Ok(GenerationCorrelation::Unresolved { reason })
        }
    }
}

fn decode_optional_timestamp(value: Option<i64>) -> Result<Option<DateTime<Utc>>, ProtocolError> {
    value
        .map(|value| {
            let secs = value.div_euclid(1_000_000_000);
            let nanos = u32::try_from(value.rem_euclid(1_000_000_000))
                .map_err(|_| ProtocolError::InvalidTimestamp)?;
            DateTime::<Utc>::from_timestamp(secs, nanos).ok_or(ProtocolError::InvalidTimestamp)
        })
        .transpose()
}

fn decode_container_termination(
    value: v1::ContainerTermination,
) -> Result<ContainerTermination, ProtocolError> {
    if decode_source(value.source)? != EvidenceSource::Kubernetes {
        return Err(ProtocolError::InvalidTermination(
            "container_termination.source",
        ));
    }
    ContainerTermination::new(
        value.runtime_container_id,
        value.reason,
        value.exit_code,
        decode_optional_timestamp(value.started_at_unix_nanos)?,
        decode_optional_timestamp(value.finished_at_unix_nanos)?,
    )
    .map_err(|_| ProtocolError::InvalidTermination("container_termination"))
}

fn decode_container_restart(
    value: v1::ContainerRestart,
) -> Result<ContainerRestart, ProtocolError> {
    if decode_source(value.source)? != EvidenceSource::Kubernetes {
        return Err(ProtocolError::InvalidTermination(
            "container_restart.source",
        ));
    }
    let restart = ContainerRestart::new(
        value.runtime_container_id,
        value.restart_count,
        value.restart_delta,
        value
            .previous_termination
            .map(decode_container_termination)
            .transpose()?,
        value.waiting_reason,
    )
    .map_err(|_| ProtocolError::InvalidTermination("container_restart"))?;
    if restart.observation_gap != value.observation_gap {
        return Err(ProtocolError::InvalidTermination(
            "container_restart.observation_gap",
        ));
    }
    Ok(restart)
}

impl TryFrom<v1::RuntimeEvent> for RuntimeEvent {
    type Error = ProtocolError;

    fn try_from(event: v1::RuntimeEvent) -> Result<Self, Self::Error> {
        if event.schema_version != EVENT_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedEventSchema(event.schema_version));
        }
        let id = parse_uuid("event_id", &event.event_id)?;
        let secs = event.observed_at_unix_nanos.div_euclid(1_000_000_000);
        let nanos = u32::try_from(event.observed_at_unix_nanos.rem_euclid(1_000_000_000))
            .map_err(|_| ProtocolError::InvalidTimestamp)?;
        let observed_at =
            DateTime::<Utc>::from_timestamp(secs, nanos).ok_or(ProtocolError::InvalidTimestamp)?;
        let a = event
            .attribution
            .ok_or(ProtocolError::Missing("attribution"))?;
        require("node_name", &a.node_name)?;
        require("namespace", &a.namespace)?;
        require("pod_uid", &a.pod_uid)?;
        require("container_id", &a.container_id)?;
        require("workload_uid", &a.workload_uid)?;
        let attribution = KubernetesAttribution {
            project_id: Uuid::nil(),
            application_id: Uuid::nil(),
            node_name: a.node_name,
            namespace: a.namespace,
            pod_uid: a.pod_uid,
            pod_name: a.pod_name,
            container_id: a.container_id,
            container_name: a.container_name,
            workload_uid: a.workload_uid,
            workload_kind: a.workload_kind,
            workload_name: a.workload_name,
            release: a.release.and_then(|value| {
                let value = value.trim().to_owned();
                (!value.is_empty() && value.len() <= 200).then_some(value)
            }),
            release_identity: a
                .release_identity
                .map(decode_release_identity)
                .transpose()?,
        };
        let p = event.process.ok_or(ProtocolError::Missing("process"))?;
        let process = ProcessIdentity {
            cgroup_id: p.cgroup_id,
            pid: p.pid,
            tgid: p.tgid,
            command: p.command,
        };
        let payload = match event.payload.ok_or(ProtocolError::Missing("payload"))? {
            v1::runtime_event::Payload::ProcessExec(exec) => {
                require("executable", &exec.executable)?;
                EventPayload::ProcessExec(ProcessExec {
                    executable: exec.executable,
                    parent_command: (!exec.parent_command.is_empty())
                        .then_some(exec.parent_command),
                })
            }
            v1::runtime_event::Payload::Syscall(syscall) => {
                require("syscall.name", &syscall.name)?;
                EventPayload::Syscall(SyscallEvent { name: syscall.name })
            }
            v1::runtime_event::Payload::NetworkConnect(network) => decode_network(&network)?,
            v1::runtime_event::Payload::NetworkListen(network) => decode_listen(&network)?,
            v1::runtime_event::Payload::NetworkAccept(network) => decode_accept(&network)?,
            v1::runtime_event::Payload::NetworkDnsQuery(query) => decode_dns_query(&query)?,
            v1::runtime_event::Payload::NetworkDnsResponse(response) => {
                decode_dns_response(&response)?
            }
            v1::runtime_event::Payload::FileCreate(value) => EventPayload::FileCreate(FileCreate {
                path: decode_file_path(value.path, "path")?,
            }),
            v1::runtime_event::Payload::FileModify(value) => EventPayload::FileModify(FileModify {
                path: decode_file_path(value.path, "path")?,
            }),
            v1::runtime_event::Payload::FileDelete(value) => EventPayload::FileDelete(FileDelete {
                path: decode_file_path(value.path, "path")?,
            }),
            v1::runtime_event::Payload::FileRename(value) => EventPayload::FileRename(
                FileRename::new(
                    decode_file_path(value.old_path, "old_path")?,
                    decode_file_path(value.new_path, "new_path")?,
                    value.replaced,
                )
                .map_err(|_| ProtocolError::InvalidFile("rename"))?,
            ),
            v1::runtime_event::Payload::ProcessExit(value) => {
                EventPayload::ProcessExit(decode_process_exit(value)?)
            }
            v1::runtime_event::Payload::ContainerTermination(value) => {
                EventPayload::ContainerTermination(decode_container_termination(value)?)
            }
            v1::runtime_event::Payload::ContainerRestart(value) => {
                EventPayload::ContainerRestart(decode_container_restart(value)?)
            }
        };
        Ok(Self {
            id,
            observed_at,
            schema_version: event.schema_version,
            attribution,
            process,
            payload,
        })
    }
}

fn decode_file_path(value: String, field: &'static str) -> Result<FileActivityPath, ProtocolError> {
    FileActivityPath::new(value).map_err(|_| ProtocolError::InvalidFile(field))
}

fn encode_network_ip(address: IpAddr) -> (v1::NetworkAddressFamily, Vec<u8>) {
    match address {
        IpAddr::V4(value) => (v1::NetworkAddressFamily::Ipv4, value.octets().to_vec()),
        IpAddr::V6(value) => (v1::NetworkAddressFamily::Ipv6, value.octets().to_vec()),
    }
}

fn decode_network_ip(
    family: i32,
    address: &[u8],
    field: &'static str,
) -> Result<(NetworkAddressFamily, IpAddr), ProtocolError> {
    match v1::NetworkAddressFamily::try_from(family)
        .map_err(|_| ProtocolError::InvalidNetwork("address_family"))?
    {
        v1::NetworkAddressFamily::Ipv4 => Ok((
            NetworkAddressFamily::Ipv4,
            IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(address).map_err(|_| ProtocolError::InvalidNetwork(field))?,
            )),
        )),
        v1::NetworkAddressFamily::Ipv6 => Ok((
            NetworkAddressFamily::Ipv6,
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(address).map_err(|_| ProtocolError::InvalidNetwork(field))?,
            )),
        )),
        v1::NetworkAddressFamily::Unspecified => {
            Err(ProtocolError::InvalidNetwork("address_family"))
        }
    }
}

fn require_tcp(transport: i32) -> Result<(), ProtocolError> {
    match v1::NetworkTransport::try_from(transport)
        .map_err(|_| ProtocolError::InvalidNetwork("transport"))?
    {
        v1::NetworkTransport::Tcp => Ok(()),
        v1::NetworkTransport::Unspecified => Err(ProtocolError::InvalidNetwork("transport")),
    }
}

fn decode_listen(network: &v1::NetworkListen) -> Result<EventPayload, ProtocolError> {
    require_tcp(network.transport)?;
    let (family, address) = decode_network_ip(
        network.address_family,
        &network.local_address,
        "local_address",
    )?;
    let port = u16::try_from(network.local_port)
        .map_err(|_| ProtocolError::InvalidNetwork("local_port"))?;
    NetworkListen::new(family, address, port)
        .map(EventPayload::NetworkListen)
        .map_err(|_| ProtocolError::InvalidNetwork("network_listen"))
}

fn decode_accept(network: &v1::NetworkAccept) -> Result<EventPayload, ProtocolError> {
    require_tcp(network.transport)?;
    let (family, local_address) = decode_network_ip(
        network.address_family,
        &network.local_address,
        "local_address",
    )?;
    let (_, remote_address) = decode_network_ip(
        network.address_family,
        &network.remote_address,
        "remote_address",
    )?;
    let local_port = u16::try_from(network.local_port)
        .map_err(|_| ProtocolError::InvalidNetwork("local_port"))?;
    let remote_port = u16::try_from(network.remote_port)
        .map_err(|_| ProtocolError::InvalidNetwork("remote_port"))?;
    NetworkAccept::new(
        family,
        local_address,
        local_port,
        remote_address,
        remote_port,
    )
    .map(EventPayload::NetworkAccept)
    .map_err(|_| ProtocolError::InvalidNetwork("network_accept"))
}

fn decode_network(network: &v1::NetworkConnect) -> Result<EventPayload, ProtocolError> {
    let (address_family, destination_address) =
        match v1::NetworkAddressFamily::try_from(network.address_family)
            .map_err(|_| ProtocolError::InvalidNetwork("address_family"))?
        {
            v1::NetworkAddressFamily::Ipv4 => (
                NetworkAddressFamily::Ipv4,
                IpAddr::V4(Ipv4Addr::from(
                    <[u8; 4]>::try_from(network.destination_address.as_slice())
                        .map_err(|_| ProtocolError::InvalidNetwork("destination_address"))?,
                )),
            ),
            v1::NetworkAddressFamily::Ipv6 => (
                NetworkAddressFamily::Ipv6,
                IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(network.destination_address.as_slice())
                        .map_err(|_| ProtocolError::InvalidNetwork("destination_address"))?,
                )),
            ),
            v1::NetworkAddressFamily::Unspecified => {
                return Err(ProtocolError::InvalidNetwork("address_family"));
            }
        };
    let destination_port = u16::try_from(network.destination_port)
        .map_err(|_| ProtocolError::InvalidNetwork("destination_port"))?;
    let outcome = match v1::NetworkConnectOutcome::try_from(network.outcome)
        .map_err(|_| ProtocolError::InvalidNetwork("outcome"))?
    {
        v1::NetworkConnectOutcome::Succeeded => NetworkConnectOutcome::Succeeded,
        v1::NetworkConnectOutcome::InProgress => NetworkConnectOutcome::InProgress,
        v1::NetworkConnectOutcome::Failed => NetworkConnectOutcome::Failed,
        v1::NetworkConnectOutcome::Unspecified => {
            return Err(ProtocolError::InvalidNetwork("outcome"));
        }
    };
    let errno = network
        .errno
        .map(u16::try_from)
        .transpose()
        .map_err(|_| ProtocolError::InvalidNetwork("errno"))?;
    let mut value = NetworkConnect::new(
        address_family,
        destination_address,
        destination_port,
        outcome,
        errno,
    )
    .map_err(|_| ProtocolError::InvalidNetwork("network_connect"))?;
    if let Some(context) = &network.dns_context {
        value = value.with_dns_context(decode_dns_context(context)?);
    }
    Ok(EventPayload::NetworkConnect(value))
}

fn encode_ip(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(value) => value.octets().to_vec(),
        IpAddr::V6(value) => value.octets().to_vec(),
    }
}

fn decode_ip(value: &[u8]) -> Result<IpAddr, ProtocolError> {
    match value.len() {
        4 => Ok(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(value).unwrap(),
        ))),
        16 => Ok(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(value).unwrap(),
        ))),
        _ => Err(ProtocolError::InvalidDns("address")),
    }
}

fn encode_dns_query(value: NetworkDnsQuery) -> v1::NetworkDnsQuery {
    v1::NetworkDnsQuery {
        transaction_id: u32::from(value.transaction_id),
        direction: encode_direction(value.direction).into(),
        transport: encode_transport(value.transport).into(),
        resolver_address: encode_ip(value.resolver_address),
        name: value.name.into(),
        query_type: encode_query_type(value.query_type).into(),
    }
}

fn encode_dns_response(value: NetworkDnsResponse) -> v1::NetworkDnsResponse {
    v1::NetworkDnsResponse {
        transaction_id: u32::from(value.transaction_id),
        direction: encode_direction(value.direction).into(),
        transport: encode_transport(value.transport).into(),
        resolver_address: encode_ip(value.resolver_address),
        name: value.name.into(),
        query_type: encode_query_type(value.query_type).into(),
        response_code: encode_response_code(value.response_code).into(),
        truncated: value.truncated,
        answers: value
            .answers
            .into_iter()
            .map(|answer| v1::DnsAddressAnswer {
                name: answer.name.into(),
                address: encode_ip(answer.address),
                ttl_seconds: answer.ttl_seconds,
            })
            .collect(),
        cname_chain: value
            .cname_chain
            .into_iter()
            .map(|cname| v1::DnsCname {
                alias: cname.alias.into(),
                canonical: cname.canonical.into(),
                ttl_seconds: cname.ttl_seconds,
            })
            .collect(),
        effective_ttl_seconds: value.effective_ttl_seconds,
    }
}

fn encode_dns_context(value: DnsContext) -> v1::DnsContext {
    v1::DnsContext {
        names: value.names.into_iter().map(Into::into).collect(),
        observed_at_unix_nanos: value.observed_at.timestamp_nanos_opt().unwrap_or_default(),
        expires_at_unix_nanos: value.expires_at.timestamp_nanos_opt().unwrap_or_default(),
        confidence: v1::DnsConfidence::ObservedRecently.into(),
        ambiguous: value.ambiguous,
    }
}

fn decode_dns_query(value: &v1::NetworkDnsQuery) -> Result<EventPayload, ProtocolError> {
    Ok(EventPayload::NetworkDnsQuery(NetworkDnsQuery {
        transaction_id: u16::try_from(value.transaction_id)
            .map_err(|_| ProtocolError::InvalidDns("transaction_id"))?,
        direction: decode_direction(value.direction)?,
        transport: decode_transport(value.transport)?,
        resolver_address: decode_ip(&value.resolver_address)?,
        name: DnsName::new(value.name.clone()).map_err(|_| ProtocolError::InvalidDns("name"))?,
        query_type: decode_query_type(value.query_type)?,
    }))
}

fn decode_dns_response(value: &v1::NetworkDnsResponse) -> Result<EventPayload, ProtocolError> {
    let response = NetworkDnsResponse {
        transaction_id: u16::try_from(value.transaction_id)
            .map_err(|_| ProtocolError::InvalidDns("transaction_id"))?,
        direction: decode_direction(value.direction)?,
        transport: decode_transport(value.transport)?,
        resolver_address: decode_ip(&value.resolver_address)?,
        name: DnsName::new(value.name.clone()).map_err(|_| ProtocolError::InvalidDns("name"))?,
        query_type: decode_query_type(value.query_type)?,
        response_code: decode_response_code(value.response_code)?,
        truncated: value.truncated,
        answers: value
            .answers
            .iter()
            .map(|answer| {
                DnsAddressAnswer::new(
                    DnsName::new(answer.name.clone())
                        .map_err(|_| ProtocolError::InvalidDns("answer.name"))?,
                    decode_ip(&answer.address)?,
                    answer.ttl_seconds,
                )
                .map_err(|_| ProtocolError::InvalidDns("answer.ttl"))
            })
            .collect::<Result<_, ProtocolError>>()?,
        cname_chain: value
            .cname_chain
            .iter()
            .map(|cname| {
                DnsCname::new(
                    DnsName::new(cname.alias.clone())
                        .map_err(|_| ProtocolError::InvalidDns("cname.alias"))?,
                    DnsName::new(cname.canonical.clone())
                        .map_err(|_| ProtocolError::InvalidDns("cname.canonical"))?,
                    cname.ttl_seconds,
                )
                .map_err(|_| ProtocolError::InvalidDns("cname.ttl"))
            })
            .collect::<Result<_, ProtocolError>>()?,
        effective_ttl_seconds: value.effective_ttl_seconds,
    };
    response
        .validate()
        .map_err(|_| ProtocolError::InvalidDns("response"))?;
    Ok(EventPayload::NetworkDnsResponse(response))
}

fn decode_dns_context(value: &v1::DnsContext) -> Result<DnsContext, ProtocolError> {
    let timestamp = |nanos: i64| {
        let subsecond = u32::try_from(nanos.rem_euclid(1_000_000_000))
            .map_err(|_| ProtocolError::InvalidDns("context.timestamp"))?;
        DateTime::<Utc>::from_timestamp(nanos.div_euclid(1_000_000_000), subsecond)
            .ok_or(ProtocolError::InvalidDns("context.timestamp"))
    };
    if value.confidence != i32::from(v1::DnsConfidence::ObservedRecently) {
        return Err(ProtocolError::InvalidDns("context.confidence"));
    }
    let names = value
        .names
        .iter()
        .map(|name| {
            DnsName::new(name.clone()).map_err(|_| ProtocolError::InvalidDns("context.name"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let context = DnsContext::new(
        names,
        timestamp(value.observed_at_unix_nanos)?,
        timestamp(value.expires_at_unix_nanos)?,
    )
    .map_err(|_| ProtocolError::InvalidDns("context"))?;
    if context.ambiguous != value.ambiguous {
        return Err(ProtocolError::InvalidDns("context.ambiguous"));
    }
    Ok(context)
}

fn encode_direction(value: DnsDirection) -> v1::DnsDirection {
    match value {
        DnsDirection::Egress => v1::DnsDirection::Egress,
        DnsDirection::Ingress => v1::DnsDirection::Ingress,
    }
}
fn encode_transport(value: DnsTransport) -> v1::DnsTransport {
    match value {
        DnsTransport::Udp => v1::DnsTransport::Udp,
        DnsTransport::Tcp => v1::DnsTransport::Tcp,
    }
}
fn encode_query_type(value: DnsQueryType) -> v1::DnsQueryType {
    match value {
        DnsQueryType::A => v1::DnsQueryType::A,
        DnsQueryType::Aaaa => v1::DnsQueryType::Aaaa,
    }
}
fn encode_response_code(value: DnsResponseCode) -> v1::DnsResponseCode {
    match value {
        DnsResponseCode::NoError => v1::DnsResponseCode::NoError,
        DnsResponseCode::FormErr => v1::DnsResponseCode::FormErr,
        DnsResponseCode::ServFail => v1::DnsResponseCode::ServFail,
        DnsResponseCode::NxDomain => v1::DnsResponseCode::NxDomain,
        DnsResponseCode::NotImp => v1::DnsResponseCode::NotImp,
        DnsResponseCode::Refused => v1::DnsResponseCode::Refused,
    }
}
fn decode_direction(value: i32) -> Result<DnsDirection, ProtocolError> {
    match v1::DnsDirection::try_from(value).ok() {
        Some(v1::DnsDirection::Egress) => Ok(DnsDirection::Egress),
        Some(v1::DnsDirection::Ingress) => Ok(DnsDirection::Ingress),
        _ => Err(ProtocolError::InvalidDns("direction")),
    }
}
fn decode_transport(value: i32) -> Result<DnsTransport, ProtocolError> {
    match v1::DnsTransport::try_from(value).ok() {
        Some(v1::DnsTransport::Udp) => Ok(DnsTransport::Udp),
        Some(v1::DnsTransport::Tcp) => Ok(DnsTransport::Tcp),
        _ => Err(ProtocolError::InvalidDns("transport")),
    }
}
fn decode_query_type(value: i32) -> Result<DnsQueryType, ProtocolError> {
    match v1::DnsQueryType::try_from(value).ok() {
        Some(v1::DnsQueryType::A) => Ok(DnsQueryType::A),
        Some(v1::DnsQueryType::Aaaa) => Ok(DnsQueryType::Aaaa),
        _ => Err(ProtocolError::InvalidDns("query_type")),
    }
}
fn decode_response_code(value: i32) -> Result<DnsResponseCode, ProtocolError> {
    match v1::DnsResponseCode::try_from(value).ok() {
        Some(v1::DnsResponseCode::NoError) => Ok(DnsResponseCode::NoError),
        Some(v1::DnsResponseCode::FormErr) => Ok(DnsResponseCode::FormErr),
        Some(v1::DnsResponseCode::ServFail) => Ok(DnsResponseCode::ServFail),
        Some(v1::DnsResponseCode::NxDomain) => Ok(DnsResponseCode::NxDomain),
        Some(v1::DnsResponseCode::NotImp) => Ok(DnsResponseCode::NotImp),
        Some(v1::DnsResponseCode::Refused) => Ok(DnsResponseCode::Refused),
        _ => Err(ProtocolError::InvalidDns("response_code")),
    }
}

fn require(field: &'static str, value: &str) -> Result<(), ProtocolError> {
    if value.trim().is_empty() {
        Err(ProtocolError::Missing(field))
    } else {
        Ok(())
    }
}

fn parse_uuid(field: &'static str, value: &str) -> Result<Uuid, ProtocolError> {
    Uuid::parse_str(value).map_err(|_| ProtocolError::InvalidUuid {
        field,
        value: value.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    fn event() -> RuntimeEvent {
        RuntimeEvent {
            id: Uuid::new_v4(),
            observed_at: Utc::now(),
            schema_version: EVENT_SCHEMA_VERSION,
            attribution: KubernetesAttribution {
                project_id: Uuid::nil(),
                application_id: Uuid::nil(),
                node_name: "node-1".into(),
                namespace: "production".into(),
                pod_uid: "pod-uid".into(),
                pod_name: "payment-api-1".into(),
                container_id: "containerd://abc".into(),
                container_name: "payment-api".into(),
                workload_uid: "deployment-uid".into(),
                workload_kind: "Deployment".into(),
                workload_name: "payment-api".into(),
                release: None,
                release_identity: None,
            },
            process: ProcessIdentity {
                cgroup_id: 42,
                pid: 100,
                tgid: 100,
                command: "sh".into(),
            },
            payload: EventPayload::ProcessExec(ProcessExec {
                executable: "/bin/sh".into(),
                parent_command: Some("payment-api".into()),
            }),
        }
    }

    #[test]
    fn resource_aggregate_round_trips_and_rejects_missing_values() {
        let start = Utc::now();
        let aggregate = ResourceAggregate {
            id: Uuid::new_v4(),
            schema_version: event_model::RESOURCE_SCHEMA_VERSION,
            interval_start: start,
            interval_end: start + chrono::Duration::minutes(1),
            covered_usec: 60_000_000,
            sample_count: 4,
            contributing_containers: 1,
            ready_containers: 1,
            namespace: "production".into(),
            workload_uid: "deployment-uid".into(),
            workload_kind: "Deployment".into(),
            workload_name: "payment-api".into(),
            container_name: "payment-api".into(),
            node_name: "node-1".into(),
            release_identity: None,
            unavailable_sources: 0,
            values: ResourceValues {
                cpu_usage_usec: Some(1_000_000),
                memory_current_sum_bytes: Some(256 * 1024 * 1024),
                ..ResourceValues::default()
            },
        };
        let wire = v1::ResourceAggregate::from(aggregate.clone());
        assert_eq!(ResourceAggregate::try_from(wire).unwrap(), aggregate);

        let mut invalid = v1::ResourceAggregate::from(aggregate);
        invalid.values = None;
        assert!(matches!(
            ResourceAggregate::try_from(invalid),
            Err(ProtocolError::Missing("resource.values"))
        ));
    }

    #[test]
    fn event_round_trip() {
        let original = event();
        let decoded = RuntimeEvent::try_from(v1::RuntimeEvent::from(original.clone())).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn optional_release_round_trips_and_old_messages_remain_valid() {
        let mut original = event();
        original.attribution.release = Some("1.7.2".into());
        assert_eq!(
            RuntimeEvent::try_from(v1::RuntimeEvent::from(original.clone())).unwrap(),
            original
        );
        let mut wire = v1::RuntimeEvent::from(event());
        wire.attribution.as_mut().unwrap().release = None;
        assert!(
            RuntimeEvent::try_from(wire)
                .unwrap()
                .attribution
                .release
                .is_none()
        );
    }

    #[test]
    fn optional_release_identity_round_trips_and_rejects_invalid_digest() {
        let mut original = event();
        original.attribution.release_identity = Some(
            ReleaseIdentity::from_image_ids([(
                ContainerCategory::Application,
                "payment-api",
                format!("registry/app@sha256:{}", "ab".repeat(32)),
            )])
            .unwrap(),
        );
        assert_eq!(
            RuntimeEvent::try_from(v1::RuntimeEvent::from(original.clone())).unwrap(),
            original
        );

        let mut wire = v1::RuntimeEvent::from(original);
        wire.attribution
            .as_mut()
            .unwrap()
            .release_identity
            .as_mut()
            .unwrap()
            .digest
            .pop();
        assert_eq!(
            RuntimeEvent::try_from(wire).unwrap_err(),
            ProtocolError::InvalidReleaseIdentity
        );
    }

    #[test]
    fn revision_evidence_and_snapshot_round_trip_with_bounds() {
        let release_identity = ReleaseIdentity::from_images([(
            ContainerCategory::Application,
            "payment-api",
            "registry/payment-api:latest",
            format!("registry/payment-api@sha256:{}", "ab".repeat(32)),
        )])
        .unwrap();
        let evidence = WorkloadRevisionEvidence {
            evidence_id: "pod-1:revision".into(),
            observed_at: Utc::now(),
            namespace: "production".into(),
            workload_uid: "deployment-uid".into(),
            workload_kind: "Deployment".into(),
            workload_name: "payment-api".into(),
            replica_set_uid: "rs-uid".into(),
            replica_set_name: "payment-api-abc".into(),
            pod_uid: "pod-uid".into(),
            pod_template_hash: Some("abc".into()),
            release_identity,
            ready: true,
        };
        assert_eq!(
            WorkloadRevisionEvidence::try_from(v1::WorkloadRevisionEvidence::from(
                evidence.clone()
            ))
            .unwrap(),
            evidence
        );
        let snapshot = RevisionReadinessSnapshot {
            snapshot_id: "snapshot".into(),
            observed_at: Utc::now(),
            initialized: true,
            continuous: true,
            revision_digest: event_model::revision_digest(&evidence),
            pod_count: 2,
            ready_pod_count: 1,
            workload_ready_pod_count: 2,
        };
        assert_eq!(
            RevisionReadinessSnapshot::try_from(v1::RevisionReadinessSnapshot::from(
                snapshot.clone()
            ))
            .unwrap(),
            snapshot
        );
        let mut invalid = v1::RevisionReadinessSnapshot::from(snapshot);
        invalid.ready_pod_count = 3;
        assert_eq!(
            RevisionReadinessSnapshot::try_from(invalid).unwrap_err(),
            ProtocolError::InvalidReleaseIdentity
        );
    }

    #[test]
    fn rejects_unknown_schema_and_missing_payload() {
        let mut wire = v1::RuntimeEvent::from(event());
        wire.schema_version = 999;
        assert_eq!(
            RuntimeEvent::try_from(wire).unwrap_err(),
            ProtocolError::UnsupportedEventSchema(999)
        );
        let mut wire = v1::RuntimeEvent::from(event());
        wire.payload = None;
        assert_eq!(
            RuntimeEvent::try_from(wire).unwrap_err(),
            ProtocolError::Missing("payload")
        );
    }

    #[test]
    fn rejects_unknown_protocol() {
        assert_eq!(
            validate_protocol(999),
            Err(ProtocolError::UnsupportedProtocol(999))
        );
    }

    fn network_event() -> RuntimeEvent {
        let mut event = event();
        event.payload = EventPayload::NetworkConnect(
            NetworkConnect::new(
                NetworkAddressFamily::Ipv6,
                "2001:db8::7".parse().unwrap(),
                443,
                NetworkConnectOutcome::Failed,
                Some(111),
            )
            .unwrap(),
        );
        event
    }

    #[test]
    fn network_event_round_trips_and_unknown_fields_are_ignored() {
        let original = network_event();
        let wire = v1::RuntimeEvent::from(original.clone());
        let mut encoded = wire.encode_to_vec();
        encoded.extend_from_slice(&[0xa0, 0x06, 0x01]);
        let decoded_wire = v1::RuntimeEvent::decode(encoded.as_slice()).unwrap();
        assert_eq!(RuntimeEvent::try_from(decoded_wire).unwrap(), original);
        let legacy = event();
        assert_eq!(
            RuntimeEvent::try_from(v1::RuntimeEvent::from(legacy.clone())).unwrap(),
            legacy
        );
    }

    #[test]
    fn rejects_invalid_network_fields() {
        let cases = [
            (0, vec![203, 0, 113, 1], 443, 1, None),
            (1, vec![203, 0, 113], 443, 1, None),
            (1, vec![203, 0, 113, 1], 0, 1, None),
            (1, vec![203, 0, 113, 1], 443, 0, None),
            (1, vec![203, 0, 113, 1], 443, 1, Some(1)),
            (1, vec![203, 0, 113, 1], 443, 2, Some(111)),
            (1, vec![203, 0, 113, 1], 443, 3, None),
            (1, vec![203, 0, 113, 1], 443, 3, Some(4096)),
        ];
        for (family, address, port, outcome, errno) in cases {
            let mut wire = v1::RuntimeEvent::from(event());
            wire.payload = Some(v1::runtime_event::Payload::NetworkConnect(
                v1::NetworkConnect {
                    address_family: family,
                    destination_address: address,
                    destination_port: port,
                    outcome,
                    errno,
                    dns_context: None,
                },
            ));
            assert!(matches!(
                RuntimeEvent::try_from(wire),
                Err(ProtocolError::InvalidNetwork(_))
            ));
        }
    }

    #[test]
    fn inbound_events_round_trip() {
        let mut listen = event();
        listen.payload = EventPayload::NetworkListen(
            NetworkListen::new(NetworkAddressFamily::Ipv4, "0.0.0.0".parse().unwrap(), 8080)
                .unwrap(),
        );
        assert_eq!(
            RuntimeEvent::try_from(v1::RuntimeEvent::from(listen.clone())).unwrap(),
            listen
        );

        let mut accepted = event();
        accepted.payload = EventPayload::NetworkAccept(
            NetworkAccept::new(
                NetworkAddressFamily::Ipv6,
                "::".parse().unwrap(),
                8443,
                "2001:db8::2".parse().unwrap(),
                52_000,
            )
            .unwrap(),
        );
        assert_eq!(
            RuntimeEvent::try_from(v1::RuntimeEvent::from(accepted.clone())).unwrap(),
            accepted
        );
    }

    #[test]
    fn rejects_malformed_inbound_events() {
        let invalid_listeners = [
            v1::NetworkListen {
                transport: v1::NetworkTransport::Unspecified.into(),
                address_family: v1::NetworkAddressFamily::Ipv4.into(),
                local_address: vec![0; 4],
                local_port: 8080,
            },
            v1::NetworkListen {
                transport: v1::NetworkTransport::Tcp.into(),
                address_family: v1::NetworkAddressFamily::Ipv6.into(),
                local_address: vec![0; 4],
                local_port: 8080,
            },
            v1::NetworkListen {
                transport: v1::NetworkTransport::Tcp.into(),
                address_family: v1::NetworkAddressFamily::Ipv4.into(),
                local_address: vec![0; 4],
                local_port: 0,
            },
        ];
        for value in invalid_listeners {
            let mut wire = v1::RuntimeEvent::from(event());
            wire.payload = Some(v1::runtime_event::Payload::NetworkListen(value));
            assert!(matches!(
                RuntimeEvent::try_from(wire),
                Err(ProtocolError::InvalidNetwork(_))
            ));
        }

        let mut wire = v1::RuntimeEvent::from(event());
        wire.payload = Some(v1::runtime_event::Payload::NetworkAccept(
            v1::NetworkAccept {
                transport: v1::NetworkTransport::Tcp.into(),
                address_family: v1::NetworkAddressFamily::Ipv4.into(),
                local_address: vec![0; 4],
                local_port: 8080,
                remote_address: vec![0; 16],
                remote_port: 50_000,
            },
        ));
        assert!(matches!(
            RuntimeEvent::try_from(wire),
            Err(ProtocolError::InvalidNetwork(_))
        ));
    }

    #[test]
    fn dns_query_response_and_connect_context_round_trip() {
        let name = DnsName::new("api.example.com").unwrap();
        let mut query = event();
        query.payload = EventPayload::NetworkDnsQuery(NetworkDnsQuery {
            transaction_id: 42,
            direction: DnsDirection::Egress,
            transport: DnsTransport::Udp,
            resolver_address: "10.96.0.10".parse().unwrap(),
            name: name.clone(),
            query_type: DnsQueryType::A,
        });
        assert_eq!(
            RuntimeEvent::try_from(v1::RuntimeEvent::from(query.clone())).unwrap(),
            query
        );

        let mut response = event();
        response.payload = EventPayload::NetworkDnsResponse(NetworkDnsResponse {
            transaction_id: 42,
            direction: DnsDirection::Ingress,
            transport: DnsTransport::Udp,
            resolver_address: "10.96.0.10".parse().unwrap(),
            name: name.clone(),
            query_type: DnsQueryType::A,
            response_code: DnsResponseCode::NoError,
            truncated: false,
            answers: vec![
                DnsAddressAnswer::new(name.clone(), "203.0.113.7".parse().unwrap(), 60).unwrap(),
            ],
            cname_chain: vec![],
            effective_ttl_seconds: Some(60),
        });
        assert_eq!(
            RuntimeEvent::try_from(v1::RuntimeEvent::from(response.clone())).unwrap(),
            response
        );

        let observed_at = Utc::now();
        let context = DnsContext::new(
            vec![name],
            observed_at,
            observed_at + chrono::Duration::seconds(60),
        )
        .unwrap();
        let mut connect = network_event();
        if let EventPayload::NetworkConnect(value) = &mut connect.payload {
            value.dns_context = Some(context);
        }
        assert_eq!(
            RuntimeEvent::try_from(v1::RuntimeEvent::from(connect.clone())).unwrap(),
            connect
        );
    }

    #[test]
    fn rejects_malformed_dns_wire_fields() {
        let mut wire = v1::RuntimeEvent::from(event());
        wire.payload = Some(v1::runtime_event::Payload::NetworkDnsQuery(
            v1::NetworkDnsQuery {
                transaction_id: 70_000,
                direction: v1::DnsDirection::Egress.into(),
                transport: v1::DnsTransport::Udp.into(),
                resolver_address: vec![10, 0, 0, 1],
                name: "UPPER.example".into(),
                query_type: v1::DnsQueryType::A.into(),
            },
        ));
        assert!(matches!(
            RuntimeEvent::try_from(wire),
            Err(ProtocolError::InvalidDns(_))
        ));

        let mut wire = v1::RuntimeEvent::from(network_event());
        if let Some(v1::runtime_event::Payload::NetworkConnect(network)) = &mut wire.payload {
            network.dns_context = Some(v1::DnsContext {
                names: vec!["one.example".into(), "two.example".into()],
                observed_at_unix_nanos: 1,
                expires_at_unix_nanos: 2,
                confidence: v1::DnsConfidence::ObservedRecently.into(),
                ambiguous: false,
            });
        }
        assert!(matches!(
            RuntimeEvent::try_from(wire),
            Err(ProtocolError::InvalidDns("context.ambiguous"))
        ));
    }

    #[test]
    fn file_payloads_round_trip_and_reject_malformed_paths() {
        let path = FileActivityPath::new("/app/data/report").unwrap();
        let payloads = [
            EventPayload::FileCreate(FileCreate { path: path.clone() }),
            EventPayload::FileModify(FileModify { path: path.clone() }),
            EventPayload::FileDelete(FileDelete { path: path.clone() }),
            EventPayload::FileRename(
                FileRename::new(
                    path,
                    FileActivityPath::new("/app/data/report.done").unwrap(),
                    Some(true),
                )
                .unwrap(),
            ),
        ];
        for payload in payloads {
            let mut value = event();
            value.payload = payload;
            assert_eq!(
                RuntimeEvent::try_from(v1::RuntimeEvent::from(value.clone())).unwrap(),
                value
            );
        }

        for invalid in ["", "relative", "/app/../secret", "/bad\0path"] {
            let mut wire = v1::RuntimeEvent::from(event());
            wire.payload = Some(v1::runtime_event::Payload::FileCreate(v1::FileCreate {
                path: invalid.into(),
            }));
            assert!(matches!(
                RuntimeEvent::try_from(wire),
                Err(ProtocolError::InvalidFile("path"))
            ));
        }
        let mut wire = v1::RuntimeEvent::from(event());
        wire.payload = Some(v1::runtime_event::Payload::FileRename(v1::FileRename {
            old_path: "/same".into(),
            new_path: "/same".into(),
            replaced: Some(false),
        }));
        assert!(matches!(
            RuntimeEvent::try_from(wire),
            Err(ProtocolError::InvalidFile("rename"))
        ));
    }

    #[test]
    fn termination_and_lifecycle_payloads_round_trip() {
        let now = Utc::now();
        let termination =
            ContainerTermination::new("containerd://abc", "OOMKilled", 137, Some(now), Some(now))
                .unwrap();
        let payloads = [
            EventPayload::ProcessExit(ProcessExit::new(
                0x8b,
                ProcessTermination::signaled(11, "SIGSEGV", true).unwrap(),
                GenerationCorrelation::observed(7, Uuid::new_v4(), "/app/worker").unwrap(),
            )),
            EventPayload::ProcessExit(ProcessExit::new(
                7 << 8,
                ProcessTermination::exited(7),
                GenerationCorrelation::Unresolved {
                    reason: UnresolvedGenerationReason::GenerationMismatch,
                },
            )),
            EventPayload::ContainerTermination(termination.clone()),
            EventPayload::ContainerRestart(
                ContainerRestart::new(
                    "containerd://abc",
                    7,
                    3,
                    Some(termination),
                    Some("CrashLoopBackOff".into()),
                )
                .unwrap(),
            ),
        ];
        for payload in payloads {
            let mut value = event();
            value.payload = payload;
            assert_eq!(
                RuntimeEvent::try_from(v1::RuntimeEvent::from(value.clone())).unwrap(),
                value
            );
        }
    }

    #[test]
    fn rejects_contradictory_exit_and_unknown_termination_enums() {
        let mut wire = v1::RuntimeEvent::from(event());
        wire.payload = Some(v1::runtime_event::Payload::ProcessExit(v1::ProcessExit {
            source: v1::EvidenceSource::Kernel.into(),
            raw_wait_status: 9,
            termination: Some(v1::process_exit::Termination::Exited(v1::ProcessExited {
                status: 9,
            })),
            correlation: Some(v1::GenerationCorrelation {
                result: Some(v1::generation_correlation::Result::Unresolved(
                    v1::UnresolvedGeneration {
                        reason: v1::UnresolvedGenerationReason::Evicted.into(),
                    },
                )),
            }),
        }));
        assert!(matches!(
            RuntimeEvent::try_from(wire),
            Err(ProtocolError::InvalidTermination("exit.raw_wait_status"))
        ));

        let mut wire = v1::RuntimeEvent::from(event());
        wire.payload = Some(v1::runtime_event::Payload::ProcessExit(v1::ProcessExit {
            source: 999,
            raw_wait_status: 9,
            termination: Some(v1::process_exit::Termination::Signaled(
                v1::ProcessSignaled {
                    signal: 9,
                    signal_name: "SIGKILL".into(),
                    core_dump_flag: false,
                },
            )),
            correlation: Some(v1::GenerationCorrelation {
                result: Some(v1::generation_correlation::Result::Unresolved(
                    v1::UnresolvedGeneration {
                        reason: v1::UnresolvedGenerationReason::Evicted.into(),
                    },
                )),
            }),
        }));
        assert!(matches!(
            RuntimeEvent::try_from(wire),
            Err(ProtocolError::InvalidTermination("source"))
        ));
    }

    #[test]
    fn rejects_invalid_restart_delta_and_observation_gap() {
        let mut wire = v1::RuntimeEvent::from(event());
        wire.payload = Some(v1::runtime_event::Payload::ContainerRestart(
            v1::ContainerRestart {
                source: v1::EvidenceSource::Kubernetes.into(),
                runtime_container_id: "containerd://abc".into(),
                restart_count: 4,
                restart_delta: 0,
                observation_gap: false,
                previous_termination: None,
                waiting_reason: None,
            },
        ));
        assert!(matches!(
            RuntimeEvent::try_from(wire),
            Err(ProtocolError::InvalidTermination("container_restart"))
        ));

        let mut restart = ContainerRestart::new("containerd://abc", 4, 1, None, None).unwrap();
        restart.observation_gap = true;
        let mut value = event();
        value.payload = EventPayload::ContainerRestart(restart);
        assert!(matches!(
            RuntimeEvent::try_from(v1::RuntimeEvent::from(value)),
            Err(ProtocolError::InvalidTermination(
                "container_restart.observation_gap"
            ))
        ));
    }
}
