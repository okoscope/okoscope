use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use agent_ebpf_common::{
    COMMAND_LEN, DNS_ADDRESS_LEN, DNS_CAPTURE_BYTES, DnsPacketRecord, ExitKernelEvent,
    FILE_FLAG_COMPLETE, FILE_FLAG_REPLACED, FILE_FLAG_REPLACEMENT_KNOWN, FILE_OPERATION_CREATE,
    FILE_OPERATION_DELETE, FILE_OPERATION_MODIFY, FILE_OPERATION_RENAME, FILE_PATH_LEN,
    FileKernelEvent, InboundKernelEvent, KernelEvent, NETWORK_ADDRESS_LEN,
};
use event_model::{
    EventPayload, InboundNetworkError, NetworkAccept, NetworkAddressFamily, NetworkConnect,
    NetworkConnectError, NetworkConnectOutcome, NetworkListen, ProcessTermination,
};
use thiserror::Error;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("kernel event has size {actual}, expected {expected}")]
    InvalidSize { actual: usize, expected: usize },
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ExitDecodeError {
    #[error(transparent)]
    Layout(#[from] DecodeError),
    #[error("exit record reserved field is non-zero")]
    InvalidReserved,
    #[error("malformed Linux wait status {0:#x}")]
    InvalidWaitStatus(i32),
    #[error("unsupported Linux terminating signal {0}")]
    UnsupportedSignal(u8),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedExitEvent {
    pub kernel: ExitKernelEvent,
    pub termination: ProcessTermination,
}

pub fn decode_exit(bytes: &[u8]) -> Result<DecodedExitEvent, ExitDecodeError> {
    if bytes.len() != ExitKernelEvent::SIZE {
        return Err(DecodeError::InvalidSize {
            actual: bytes.len(),
            expected: ExitKernelEvent::SIZE,
        }
        .into());
    }
    let u64_at = |offset: usize| {
        u64::from_ne_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .expect("validated fixed layout"),
        )
    };
    let i32_at = |offset: usize| {
        i32::from_ne_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("validated fixed layout"),
        )
    };
    let u32_at = |offset: usize| {
        u32::from_ne_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("validated fixed layout"),
        )
    };
    let raw_wait_status = i32_at(24);
    let reserved = u32_at(28);
    if reserved != 0 {
        return Err(ExitDecodeError::InvalidReserved);
    }
    let termination = decode_wait_status(raw_wait_status)?;
    let mut command = [0; COMMAND_LEN];
    command.copy_from_slice(&bytes[32..48]);
    Ok(DecodedExitEvent {
        kernel: ExitKernelEvent {
            timestamp_ns: u64_at(0),
            cgroup_id: u64_at(8),
            pid_tgid: u64_at(16),
            raw_wait_status,
            reserved,
            command,
        },
        termination,
    })
}

pub fn decode_wait_status(raw: i32) -> Result<ProcessTermination, ExitDecodeError> {
    if raw < 0 || raw & !0xffff != 0 {
        return Err(ExitDecodeError::InvalidWaitStatus(raw));
    }
    let low = u8::try_from(raw & 0xff).expect("non-negative value is masked to one byte");
    if low == 0 {
        let status =
            u8::try_from((raw >> 8) & 0xff).expect("non-negative value is masked to one byte");
        return Ok(ProcessTermination::exited(status));
    }
    let signal = low & 0x7f;
    let core_dump_flag = low & 0x80 != 0;
    if raw & !0xff != 0 || signal == 0 || signal > event_model::MAX_LINUX_SIGNAL {
        return Err(if signal > event_model::MAX_LINUX_SIGNAL {
            ExitDecodeError::UnsupportedSignal(signal)
        } else {
            ExitDecodeError::InvalidWaitStatus(raw)
        });
    }
    ProcessTermination::signaled(signal, canonical_signal_name(signal), core_dump_flag)
        .map_err(|_| ExitDecodeError::UnsupportedSignal(signal))
}

fn canonical_signal_name(signal: u8) -> String {
    let known = match signal {
        1 => Some("SIGHUP"),
        2 => Some("SIGINT"),
        3 => Some("SIGQUIT"),
        4 => Some("SIGILL"),
        5 => Some("SIGTRAP"),
        6 => Some("SIGABRT"),
        7 => Some("SIGBUS"),
        8 => Some("SIGFPE"),
        9 => Some("SIGKILL"),
        10 => Some("SIGUSR1"),
        11 => Some("SIGSEGV"),
        12 => Some("SIGUSR2"),
        13 => Some("SIGPIPE"),
        14 => Some("SIGALRM"),
        15 => Some("SIGTERM"),
        16 => Some("SIGSTKFLT"),
        17 => Some("SIGCHLD"),
        18 => Some("SIGCONT"),
        19 => Some("SIGSTOP"),
        20 => Some("SIGTSTP"),
        21 => Some("SIGTTIN"),
        22 => Some("SIGTTOU"),
        23 => Some("SIGURG"),
        24 => Some("SIGXCPU"),
        25 => Some("SIGXFSZ"),
        26 => Some("SIGVTALRM"),
        27 => Some("SIGPROF"),
        28 => Some("SIGWINCH"),
        29 => Some("SIGIO"),
        30 => Some("SIGPWR"),
        31 => Some("SIGSYS"),
        _ => None,
    };
    known.map_or_else(|| format!("SIGRTMIN+{}", signal - 32), str::to_owned)
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FileDecodeError {
    #[error(transparent)]
    Layout(#[from] DecodeError),
    #[error("unsupported file operation {0}")]
    UnsupportedOperation(u8),
    #[error("file record path is incomplete")]
    IncompletePath,
    #[error("invalid file record flags {0:#x}")]
    InvalidFlags(u8),
    #[error("invalid file record path length")]
    InvalidPathLength,
    #[error("invalid UTF-8 file record path")]
    InvalidUtf8,
    #[error(transparent)]
    InvalidPath(#[from] event_model::FileActivityError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedFileEvent {
    pub kernel: FileKernelEvent,
    pub payload: EventPayload,
}

pub fn decode_file(bytes: &[u8]) -> Result<DecodedFileEvent, FileDecodeError> {
    if bytes.len() != FileKernelEvent::SIZE {
        return Err(DecodeError::InvalidSize {
            actual: bytes.len(),
            expected: FileKernelEvent::SIZE,
        }
        .into());
    }
    let u64_at = |offset: usize| u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap());
    let i32_at = |offset: usize| i32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap());
    let u16_at = |offset: usize| u16::from_ne_bytes(bytes[offset..offset + 2].try_into().unwrap());
    let path_len = usize::from(u16_at(40));
    let new_path_len = usize::from(u16_at(42));
    let operation = bytes[44];
    let flags = bytes[45];
    if flags & !(FILE_FLAG_COMPLETE | FILE_FLAG_REPLACED | FILE_FLAG_REPLACEMENT_KNOWN) != 0
        || flags & FILE_FLAG_REPLACED != 0 && flags & FILE_FLAG_REPLACEMENT_KNOWN == 0
    {
        return Err(FileDecodeError::InvalidFlags(flags));
    }
    if flags & FILE_FLAG_COMPLETE == 0 {
        return Err(FileDecodeError::IncompletePath);
    }
    if path_len == 0 || path_len > FILE_PATH_LEN || new_path_len > FILE_PATH_LEN {
        return Err(FileDecodeError::InvalidPathLength);
    }
    let path_offset = 64;
    let new_path_offset = path_offset + FILE_PATH_LEN;
    let decode_path = |slice: &[u8]| {
        let value = core::str::from_utf8(slice).map_err(|_| FileDecodeError::InvalidUtf8)?;
        event_model::FileActivityPath::new(value.to_owned()).map_err(FileDecodeError::InvalidPath)
    };
    let path = decode_path(&bytes[path_offset..path_offset + path_len])?;
    let new_path = (new_path_len != 0)
        .then(|| decode_path(&bytes[new_path_offset..new_path_offset + new_path_len]))
        .transpose()?;
    let payload = match operation {
        FILE_OPERATION_CREATE if new_path.is_none() => {
            EventPayload::FileCreate(event_model::FileCreate { path })
        }
        FILE_OPERATION_MODIFY if new_path.is_none() => {
            EventPayload::FileModify(event_model::FileModify { path })
        }
        FILE_OPERATION_DELETE if new_path.is_none() => {
            EventPayload::FileDelete(event_model::FileDelete { path })
        }
        FILE_OPERATION_RENAME => EventPayload::FileRename(event_model::FileRename::new(
            path,
            new_path.ok_or(FileDecodeError::InvalidPathLength)?,
            (flags & FILE_FLAG_REPLACEMENT_KNOWN != 0).then_some(flags & FILE_FLAG_REPLACED != 0),
        )?),
        value => return Err(FileDecodeError::UnsupportedOperation(value)),
    };
    let mut command = [0; COMMAND_LEN];
    command.copy_from_slice(&bytes[48..64]);
    let mut raw_path = [0; FILE_PATH_LEN];
    raw_path.copy_from_slice(&bytes[path_offset..new_path_offset]);
    let mut raw_new_path = [0; FILE_PATH_LEN];
    raw_new_path.copy_from_slice(&bytes[new_path_offset..new_path_offset + FILE_PATH_LEN]);
    Ok(DecodedFileEvent {
        kernel: FileKernelEvent {
            timestamp_ns: u64_at(0),
            cgroup_id: u64_at(8),
            pid_tgid: u64_at(16),
            descriptor_generation: u64_at(24),
            fd: i32_at(32),
            result: i32_at(36),
            path_len: u16::try_from(path_len).map_err(|_| FileDecodeError::InvalidPathLength)?,
            new_path_len: u16::try_from(new_path_len)
                .map_err(|_| FileDecodeError::InvalidPathLength)?,
            operation,
            flags,
            padding: [bytes[46], bytes[47]],
            command,
            path: raw_path,
            new_path: raw_new_path,
        },
        payload,
    })
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum NetworkDecodeError {
    #[error("unsupported network address family {0}")]
    UnsupportedFamily(u8),
    #[error("unsupported connect outcome {0}")]
    UnsupportedOutcome(u8),
    #[error("unsupported inbound event kind {0}")]
    UnsupportedInboundKind(u8),
    #[error(transparent)]
    Invalid(#[from] NetworkConnectError),
    #[error(transparent)]
    InvalidInbound(#[from] InboundNetworkError),
}

pub fn decode_inbound(bytes: &[u8]) -> Result<InboundKernelEvent, DecodeError> {
    if bytes.len() != InboundKernelEvent::SIZE {
        return Err(DecodeError::InvalidSize {
            actual: bytes.len(),
            expected: InboundKernelEvent::SIZE,
        });
    }
    let u64_at = |offset: usize| {
        u64::from_ne_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .expect("validated fixed layout"),
        )
    };
    let u16_at = |offset: usize| {
        u16::from_ne_bytes(
            bytes[offset..offset + 2]
                .try_into()
                .expect("validated fixed layout"),
        )
    };
    let mut local_address = [0; NETWORK_ADDRESS_LEN];
    local_address.copy_from_slice(&bytes[24..40]);
    let mut remote_address = [0; NETWORK_ADDRESS_LEN];
    remote_address.copy_from_slice(&bytes[40..56]);
    let mut command = [0; COMMAND_LEN];
    command.copy_from_slice(&bytes[64..80]);
    Ok(InboundKernelEvent {
        timestamp_ns: u64_at(0),
        cgroup_id: u64_at(8),
        pid_tgid: u64_at(16),
        local_address,
        remote_address,
        local_port: u16_at(56),
        remote_port: u16_at(58),
        event_kind: bytes[60],
        address_family: bytes[61],
        padding: [bytes[62], bytes[63]],
        command,
    })
}

pub fn decode(bytes: &[u8]) -> Result<KernelEvent, DecodeError> {
    if bytes.len() != KernelEvent::SIZE {
        return Err(DecodeError::InvalidSize {
            actual: bytes.len(),
            expected: KernelEvent::SIZE,
        });
    }
    let u64_at = |offset: usize| {
        u64::from_ne_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .expect("validated fixed layout"),
        )
    };
    let u32_at = |offset: usize| {
        u32::from_ne_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("validated fixed layout"),
        )
    };
    let i32_at = |offset: usize| {
        i32::from_ne_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("validated fixed layout"),
        )
    };
    let u16_at = |offset: usize| {
        u16::from_ne_bytes(
            bytes[offset..offset + 2]
                .try_into()
                .expect("validated fixed layout"),
        )
    };
    let mut destination_address = [0_u8; NETWORK_ADDRESS_LEN];
    destination_address.copy_from_slice(&bytes[40..56]);
    let mut command = [0_u8; COMMAND_LEN];
    command.copy_from_slice(&bytes[56..72]);
    Ok(KernelEvent {
        timestamp_ns: u64_at(0),
        cgroup_id: u64_at(8),
        pid_tgid: u64_at(16),
        syscall_id: u32_at(24),
        connect_result: i32_at(28),
        event_kind: bytes[32],
        address_family: bytes[33],
        connect_outcome: bytes[34],
        padding: bytes[35],
        destination_port: u16_at(36),
        errno: u16_at(38),
        destination_address,
        command,
    })
}

pub fn decode_dns_packet(bytes: &[u8]) -> Result<DnsPacketRecord, DecodeError> {
    if bytes.len() != DnsPacketRecord::SIZE {
        return Err(DecodeError::InvalidSize {
            actual: bytes.len(),
            expected: DnsPacketRecord::SIZE,
        });
    }
    let u64_at = |offset: usize| {
        u64::from_ne_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .expect("validated fixed layout"),
        )
    };
    let u32_at = |offset: usize| {
        u32::from_ne_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("validated fixed layout"),
        )
    };
    let u16_at = |offset: usize| {
        u16::from_ne_bytes(
            bytes[offset..offset + 2]
                .try_into()
                .expect("validated fixed layout"),
        )
    };
    let mut resolver_address = [0; DNS_ADDRESS_LEN];
    resolver_address.copy_from_slice(&bytes[44..60]);
    let mut command = [0; COMMAND_LEN];
    command.copy_from_slice(&bytes[60..76]);
    let mut payload = [0; DNS_CAPTURE_BYTES];
    payload.copy_from_slice(&bytes[76..76 + DNS_CAPTURE_BYTES]);
    Ok(DnsPacketRecord {
        timestamp_ns: u64_at(0),
        cgroup_id: u64_at(8),
        socket_cookie: u64_at(16),
        pid_tgid: u64_at(24),
        sequence: u32_at(32),
        payload_len: u16_at(36),
        resolver_port: u16_at(38),
        address_family: bytes[40],
        transport: bytes[41],
        direction: bytes[42],
        tcp_flags: bytes[43],
        resolver_address,
        command,
        payload,
    })
}

pub fn network_connect(event: &KernelEvent) -> Result<NetworkConnect, NetworkDecodeError> {
    let (address_family, destination_address) = match event.address_family {
        agent_ebpf_common::ADDRESS_FAMILY_IPV4 => (
            NetworkAddressFamily::Ipv4,
            IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(&event.destination_address[..4])
                    .expect("fixed IPv4 address slice"),
            )),
        ),
        agent_ebpf_common::ADDRESS_FAMILY_IPV6 => (
            NetworkAddressFamily::Ipv6,
            IpAddr::V6(Ipv6Addr::from(event.destination_address)),
        ),
        family => return Err(NetworkDecodeError::UnsupportedFamily(family)),
    };
    let (outcome, errno) = match event.connect_outcome {
        agent_ebpf_common::CONNECT_OUTCOME_SUCCEEDED => (
            NetworkConnectOutcome::Succeeded,
            (event.errno != 0).then_some(event.errno),
        ),
        agent_ebpf_common::CONNECT_OUTCOME_IN_PROGRESS => {
            (NetworkConnectOutcome::InProgress, Some(event.errno))
        }
        agent_ebpf_common::CONNECT_OUTCOME_FAILED => {
            (NetworkConnectOutcome::Failed, Some(event.errno))
        }
        outcome => return Err(NetworkDecodeError::UnsupportedOutcome(outcome)),
    };
    NetworkConnect::new(
        address_family,
        destination_address,
        event.destination_port,
        outcome,
        errno,
    )
    .map_err(Into::into)
}

pub fn inbound_payload(event: &InboundKernelEvent) -> Result<EventPayload, NetworkDecodeError> {
    let (family, local_address, remote_address) = match event.address_family {
        agent_ebpf_common::ADDRESS_FAMILY_IPV4 => (
            NetworkAddressFamily::Ipv4,
            IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(&event.local_address[..4]).expect("fixed IPv4 slice"),
            )),
            IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(&event.remote_address[..4]).expect("fixed IPv4 slice"),
            )),
        ),
        agent_ebpf_common::ADDRESS_FAMILY_IPV6 => (
            NetworkAddressFamily::Ipv6,
            IpAddr::V6(Ipv6Addr::from(event.local_address)),
            IpAddr::V6(Ipv6Addr::from(event.remote_address)),
        ),
        family => return Err(NetworkDecodeError::UnsupportedFamily(family)),
    };
    match event.event_kind {
        agent_ebpf_common::EVENT_KIND_NETWORK_LISTEN => {
            NetworkListen::new(family, local_address, event.local_port)
                .map(EventPayload::NetworkListen)
                .map_err(Into::into)
        }
        agent_ebpf_common::EVENT_KIND_NETWORK_ACCEPT => NetworkAccept::new(
            family,
            local_address,
            event.local_port,
            remote_address,
            event.remote_port,
        )
        .map(EventPayload::NetworkAccept)
        .map_err(Into::into),
        kind => Err(NetworkDecodeError::UnsupportedInboundKind(kind)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exit_fixture(raw_wait_status: i32) -> [u8; ExitKernelEvent::SIZE] {
        let mut bytes = [0; ExitKernelEvent::SIZE];
        bytes[0..8].copy_from_slice(&1_u64.to_ne_bytes());
        bytes[8..16].copy_from_slice(&2_u64.to_ne_bytes());
        bytes[16..24].copy_from_slice(&3_u64.to_ne_bytes());
        bytes[24..28].copy_from_slice(&raw_wait_status.to_ne_bytes());
        bytes[32..38].copy_from_slice(b"worker");
        bytes
    }

    #[test]
    fn exit_fixtures_decode_native_wait_semantics() {
        let cases = [
            (7 << 8, ProcessTermination::Exited { status: 7 }, None),
            (
                15,
                ProcessTermination::Signaled {
                    signal: 15,
                    signal_name: "SIGTERM".into(),
                    core_dump_flag: false,
                },
                Some(143),
            ),
            (
                9,
                ProcessTermination::Signaled {
                    signal: 9,
                    signal_name: "SIGKILL".into(),
                    core_dump_flag: false,
                },
                Some(137),
            ),
            (
                0x8b,
                ProcessTermination::Signaled {
                    signal: 11,
                    signal_name: "SIGSEGV".into(),
                    core_dump_flag: true,
                },
                Some(139),
            ),
        ];
        for (raw, expected, conventional) in cases {
            let decoded = decode_exit(&exit_fixture(raw)).unwrap();
            assert_eq!(decoded.termination, expected);
            assert_eq!(decoded.termination.conventional_exit_code(), conventional);
            assert_eq!(decoded.kernel.raw_wait_status, raw);
            assert_eq!(&decoded.kernel.command[..6], b"worker");
        }
    }

    #[test]
    fn exit_decoder_rejects_layout_reserved_and_malformed_status() {
        assert!(matches!(
            decode_exit(&[0; 4]),
            Err(ExitDecodeError::Layout(DecodeError::InvalidSize { .. }))
        ));
        let mut reserved = exit_fixture(0);
        reserved[28] = 1;
        assert_eq!(
            decode_exit(&reserved),
            Err(ExitDecodeError::InvalidReserved)
        );
        for raw in [-1, 0x1_0000, 0x100 | 9, 0x7f] {
            assert!(decode_wait_status(raw).is_err(), "accepted {raw:#x}");
        }
    }

    #[test]
    fn rejects_wrong_size() {
        assert!(matches!(
            decode(&[0; 4]),
            Err(DecodeError::InvalidSize { .. })
        ));
        assert!(matches!(
            decode_dns_packet(&[0; 4]),
            Err(DecodeError::InvalidSize { .. })
        ));
        assert!(matches!(
            decode_inbound(&[0; 4]),
            Err(DecodeError::InvalidSize { .. })
        ));
    }

    #[test]
    fn decodes_dns_packet_record_with_fixed_native_layout() {
        let mut bytes = [0_u8; DnsPacketRecord::SIZE];
        bytes[0..8].copy_from_slice(&17_u64.to_ne_bytes());
        bytes[8..16].copy_from_slice(&23_u64.to_ne_bytes());
        bytes[16..24].copy_from_slice(&29_u64.to_ne_bytes());
        bytes[24..32].copy_from_slice(&31_u64.to_ne_bytes());
        bytes[32..36].copy_from_slice(&37_u32.to_ne_bytes());
        bytes[36..38].copy_from_slice(&4_u16.to_ne_bytes());
        bytes[38..40].copy_from_slice(&53_u16.to_ne_bytes());
        bytes[40] = agent_ebpf_common::ADDRESS_FAMILY_IPV6;
        bytes[41] = agent_ebpf_common::DNS_TRANSPORT_TCP;
        bytes[42] = agent_ebpf_common::DNS_DIRECTION_INGRESS;
        bytes[43] = 0x18;
        bytes[44..60].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        bytes[60..68].copy_from_slice(b"resolver");
        bytes[76..80].copy_from_slice(&[0x12, 0x34, 0x01, 0x00]);

        let decoded = decode_dns_packet(&bytes).unwrap();
        assert_eq!(decoded.timestamp_ns, 17);
        assert_eq!(decoded.cgroup_id, 23);
        assert_eq!(decoded.socket_cookie, 29);
        assert_eq!(decoded.pid_tgid, 31);
        assert_eq!(decoded.sequence, 37);
        assert_eq!(decoded.payload_len, 4);
        assert_eq!(decoded.resolver_port, 53);
        assert_eq!(
            decoded.address_family,
            agent_ebpf_common::ADDRESS_FAMILY_IPV6
        );
        assert_eq!(decoded.transport, agent_ebpf_common::DNS_TRANSPORT_TCP);
        assert_eq!(decoded.direction, agent_ebpf_common::DNS_DIRECTION_INGRESS);
        assert_eq!(decoded.resolver_address, Ipv6Addr::LOCALHOST.octets());
        assert_eq!(&decoded.command[..8], b"resolver");
        assert_eq!(&decoded.payload[..4], &[0x12, 0x34, 0x01, 0x00]);
    }

    #[test]
    fn decodes_network_record_with_native_layout() {
        let mut bytes = [0_u8; KernelEvent::SIZE];
        bytes[28..32].copy_from_slice(&(-111_i32).to_ne_bytes());
        bytes[32] = agent_ebpf_common::EVENT_KIND_NETWORK_CONNECT;
        bytes[33] = agent_ebpf_common::ADDRESS_FAMILY_IPV4;
        bytes[34] = agent_ebpf_common::CONNECT_OUTCOME_FAILED;
        bytes[36..38].copy_from_slice(&443_u16.to_ne_bytes());
        bytes[38..40].copy_from_slice(&111_u16.to_ne_bytes());
        bytes[40..44].copy_from_slice(&[203, 0, 113, 7]);
        assert_eq!(decode(&bytes).unwrap().connect_result, -111);
        assert_eq!(decode(&bytes).unwrap().destination_port, 443);
        assert_eq!(
            decode(&bytes).unwrap().destination_address[0..4],
            [203, 0, 113, 7]
        );
        let decoded = decode(&bytes).unwrap();
        let network = network_connect(&decoded).unwrap();
        assert_eq!(network.destination_address.to_string(), "203.0.113.7");
        assert_eq!(network.outcome, NetworkConnectOutcome::Failed);
        assert_eq!(network.errno, Some(111));
    }

    #[test]
    fn decodes_ipv6_and_rejects_invalid_network_semantics() {
        let mut event = KernelEvent {
            timestamp_ns: 1,
            cgroup_id: 2,
            pid_tgid: 3,
            syscall_id: 0,
            connect_result: -115,
            event_kind: agent_ebpf_common::EVENT_KIND_NETWORK_CONNECT,
            address_family: agent_ebpf_common::ADDRESS_FAMILY_IPV6,
            connect_outcome: agent_ebpf_common::CONNECT_OUTCOME_IN_PROGRESS,
            padding: 0,
            destination_port: 443,
            errno: event_model::LINUX_EINPROGRESS,
            destination_address: Ipv6Addr::LOCALHOST.octets(),
            command: [0; COMMAND_LEN],
        };
        assert_eq!(
            network_connect(&event).unwrap().destination_address,
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        );
        event.address_family = 99;
        assert_eq!(
            network_connect(&event),
            Err(NetworkDecodeError::UnsupportedFamily(99))
        );
        event.address_family = agent_ebpf_common::ADDRESS_FAMILY_IPV6;
        event.connect_outcome = agent_ebpf_common::CONNECT_OUTCOME_SUCCEEDED;
        assert_eq!(
            network_connect(&event),
            Err(NetworkDecodeError::Invalid(
                NetworkConnectError::InconsistentOutcome
            ))
        );
    }

    #[test]
    fn decodes_listener_and_accepted_connection_records() {
        let mut bytes = [0_u8; InboundKernelEvent::SIZE];
        bytes[0..8].copy_from_slice(&17_u64.to_ne_bytes());
        bytes[8..16].copy_from_slice(&23_u64.to_ne_bytes());
        bytes[16..24].copy_from_slice(&29_u64.to_ne_bytes());
        bytes[24..28].copy_from_slice(&[0, 0, 0, 0]);
        bytes[40..44].copy_from_slice(&[203, 0, 113, 9]);
        bytes[56..58].copy_from_slice(&8080_u16.to_ne_bytes());
        bytes[58..60].copy_from_slice(&51_000_u16.to_ne_bytes());
        bytes[60] = agent_ebpf_common::EVENT_KIND_NETWORK_ACCEPT;
        bytes[61] = agent_ebpf_common::ADDRESS_FAMILY_IPV4;
        bytes[64..67].copy_from_slice(b"api");
        let decoded = decode_inbound(&bytes).unwrap();
        assert_eq!(decoded.cgroup_id, 23);
        assert_eq!(&decoded.command[..3], b"api");
        let EventPayload::NetworkAccept(accepted) = inbound_payload(&decoded).unwrap() else {
            panic!("expected accepted connection");
        };
        assert_eq!(accepted.local_address.to_string(), "0.0.0.0");
        assert_eq!(accepted.remote_address.to_string(), "203.0.113.9");
        assert_eq!(accepted.remote_port, 51_000);

        let mut listener = decoded;
        listener.event_kind = agent_ebpf_common::EVENT_KIND_NETWORK_LISTEN;
        listener.remote_port = 0;
        let EventPayload::NetworkListen(listener) = inbound_payload(&listener).unwrap() else {
            panic!("expected listener");
        };
        assert_eq!(listener.local_port, 8080);

        let mut ipv6 = decoded;
        ipv6.address_family = agent_ebpf_common::ADDRESS_FAMILY_IPV6;
        ipv6.local_address = Ipv6Addr::UNSPECIFIED.octets();
        ipv6.remote_address = Ipv6Addr::LOCALHOST.octets();
        let EventPayload::NetworkAccept(ipv6) = inbound_payload(&ipv6).unwrap() else {
            panic!("expected IPv6 accepted connection");
        };
        assert_eq!(ipv6.local_address, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert_eq!(ipv6.remote_address, IpAddr::V6(Ipv6Addr::LOCALHOST));

        let mut malformed = decoded;
        malformed.address_family = 99;
        assert_eq!(
            inbound_payload(&malformed),
            Err(NetworkDecodeError::UnsupportedFamily(99))
        );
        malformed = decoded;
        malformed.event_kind = 99;
        assert_eq!(
            inbound_payload(&malformed),
            Err(NetworkDecodeError::UnsupportedInboundKind(99))
        );
        malformed = decoded;
        malformed.remote_port = 0;
        assert!(matches!(
            inbound_payload(&malformed),
            Err(NetworkDecodeError::InvalidInbound(_))
        ));
    }

    #[test]
    fn decodes_file_records_and_rejects_invalid_layout_semantics() {
        let mut bytes = vec![0_u8; FileKernelEvent::SIZE];
        bytes[0..8].copy_from_slice(&11_u64.to_ne_bytes());
        bytes[8..16].copy_from_slice(&12_u64.to_ne_bytes());
        bytes[16..24].copy_from_slice(&13_u64.to_ne_bytes());
        bytes[24..32].copy_from_slice(&14_u64.to_ne_bytes());
        bytes[32..36].copy_from_slice(&7_i32.to_ne_bytes());
        bytes[36..40].copy_from_slice(&1_i32.to_ne_bytes());
        let path = b"/app/data/report";
        bytes[40..42].copy_from_slice(&u16::try_from(path.len()).unwrap().to_ne_bytes());
        bytes[44] = FILE_OPERATION_MODIFY;
        bytes[45] = FILE_FLAG_COMPLETE;
        bytes[48..51].copy_from_slice(b"api");
        bytes[64..64 + path.len()].copy_from_slice(path);
        let decoded = decode_file(&bytes).unwrap();
        assert_eq!(decoded.kernel.descriptor_generation, 14);
        assert!(matches!(decoded.payload, EventPayload::FileModify(_)));

        let mut incomplete = bytes.clone();
        incomplete[45] = 0;
        assert_eq!(
            decode_file(&incomplete),
            Err(FileDecodeError::IncompletePath)
        );
        let mut unknown = bytes.clone();
        unknown[44] = 99;
        assert_eq!(
            decode_file(&unknown),
            Err(FileDecodeError::UnsupportedOperation(99))
        );
        let mut relative = bytes;
        let relative_path = b"relative/report";
        relative[40..42]
            .copy_from_slice(&u16::try_from(relative_path.len()).unwrap().to_ne_bytes());
        relative[64..64 + path.len()].fill(0);
        relative[64..64 + relative_path.len()].copy_from_slice(relative_path);
        assert!(matches!(
            decode_file(&relative),
            Err(FileDecodeError::InvalidPath(_))
        ));
        assert!(matches!(
            decode_file(&[0; 2]),
            Err(FileDecodeError::Layout(_))
        ));
    }
}
