#![no_std]

pub const COMMAND_LEN: usize = 16;
pub const EVENT_KIND_EXEC: u8 = 1;
pub const EVENT_KIND_SYSCALL: u8 = 2;
pub const EVENT_KIND_NETWORK_CONNECT: u8 = 3;
pub const EVENT_KIND_NETWORK_LISTEN: u8 = 4;
pub const EVENT_KIND_NETWORK_ACCEPT: u8 = 5;
pub const ADDRESS_FAMILY_IPV4: u8 = 1;
pub const ADDRESS_FAMILY_IPV6: u8 = 2;
pub const CONNECT_OUTCOME_SUCCEEDED: u8 = 1;
pub const CONNECT_OUTCOME_IN_PROGRESS: u8 = 2;
pub const CONNECT_OUTCOME_FAILED: u8 = 3;
pub const NETWORK_ADDRESS_LEN: usize = 16;
pub const NETWORK_COUNTER_CAPACITY: u32 = 0;
pub const NETWORK_COUNTER_CORRELATION_MISS: u32 = 1;
pub const NETWORK_COUNTER_DECODE_FAILED: u32 = 2;
pub const NETWORK_COUNTER_UNSUPPORTED_FAMILY: u32 = 3;
pub const NETWORK_COUNTER_KERNEL_LOST: u32 = 4;
pub const NETWORK_COUNTER_COUNT: u32 = 5;
pub const INBOUND_COUNTER_DECODE_FAILED: u32 = 0;
pub const INBOUND_COUNTER_ATTRIBUTION_FAILED: u32 = 1;
pub const INBOUND_COUNTER_UNSUPPORTED_FAMILY: u32 = 2;
pub const INBOUND_COUNTER_KERNEL_LOST: u32 = 3;
pub const INBOUND_COUNTER_CORRELATION_MISS: u32 = 4;
pub const INBOUND_COUNTER_COUNT: u32 = 5;
pub const INBOUND_PENDING_ACCEPT_CAPACITY: u32 = 16_384;
pub const INBOUND_RING_BYTES: u32 = 256 * 1024;
pub const IP_PROTOCOL_TCP: u16 = 6;
pub const TCP_STATE_ESTABLISHED: i32 = 1;
pub const TCP_STATE_SYN_RECV: i32 = 3;
pub const TCP_STATE_LISTEN: i32 = 10;
pub const TCP_STATE_NEW_SYN_RECV: i32 = 12;
pub const DNS_CAPTURE_BYTES: usize = 1232;
pub const DNS_ADDRESS_LEN: usize = 16;
pub const DNS_TRANSPORT_UDP: u8 = 1;
pub const DNS_TRANSPORT_TCP: u8 = 2;
pub const DNS_DIRECTION_EGRESS: u8 = 1;
pub const DNS_DIRECTION_INGRESS: u8 = 2;
pub const DNS_COUNTER_UNSUPPORTED_FRAMING: u32 = 0;
pub const DNS_COUNTER_ATTRIBUTION_FAILED: u32 = 1;
pub const DNS_COUNTER_DECODE_FAILED: u32 = 2;
pub const DNS_COUNTER_OVERSIZE: u32 = 3;
pub const DNS_COUNTER_RING_LOST: u32 = 4;
pub const DNS_COUNTER_COUNT: u32 = 5;
pub const FILE_PATH_LEN: usize = 1024;
pub const FILE_OPERATION_CREATE: u8 = 1;
pub const FILE_OPERATION_MODIFY: u8 = 2;
pub const FILE_OPERATION_DELETE: u8 = 3;
pub const FILE_OPERATION_RENAME: u8 = 4;
pub const FILE_OPERATION_OPEN: u8 = 5;
pub const FILE_OPERATION_CLOSE: u8 = 6;
pub const FILE_FLAG_REPLACED: u8 = 1;
pub const FILE_FLAG_COMPLETE: u8 = 2;
pub const FILE_FLAG_REPLACEMENT_KNOWN: u8 = 4;
pub const FILE_COUNTER_CORRELATION_CAPACITY: u32 = 0;
pub const FILE_COUNTER_CORRELATION_MISS: u32 = 1;
pub const FILE_COUNTER_PATH_READ_FAILED: u32 = 2;
pub const FILE_COUNTER_PATH_RELATIVE: u32 = 3;
pub const FILE_COUNTER_PATH_INVALID: u32 = 4;
pub const FILE_COUNTER_PATH_OVERSIZE: u32 = 5;
pub const FILE_COUNTER_FD_MISS: u32 = 6;
pub const FILE_COUNTER_FILTERED: u32 = 7;
pub const FILE_COUNTER_KERNEL_LOST: u32 = 8;
pub const FILE_COUNTER_COUNT: u32 = 9;
pub const EXIT_COUNTER_RING_LOST: u32 = 0;
pub const EXIT_COUNTER_COUNT: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KernelEvent {
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub pid_tgid: u64,
    pub syscall_id: u32,
    pub connect_result: i32,
    pub event_kind: u8,
    pub address_family: u8,
    pub connect_outcome: u8,
    pub padding: u8,
    pub destination_port: u16,
    pub errno: u16,
    pub destination_address: [u8; NETWORK_ADDRESS_LEN],
    pub command: [u8; COMMAND_LEN],
}

impl KernelEvent {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

/// Fixed kernel/userspace ABI emitted by the C CO-RE exit companion.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExitKernelEvent {
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub pid_tgid: u64,
    pub raw_wait_status: i32,
    pub reserved: u32,
    pub command: [u8; COMMAND_LEN],
}

impl ExitKernelEvent {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PendingConnect {
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub pid_tgid: u64,
    pub destination_address: [u8; NETWORK_ADDRESS_LEN],
    pub destination_port: u16,
    pub address_family: u8,
    pub padding: [u8; 5],
    pub command: [u8; COMMAND_LEN],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct InboundEndpoints {
    pub observed_at_ns: u64,
    pub local_address: [u8; NETWORK_ADDRESS_LEN],
    pub remote_address: [u8; NETWORK_ADDRESS_LEN],
    pub local_port: u16,
    pub remote_port: u16,
    pub address_family: u8,
    pub padding: [u8; 3],
}

impl InboundEndpoints {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct InboundKernelEvent {
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub pid_tgid: u64,
    pub local_address: [u8; NETWORK_ADDRESS_LEN],
    pub remote_address: [u8; NETWORK_ADDRESS_LEN],
    pub local_port: u16,
    pub remote_port: u16,
    pub event_kind: u8,
    pub address_family: u8,
    pub padding: [u8; 2],
    pub command: [u8; COMMAND_LEN],
}

impl InboundKernelEvent {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InboundTransition {
    Ignore,
    Invalid,
    Listen,
    PendingAccept,
}

pub const fn classify_inbound_transition(
    protocol: u16,
    socket_address: u64,
    old_state: i32,
    new_state: i32,
    local_port: u16,
    remote_port: u16,
) -> InboundTransition {
    if protocol != IP_PROTOCOL_TCP {
        return InboundTransition::Ignore;
    }
    if new_state == TCP_STATE_LISTEN && old_state != TCP_STATE_LISTEN {
        return if socket_address == 0 || local_port == 0 {
            InboundTransition::Invalid
        } else {
            InboundTransition::Listen
        };
    }
    if new_state == TCP_STATE_ESTABLISHED
        && (old_state == TCP_STATE_SYN_RECV || old_state == TCP_STATE_NEW_SYN_RECV)
    {
        return if socket_address == 0 || local_port == 0 || remote_port == 0 {
            InboundTransition::Invalid
        } else {
            InboundTransition::PendingAccept
        };
    }
    InboundTransition::Ignore
}

/// Fixed kernel/userspace ABI for one bounded plaintext DNS packet candidate.
/// Source ephemeral ports and bytes beyond `payload_len` are never meaningful.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DnsPacketRecord {
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub socket_cookie: u64,
    pub pid_tgid: u64,
    pub sequence: u32,
    pub payload_len: u16,
    pub resolver_port: u16,
    pub address_family: u8,
    pub transport: u8,
    pub direction: u8,
    pub tcp_flags: u8,
    pub resolver_address: [u8; DNS_ADDRESS_LEN],
    pub command: [u8; COMMAND_LEN],
    pub payload: [u8; DNS_CAPTURE_BYTES],
}

impl DnsPacketRecord {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileKernelEvent {
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub pid_tgid: u64,
    pub descriptor_generation: u64,
    pub fd: i32,
    pub result: i32,
    pub path_len: u16,
    pub new_path_len: u16,
    pub operation: u8,
    pub flags: u8,
    pub padding: [u8; 2],
    pub command: [u8; COMMAND_LEN],
    pub path: [u8; FILE_PATH_LEN],
    pub new_path: [u8; FILE_PATH_LEN],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PendingFileOperation {
    pub cgroup_id: u64,
    pub pid_tgid: u64,
    pub fd: i32,
    pub operation: u8,
    pub flags: u8,
    pub path_len: u16,
    pub new_path_len: u16,
    pub padding: [u8; 2],
    pub command: [u8; COMMAND_LEN],
    pub path: [u8; FILE_PATH_LEN],
    pub new_path: [u8; FILE_PATH_LEN],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TrackedFileDescriptor {
    pub cgroup_id: u64,
    pub pid_tgid: u64,
    pub generation: u64,
    pub path_len: u16,
    pub padding: [u8; 6],
    pub command: [u8; COMMAND_LEN],
    pub path: [u8; FILE_PATH_LEN],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileDescriptorKey {
    pub tgid: u32,
    pub fd: i32,
}

impl FileKernelEvent {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

const _: [(); 72] = [(); core::mem::size_of::<KernelEvent>()];
const _: [(); 48] = [(); core::mem::size_of::<ExitKernelEvent>()];
const _: [(); 8] = [(); core::mem::align_of::<ExitKernelEvent>()];
const _: [(); 24] = [(); core::mem::offset_of!(ExitKernelEvent, raw_wait_status)];
const _: [(); 32] = [(); core::mem::offset_of!(ExitKernelEvent, command)];
const _: [(); 64] = [(); core::mem::size_of::<PendingConnect>()];
const _: [(); 48] = [(); core::mem::size_of::<InboundEndpoints>()];
const _: [(); 80] = [(); core::mem::size_of::<InboundKernelEvent>()];
const _: [(); 1312] = [(); core::mem::size_of::<DnsPacketRecord>()];
const _: [(); 8] = [(); core::mem::align_of::<DnsPacketRecord>()];
const _: [(); 2112] = [(); core::mem::size_of::<FileKernelEvent>()];
const _: [(); 8] = [(); core::mem::align_of::<FileKernelEvent>()];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbound_transition_predicates_are_bounded_and_deduplicated() {
        assert_eq!(
            classify_inbound_transition(IP_PROTOCOL_TCP, 1, 7, TCP_STATE_LISTEN, 8080, 0),
            InboundTransition::Listen
        );
        assert_eq!(
            classify_inbound_transition(
                IP_PROTOCOL_TCP,
                1,
                TCP_STATE_LISTEN,
                TCP_STATE_LISTEN,
                8080,
                0,
            ),
            InboundTransition::Ignore
        );
        for old_state in [TCP_STATE_SYN_RECV, TCP_STATE_NEW_SYN_RECV] {
            assert_eq!(
                classify_inbound_transition(
                    IP_PROTOCOL_TCP,
                    1,
                    old_state,
                    TCP_STATE_ESTABLISHED,
                    8080,
                    51_000,
                ),
                InboundTransition::PendingAccept
            );
        }
        assert_eq!(
            classify_inbound_transition(17, 1, 7, TCP_STATE_LISTEN, 53, 0),
            InboundTransition::Ignore
        );
        assert_eq!(
            classify_inbound_transition(IP_PROTOCOL_TCP, 0, 7, TCP_STATE_LISTEN, 8080, 0),
            InboundTransition::Invalid
        );
        assert_eq!(
            classify_inbound_transition(IP_PROTOCOL_TCP, 1, 7, TCP_STATE_LISTEN, 0, 0),
            InboundTransition::Invalid
        );
        assert_eq!(
            classify_inbound_transition(IP_PROTOCOL_TCP, 1, 7, 7, 0, 0),
            InboundTransition::Ignore
        );
        assert_eq!(
            classify_inbound_transition(
                IP_PROTOCOL_TCP,
                1,
                TCP_STATE_SYN_RECV,
                TCP_STATE_ESTABLISHED,
                8080,
                0,
            ),
            InboundTransition::Invalid
        );
    }

    #[test]
    fn inbound_capacity_and_abi_stay_fixed() {
        assert_eq!(INBOUND_PENDING_ACCEPT_CAPACITY, 16_384);
        assert_eq!(INBOUND_RING_BYTES, 256 * 1024);
        assert_eq!(InboundEndpoints::SIZE, 48);
        assert_eq!(InboundKernelEvent::SIZE, 80);
    }
}
