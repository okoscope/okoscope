#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use agent_ebpf_common::{
    ADDRESS_FAMILY_IPV4, ADDRESS_FAMILY_IPV6, CONNECT_OUTCOME_FAILED, CONNECT_OUTCOME_IN_PROGRESS,
    CONNECT_OUTCOME_SUCCEEDED, DNS_ADDRESS_LEN, DNS_CAPTURE_BYTES, DNS_COUNTER_ATTRIBUTION_FAILED,
    DNS_COUNTER_COUNT, DNS_COUNTER_DECODE_FAILED, DNS_COUNTER_OVERSIZE, DNS_COUNTER_RING_LOST,
    DNS_COUNTER_UNSUPPORTED_FRAMING, DNS_DIRECTION_EGRESS, DNS_DIRECTION_INGRESS,
    DNS_TRANSPORT_TCP, DNS_TRANSPORT_UDP, DnsPacketRecord, EVENT_KIND_EXEC,
    EVENT_KIND_NETWORK_ACCEPT, EVENT_KIND_NETWORK_CONNECT, EVENT_KIND_NETWORK_LISTEN,
    EVENT_KIND_SYSCALL, FILE_COUNTER_CORRELATION_CAPACITY, FILE_COUNTER_CORRELATION_MISS,
    FILE_COUNTER_COUNT, FILE_COUNTER_FD_MISS, FILE_COUNTER_KERNEL_LOST, FILE_COUNTER_PATH_OVERSIZE,
    FILE_COUNTER_PATH_READ_FAILED, FILE_COUNTER_PATH_RELATIVE, FILE_FLAG_COMPLETE,
    FILE_FLAG_REPLACEMENT_KNOWN, FILE_OPERATION_CLOSE, FILE_OPERATION_CREATE,
    FILE_OPERATION_DELETE, FILE_OPERATION_MODIFY, FILE_OPERATION_OPEN, FILE_OPERATION_RENAME,
    FILE_PATH_LEN, FileDescriptorKey, FileKernelEvent, INBOUND_COUNTER_ATTRIBUTION_FAILED,
    INBOUND_COUNTER_CORRELATION_MISS, INBOUND_COUNTER_COUNT, INBOUND_COUNTER_DECODE_FAILED,
    INBOUND_COUNTER_KERNEL_LOST, INBOUND_COUNTER_UNSUPPORTED_FAMILY,
    INBOUND_PENDING_ACCEPT_CAPACITY, INBOUND_RING_BYTES, InboundEndpoints, InboundKernelEvent,
    InboundTransition, KernelEvent, NETWORK_ADDRESS_LEN, NETWORK_COUNTER_CAPACITY,
    NETWORK_COUNTER_CORRELATION_MISS, NETWORK_COUNTER_COUNT, NETWORK_COUNTER_DECODE_FAILED,
    NETWORK_COUNTER_KERNEL_LOST, NETWORK_COUNTER_UNSUPPORTED_FAMILY, PendingConnect,
    PendingFileOperation, TrackedFileDescriptor, classify_inbound_transition,
};
use aya_ebpf::{
    EbpfContext,
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_socket_cookie, bpf_ktime_get_ns, bpf_probe_read_kernel_buf, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes, bpf_skb_cgroup_id,
    },
    macros::{cgroup_skb, kretprobe, map, tracepoint},
    maps::{HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::{RetProbeContext, SkBuffContext, TracePointContext},
};

#[map]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static mut SYSCALL_ALLOWLIST: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);

#[map]
static mut PENDING_CONNECTS: HashMap<u64, PendingConnect> = HashMap::with_max_entries(4096, 0);

#[map]
static mut NETWORK_COUNTERS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(NETWORK_COUNTER_COUNT, 0);

#[map]
static mut INBOUND_EVENTS: RingBuf = RingBuf::with_byte_size(INBOUND_RING_BYTES, 0);

#[map]
static mut PENDING_ACCEPTS: LruHashMap<u64, InboundEndpoints> =
    LruHashMap::with_max_entries(INBOUND_PENDING_ACCEPT_CAPACITY, 0);

#[map]
static mut INBOUND_COUNTERS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(INBOUND_COUNTER_COUNT, 0);

#[map]
static mut DNS_EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

#[map]
static mut DNS_COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(DNS_COUNTER_COUNT, 0);

#[map]
static mut FILE_EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

#[map]
static mut PENDING_FILE_OPERATIONS: HashMap<u64, PendingFileOperation> =
    HashMap::with_max_entries(4096, 0);

#[map]
static mut TRACKED_FILE_DESCRIPTORS: LruHashMap<FileDescriptorKey, TrackedFileDescriptor> =
    LruHashMap::with_max_entries(16_384, 0);

#[map]
static mut FILE_OPERATION_SCRATCH: PerCpuArray<PendingFileOperation> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static mut FILE_DESCRIPTOR_SCRATCH: PerCpuArray<TrackedFileDescriptor> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static mut FILE_COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(FILE_COUNTER_COUNT, 0);

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const EINPROGRESS: i64 = 115;
const AF_INET_U32: u32 = 2;
const AF_INET6_U32: u32 = 10;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const DNS_PORT: u16 = 53;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_TRUNC: u64 = 0o1000;
const AT_REMOVEDIR: u64 = 0x200;
const RENAME_NOREPLACE: u64 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn {
    family: u16,
    port: [u8; 2],
    address: [u8; 4],
    zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn6 {
    family: u16,
    port: [u8; 2],
    flow_info: u32,
    address: [u8; 16],
    scope_id: u32,
}

#[tracepoint]
pub fn okoscope_exec(_ctx: TracePointContext) -> u32 {
    match emit(EVENT_KIND_EXEC, 0) {
        Ok(()) => 0,
        Err(error) => error,
    }
}

#[tracepoint]
pub fn okoscope_sys_enter(ctx: TracePointContext) -> u32 {
    match try_sys_enter(&ctx) {
        Ok(()) => 0,
        Err(error) => error,
    }
}

#[tracepoint]
pub fn okoscope_file_open_enter(ctx: TracePointContext) -> u32 {
    file_path_enter(&ctx, FILE_OPERATION_OPEN, 24, None, 32)
}

#[tracepoint]
pub fn okoscope_file_open_exit(ctx: TracePointContext) -> u32 {
    file_open_exit(&ctx)
}

#[tracepoint]
pub fn okoscope_file_write_enter(ctx: TracePointContext) -> u32 {
    file_fd_enter(&ctx, FILE_OPERATION_MODIFY)
}

#[tracepoint]
pub fn okoscope_file_write_exit(ctx: TracePointContext) -> u32 {
    file_operation_exit(&ctx, true)
}

#[tracepoint]
pub fn okoscope_file_truncate_enter(ctx: TracePointContext) -> u32 {
    file_path_enter(&ctx, FILE_OPERATION_MODIFY, 16, None, 0)
}

#[tracepoint]
pub fn okoscope_file_truncate_exit(ctx: TracePointContext) -> u32 {
    file_operation_exit(&ctx, false)
}

#[tracepoint]
pub fn okoscope_file_ftruncate_enter(ctx: TracePointContext) -> u32 {
    file_fd_enter(&ctx, FILE_OPERATION_MODIFY)
}

#[tracepoint]
pub fn okoscope_file_ftruncate_exit(ctx: TracePointContext) -> u32 {
    file_operation_exit(&ctx, false)
}

#[tracepoint]
pub fn okoscope_file_unlink_enter(ctx: TracePointContext) -> u32 {
    let flags: u64 = unsafe { ctx.read_at(32).unwrap_or(AT_REMOVEDIR) };
    if flags & AT_REMOVEDIR != 0 {
        return 0;
    }
    file_path_enter(&ctx, FILE_OPERATION_DELETE, 24, None, 0)
}

#[tracepoint]
pub fn okoscope_file_unlink_exit(ctx: TracePointContext) -> u32 {
    file_operation_exit(&ctx, false)
}

#[tracepoint]
pub fn okoscope_file_unlink_legacy_enter(ctx: TracePointContext) -> u32 {
    file_path_enter(&ctx, FILE_OPERATION_DELETE, 16, None, 0)
}

#[tracepoint]
pub fn okoscope_file_unlink_legacy_exit(ctx: TracePointContext) -> u32 {
    file_operation_exit(&ctx, false)
}

#[tracepoint]
pub fn okoscope_file_rename_enter(ctx: TracePointContext) -> u32 {
    file_path_enter(&ctx, FILE_OPERATION_RENAME, 24, Some(40), 48)
}

#[tracepoint]
pub fn okoscope_file_rename_exit(ctx: TracePointContext) -> u32 {
    file_operation_exit(&ctx, false)
}

#[tracepoint]
pub fn okoscope_file_rename_legacy_enter(ctx: TracePointContext) -> u32 {
    file_path_enter(&ctx, FILE_OPERATION_RENAME, 16, Some(24), 0)
}

#[tracepoint]
pub fn okoscope_file_rename_legacy_exit(ctx: TracePointContext) -> u32 {
    file_operation_exit(&ctx, false)
}

#[tracepoint]
pub fn okoscope_file_close_enter(ctx: TracePointContext) -> u32 {
    file_fd_enter(&ctx, FILE_OPERATION_CLOSE)
}

#[tracepoint]
pub fn okoscope_file_close_exit(ctx: TracePointContext) -> u32 {
    file_close_exit(&ctx)
}

#[tracepoint]
pub fn okoscope_connect_enter(ctx: TracePointContext) -> u32 {
    match try_connect_enter(&ctx) {
        Ok(()) => 0,
        Err(error) => error,
    }
}

#[tracepoint]
pub fn okoscope_connect_exit(ctx: TracePointContext) -> u32 {
    match try_connect_exit(&ctx) {
        Ok(()) => 0,
        Err(error) => error,
    }
}

#[tracepoint]
pub fn okoscope_inet_sock_set_state(ctx: TracePointContext) -> u32 {
    match try_inet_sock_set_state(&ctx) {
        Ok(()) => 0,
        Err(error) => error,
    }
}

#[kretprobe(function = "inet_csk_accept")]
pub fn okoscope_inet_csk_accept_return(ctx: RetProbeContext) -> u32 {
    match try_inet_csk_accept_return(&ctx) {
        Ok(()) => 0,
        Err(error) => error,
    }
}

#[cgroup_skb(egress)]
pub fn okoscope_dns_egress(ctx: SkBuffContext) -> i32 {
    let _ = capture_dns(&ctx, DNS_DIRECTION_EGRESS);
    1
}

#[cgroup_skb(ingress)]
pub fn okoscope_dns_ingress(ctx: SkBuffContext) -> i32 {
    let _ = capture_dns(&ctx, DNS_DIRECTION_INGRESS);
    1
}

fn capture_dns(ctx: &SkBuffContext, direction: u8) -> Result<(), ()> {
    let family = ctx.skb.family();
    let (address_family, protocol, transport_offset, resolver_address) = match family {
        AF_INET_U32 => parse_ipv4(ctx, direction)?,
        AF_INET6_U32 => parse_ipv6(ctx, direction)?,
        _ => return Ok(()),
    };
    let (transport, resolver_port, payload_offset, sequence, tcp_flags) =
        parse_transport(ctx, protocol, transport_offset, direction)?;
    if resolver_port != DNS_PORT {
        return Ok(());
    }
    let cgroup_id = unsafe { bpf_skb_cgroup_id(ctx.as_ptr().cast()) };
    if cgroup_id == 0 {
        increment_dns_counter(DNS_COUNTER_ATTRIBUTION_FAILED);
        return Ok(());
    }
    let packet_len = usize::try_from(ctx.len()).map_err(|_| ())?;
    let payload_len = packet_len.checked_sub(payload_offset).ok_or_else(|| {
        increment_dns_counter(DNS_COUNTER_DECODE_FAILED);
    })?;
    if payload_len == 0 {
        increment_dns_counter(DNS_COUNTER_DECODE_FAILED);
        return Ok(());
    }
    if payload_len > DNS_CAPTURE_BYTES {
        increment_dns_counter(DNS_COUNTER_OVERSIZE);
    }
    let Some(mut slot) = (unsafe { DNS_EVENTS.reserve::<DnsPacketRecord>(0) }) else {
        increment_dns_counter(DNS_COUNTER_RING_LOST);
        return Ok(());
    };
    let captured_len = payload_len.min(DNS_CAPTURE_BYTES);
    let record = unsafe { &mut *slot.as_mut_ptr() };
    record.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    record.cgroup_id = cgroup_id;
    record.socket_cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
    // Cgroup skb programs cannot call current-task helpers on all supported kernels.
    // Workload attribution therefore relies on the trusted cgroup id for both directions.
    record.pid_tgid = 0;
    record.sequence = sequence;
    record.payload_len = captured_len as u16;
    record.resolver_port = resolver_port;
    record.address_family = address_family;
    record.transport = transport;
    record.direction = direction;
    record.tcp_flags = tcp_flags;
    record.resolver_address = resolver_address;
    record.command = [0; 16];
    record.payload = [0; DNS_CAPTURE_BYTES];
    let mut index = 0;
    while index < DNS_CAPTURE_BYTES {
        if index >= captured_len {
            break;
        }
        let Ok(byte) = ctx.load::<u8>(payload_offset + index) else {
            increment_dns_counter(DNS_COUNTER_DECODE_FAILED);
            slot.discard(0);
            return Ok(());
        };
        record.payload[index] = byte;
        index += 1;
    }
    slot.submit(0);
    Ok(())
}

fn parse_ipv4(
    ctx: &SkBuffContext,
    direction: u8,
) -> Result<(u8, u8, usize, [u8; DNS_ADDRESS_LEN]), ()> {
    let version_ihl: u8 = ctx.load(0).map_err(|_| ())?;
    if version_ihl >> 4 != 4 {
        increment_dns_counter(DNS_COUNTER_DECODE_FAILED);
        return Err(());
    }
    let header_len = usize::from(version_ihl & 0x0f) * 4;
    if header_len < 20 {
        increment_dns_counter(DNS_COUNTER_DECODE_FAILED);
        return Err(());
    }
    let fragment: u16 = u16::from_be(ctx.load(6).map_err(|_| ())?);
    if fragment & 0x3fff != 0 {
        increment_dns_counter(DNS_COUNTER_UNSUPPORTED_FRAMING);
        return Err(());
    }
    let protocol: u8 = ctx.load(9).map_err(|_| ())?;
    let address_offset = if direction == DNS_DIRECTION_EGRESS {
        16
    } else {
        12
    };
    let address: [u8; 4] = ctx.load(address_offset).map_err(|_| ())?;
    let mut resolver = [0; DNS_ADDRESS_LEN];
    resolver[..4].copy_from_slice(&address);
    Ok((
        agent_ebpf_common::ADDRESS_FAMILY_IPV4,
        protocol,
        header_len,
        resolver,
    ))
}

fn parse_ipv6(
    ctx: &SkBuffContext,
    direction: u8,
) -> Result<(u8, u8, usize, [u8; DNS_ADDRESS_LEN]), ()> {
    let version: u8 = ctx.load(0).map_err(|_| ())?;
    if version >> 4 != 6 {
        increment_dns_counter(DNS_COUNTER_DECODE_FAILED);
        return Err(());
    }
    let protocol: u8 = ctx.load(6).map_err(|_| ())?;
    if protocol != IPPROTO_UDP && protocol != IPPROTO_TCP {
        increment_dns_counter(DNS_COUNTER_UNSUPPORTED_FRAMING);
        return Err(());
    }
    let address_offset = if direction == DNS_DIRECTION_EGRESS {
        24
    } else {
        8
    };
    let resolver: [u8; 16] = ctx.load(address_offset).map_err(|_| ())?;
    Ok((
        agent_ebpf_common::ADDRESS_FAMILY_IPV6,
        protocol,
        40,
        resolver,
    ))
}

fn parse_transport(
    ctx: &SkBuffContext,
    protocol: u8,
    offset: usize,
    direction: u8,
) -> Result<(u8, u16, usize, u32, u8), ()> {
    let source_port = u16::from_be(ctx.load(offset).map_err(|_| ())?);
    let destination_port = u16::from_be(ctx.load(offset + 2).map_err(|_| ())?);
    let resolver_port = if direction == DNS_DIRECTION_EGRESS {
        destination_port
    } else {
        source_port
    };
    match protocol {
        IPPROTO_UDP => {
            let length = usize::from(u16::from_be(ctx.load(offset + 4).map_err(|_| ())?));
            if length < 8 {
                increment_dns_counter(DNS_COUNTER_DECODE_FAILED);
                return Err(());
            }
            Ok((DNS_TRANSPORT_UDP, resolver_port, offset + 8, 0, 0))
        }
        IPPROTO_TCP => {
            let sequence = u32::from_be(ctx.load(offset + 4).map_err(|_| ())?);
            let data_offset: u8 = ctx.load(offset + 12).map_err(|_| ())?;
            let header_len = usize::from(data_offset >> 4) * 4;
            if header_len < 20 {
                increment_dns_counter(DNS_COUNTER_DECODE_FAILED);
                return Err(());
            }
            let flags: u8 = ctx.load(offset + 13).map_err(|_| ())?;
            Ok((
                DNS_TRANSPORT_TCP,
                resolver_port,
                offset + header_len,
                sequence,
                flags,
            ))
        }
        _ => Ok((0, resolver_port, offset, 0, 0)),
    }
}

fn try_sys_enter(ctx: &TracePointContext) -> Result<(), u32> {
    let syscall_id: u64 = unsafe { ctx.read_at(8).map_err(|_| 1_u32)? };
    let syscall_id = syscall_id as u32;
    if unsafe { SYSCALL_ALLOWLIST.get(&syscall_id) }.is_none() {
        return Ok(());
    }
    emit(EVENT_KIND_SYSCALL, syscall_id)
}

#[inline(always)]
fn file_path_enter(
    ctx: &TracePointContext,
    mut operation: u8,
    path_offset: usize,
    new_path_offset: Option<usize>,
    flags_offset: usize,
) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let Some(scratch_ptr) = (unsafe { FILE_OPERATION_SCRATCH.get_ptr_mut(0) }) else {
        increment_file_counter(FILE_COUNTER_CORRELATION_CAPACITY);
        return 0;
    };
    let scratch = unsafe { &mut *scratch_ptr };
    scratch.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    scratch.pid_tgid = pid_tgid;
    scratch.fd = -1;
    scratch.operation = operation;
    scratch.flags = FILE_FLAG_COMPLETE;
    scratch.path_len = 0;
    scratch.new_path_len = 0;
    scratch.command = bpf_get_current_comm().unwrap_or([0; 16]);
    let path_ptr: u64 = match unsafe { ctx.read_at(path_offset) } {
        Ok(value) => value,
        Err(_) => {
            increment_file_counter(FILE_COUNTER_PATH_READ_FAILED);
            return 0;
        }
    };
    let Ok(path) =
        (unsafe { bpf_probe_read_user_str_bytes(path_ptr as *const u8, &mut scratch.path) })
    else {
        increment_file_counter(FILE_COUNTER_PATH_READ_FAILED);
        return 0;
    };
    if path.is_empty() || path[0] != b'/' {
        increment_file_counter(FILE_COUNTER_PATH_RELATIVE);
        return 0;
    }
    if path.len() >= FILE_PATH_LEN {
        increment_file_counter(FILE_COUNTER_PATH_OVERSIZE);
        return 0;
    }
    scratch.path_len = path.len() as u16;
    if let Some(offset) = new_path_offset {
        let new_path_ptr: u64 = match unsafe { ctx.read_at(offset) } {
            Ok(value) => value,
            Err(_) => {
                increment_file_counter(FILE_COUNTER_PATH_READ_FAILED);
                return 0;
            }
        };
        let Ok(new_path) = (unsafe {
            bpf_probe_read_user_str_bytes(new_path_ptr as *const u8, &mut scratch.new_path)
        }) else {
            increment_file_counter(FILE_COUNTER_PATH_READ_FAILED);
            return 0;
        };
        if new_path.is_empty() || new_path[0] != b'/' {
            increment_file_counter(FILE_COUNTER_PATH_RELATIVE);
            return 0;
        }
        if new_path.len() >= FILE_PATH_LEN {
            increment_file_counter(FILE_COUNTER_PATH_OVERSIZE);
            return 0;
        }
        scratch.new_path_len = new_path.len() as u16;
    }
    if flags_offset != 0 {
        let flags: u64 = unsafe { ctx.read_at(flags_offset).unwrap_or(0) };
        if operation == FILE_OPERATION_OPEN && flags & (O_CREAT | O_EXCL) == (O_CREAT | O_EXCL) {
            operation = FILE_OPERATION_CREATE;
            scratch.operation = operation;
        } else if operation == FILE_OPERATION_OPEN && flags & O_TRUNC != 0 {
            operation = FILE_OPERATION_MODIFY;
            scratch.operation = operation;
        }
        if operation == FILE_OPERATION_RENAME && flags & RENAME_NOREPLACE != 0 {
            scratch.flags |= FILE_FLAG_REPLACEMENT_KNOWN;
        }
    }
    if unsafe { PENDING_FILE_OPERATIONS.insert(&pid_tgid, scratch, 0) }.is_err() {
        increment_file_counter(FILE_COUNTER_CORRELATION_CAPACITY);
    }
    0
}

#[inline(always)]
fn file_fd_enter(ctx: &TracePointContext, operation: u8) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let fd_raw: u64 = match unsafe { ctx.read_at(16) } {
        Ok(value) => value,
        Err(_) => return 0,
    };
    let fd = fd_raw as i32;
    let key = FileDescriptorKey {
        tgid: (pid_tgid >> 32) as u32,
        fd,
    };
    let Some(tracked_ptr) = (unsafe { TRACKED_FILE_DESCRIPTORS.get_ptr(&key) }) else {
        if operation == FILE_OPERATION_MODIFY {
            increment_file_counter(FILE_COUNTER_FD_MISS);
        }
        return 0;
    };
    let Some(scratch_ptr) = (unsafe { FILE_OPERATION_SCRATCH.get_ptr_mut(0) }) else {
        increment_file_counter(FILE_COUNTER_CORRELATION_CAPACITY);
        return 0;
    };
    let tracked = unsafe { &*tracked_ptr };
    let scratch = unsafe { &mut *scratch_ptr };
    scratch.cgroup_id = tracked.cgroup_id;
    scratch.pid_tgid = pid_tgid;
    scratch.fd = fd;
    scratch.operation = operation;
    scratch.flags = FILE_FLAG_COMPLETE;
    scratch.path_len = tracked.path_len;
    scratch.new_path_len = 0;
    scratch.command = tracked.command;
    if unsafe { bpf_probe_read_kernel_buf(tracked.path.as_ptr(), &mut scratch.path) }.is_err() {
        increment_file_counter(FILE_COUNTER_PATH_READ_FAILED);
        return 0;
    }
    if unsafe { PENDING_FILE_OPERATIONS.insert(&pid_tgid, scratch, 0) }.is_err() {
        increment_file_counter(FILE_COUNTER_CORRELATION_CAPACITY);
    }
    0
}

#[inline(always)]
fn file_open_exit(ctx: &TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let Some(pending_ptr) = (unsafe { PENDING_FILE_OPERATIONS.get_ptr(&pid_tgid) }) else {
        increment_file_counter(FILE_COUNTER_CORRELATION_MISS);
        return 0;
    };
    let pending = unsafe { &*pending_ptr };
    let result: i64 = unsafe { ctx.read_at(16).unwrap_or(-1) };
    if result < 0 || result > i64::from(i32::MAX) {
        let _ = unsafe { PENDING_FILE_OPERATIONS.remove(&pid_tgid) };
        return 0;
    }
    let fd = result as i32;
    let Some(descriptor_ptr) = (unsafe { FILE_DESCRIPTOR_SCRATCH.get_ptr_mut(0) }) else {
        increment_file_counter(FILE_COUNTER_CORRELATION_CAPACITY);
        return 0;
    };
    let descriptor = unsafe { &mut *descriptor_ptr };
    descriptor.cgroup_id = pending.cgroup_id;
    descriptor.pid_tgid = pending.pid_tgid;
    descriptor.generation = unsafe { bpf_ktime_get_ns() };
    descriptor.path_len = pending.path_len;
    descriptor.command = pending.command;
    if unsafe { bpf_probe_read_kernel_buf(pending.path.as_ptr(), &mut descriptor.path) }.is_err() {
        increment_file_counter(FILE_COUNTER_PATH_READ_FAILED);
        let _ = unsafe { PENDING_FILE_OPERATIONS.remove(&pid_tgid) };
        return 0;
    }
    let key = FileDescriptorKey {
        tgid: (pending.pid_tgid >> 32) as u32,
        fd,
    };
    if unsafe { TRACKED_FILE_DESCRIPTORS.insert(&key, descriptor, 0) }.is_err() {
        increment_file_counter(FILE_COUNTER_CORRELATION_CAPACITY);
        let _ = unsafe { PENDING_FILE_OPERATIONS.remove(&pid_tgid) };
        return 0;
    }
    if pending.operation == FILE_OPERATION_CREATE || pending.operation == FILE_OPERATION_MODIFY {
        emit_file(pending, descriptor.generation, fd, 0);
    }
    let _ = unsafe { PENDING_FILE_OPERATIONS.remove(&pid_tgid) };
    0
}

#[inline(always)]
fn file_operation_exit(ctx: &TracePointContext, positive_result: bool) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let Some(pending_ptr) = (unsafe { PENDING_FILE_OPERATIONS.get_ptr(&pid_tgid) }) else {
        increment_file_counter(FILE_COUNTER_CORRELATION_MISS);
        return 0;
    };
    let pending = unsafe { &*pending_ptr };
    let result: i64 = unsafe { ctx.read_at(16).unwrap_or(-1) };
    if (positive_result && result <= 0) || (!positive_result && result != 0) {
        let _ = unsafe { PENDING_FILE_OPERATIONS.remove(&pid_tgid) };
        return 0;
    }
    let generation = if pending.fd >= 0 {
        let key = FileDescriptorKey {
            tgid: (pending.pid_tgid >> 32) as u32,
            fd: pending.fd,
        };
        unsafe { TRACKED_FILE_DESCRIPTORS.get(&key) }.map_or(0, |tracked| tracked.generation)
    } else {
        0
    };
    emit_file(pending, generation, pending.fd, result as i32);
    let _ = unsafe { PENDING_FILE_OPERATIONS.remove(&pid_tgid) };
    0
}

#[inline(always)]
fn file_close_exit(ctx: &TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let Some(pending_ptr) = (unsafe { PENDING_FILE_OPERATIONS.get_ptr(&pid_tgid) }) else {
        return 0;
    };
    let pending = unsafe { &*pending_ptr };
    let result: i64 = unsafe { ctx.read_at(16).unwrap_or(-1) };
    if result == 0 {
        let key = FileDescriptorKey {
            tgid: (pending.pid_tgid >> 32) as u32,
            fd: pending.fd,
        };
        let _ = unsafe { TRACKED_FILE_DESCRIPTORS.remove(&key) };
    }
    let _ = unsafe { PENDING_FILE_OPERATIONS.remove(&pid_tgid) };
    0
}

#[inline(always)]
fn emit_file(pending: &PendingFileOperation, generation: u64, fd: i32, result: i32) {
    let Some(mut slot) = (unsafe { FILE_EVENTS.reserve::<FileKernelEvent>(0) }) else {
        increment_file_counter(FILE_COUNTER_KERNEL_LOST);
        return;
    };
    let record = unsafe { &mut *slot.as_mut_ptr() };
    record.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    record.cgroup_id = pending.cgroup_id;
    record.pid_tgid = pending.pid_tgid;
    record.descriptor_generation = generation;
    record.fd = fd;
    record.result = result;
    record.path_len = pending.path_len;
    record.new_path_len = pending.new_path_len;
    record.operation = pending.operation;
    record.flags = pending.flags;
    record.padding = [0; 2];
    record.command = pending.command;
    if unsafe { bpf_probe_read_kernel_buf(pending.path.as_ptr(), &mut record.path) }.is_err()
        || unsafe { bpf_probe_read_kernel_buf(pending.new_path.as_ptr(), &mut record.new_path) }
            .is_err()
    {
        increment_file_counter(FILE_COUNTER_PATH_READ_FAILED);
        slot.discard(0);
        return;
    }
    slot.submit(0);
}

fn emit(event_kind: u8, syscall_id: u32) -> Result<(), u32> {
    let Some(mut slot) = (unsafe { EVENTS.reserve::<KernelEvent>(0) }) else {
        return Err(2);
    };
    let command = bpf_get_current_comm().unwrap_or([0; 16]);
    slot.write(KernelEvent {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        pid_tgid: bpf_get_current_pid_tgid(),
        syscall_id,
        connect_result: 0,
        event_kind,
        address_family: 0,
        connect_outcome: 0,
        padding: 0,
        destination_port: 0,
        errno: 0,
        destination_address: [0; NETWORK_ADDRESS_LEN],
        command,
    });
    slot.submit(0);
    Ok(())
}

fn try_connect_enter(ctx: &TracePointContext) -> Result<(), u32> {
    let address_ptr: u64 = unsafe { ctx.read_at(24).map_err(|_| 1_u32)? };
    let address_len: u64 = unsafe { ctx.read_at(32).map_err(|_| 1_u32)? };
    if address_ptr == 0 {
        increment_counter(NETWORK_COUNTER_DECODE_FAILED);
        return Ok(());
    }
    let family = unsafe { bpf_probe_read_user(address_ptr as *const u16) };
    let Ok(family) = family else {
        increment_counter(NETWORK_COUNTER_DECODE_FAILED);
        return Ok(());
    };
    let mut destination_address = [0_u8; NETWORK_ADDRESS_LEN];
    let (address_family, destination_port) = match family {
        AF_INET if address_len >= core::mem::size_of::<SockAddrIn>() as u64 => {
            let Ok(address) = (unsafe { bpf_probe_read_user(address_ptr as *const SockAddrIn) })
            else {
                increment_counter(NETWORK_COUNTER_DECODE_FAILED);
                return Ok(());
            };
            destination_address[..4].copy_from_slice(&address.address);
            (ADDRESS_FAMILY_IPV4, u16::from_be_bytes(address.port))
        }
        AF_INET6 if address_len >= core::mem::size_of::<SockAddrIn6>() as u64 => {
            let Ok(address) = (unsafe { bpf_probe_read_user(address_ptr as *const SockAddrIn6) })
            else {
                increment_counter(NETWORK_COUNTER_DECODE_FAILED);
                return Ok(());
            };
            destination_address.copy_from_slice(&address.address);
            (ADDRESS_FAMILY_IPV6, u16::from_be_bytes(address.port))
        }
        AF_INET | AF_INET6 => {
            increment_counter(NETWORK_COUNTER_DECODE_FAILED);
            return Ok(());
        }
        _ => {
            increment_counter(NETWORK_COUNTER_UNSUPPORTED_FAMILY);
            return Ok(());
        }
    };
    if destination_port == 0 {
        increment_counter(NETWORK_COUNTER_DECODE_FAILED);
        return Ok(());
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let pending = PendingConnect {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        pid_tgid,
        destination_address,
        destination_port,
        address_family,
        padding: [0; 5],
        command: bpf_get_current_comm().unwrap_or([0; 16]),
    };
    if unsafe { PENDING_CONNECTS.insert(&pid_tgid, &pending, 0) }.is_err() {
        increment_counter(NETWORK_COUNTER_CAPACITY);
    }
    Ok(())
}

fn try_connect_exit(ctx: &TracePointContext) -> Result<(), u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let Some(pending_ptr) = (unsafe { PENDING_CONNECTS.get_ptr(&pid_tgid) }) else {
        increment_counter(NETWORK_COUNTER_CORRELATION_MISS);
        return Ok(());
    };
    let pending = unsafe { *pending_ptr };
    let _ = unsafe { PENDING_CONNECTS.remove(&pid_tgid) };
    let result: i64 = unsafe { ctx.read_at(16).map_err(|_| 1_u32)? };
    let (connect_outcome, errno) = if result == 0 {
        (CONNECT_OUTCOME_SUCCEEDED, 0)
    } else if result == -EINPROGRESS {
        (CONNECT_OUTCOME_IN_PROGRESS, EINPROGRESS as u16)
    } else if (-4095..0).contains(&result) {
        (CONNECT_OUTCOME_FAILED, (-result) as u16)
    } else {
        increment_counter(NETWORK_COUNTER_DECODE_FAILED);
        return Ok(());
    };
    let Some(mut slot) = (unsafe { EVENTS.reserve::<KernelEvent>(0) }) else {
        increment_counter(NETWORK_COUNTER_KERNEL_LOST);
        return Ok(());
    };
    slot.write(KernelEvent {
        timestamp_ns: pending.timestamp_ns,
        cgroup_id: pending.cgroup_id,
        pid_tgid: pending.pid_tgid,
        syscall_id: 0,
        connect_result: result as i32,
        event_kind: EVENT_KIND_NETWORK_CONNECT,
        address_family: pending.address_family,
        connect_outcome,
        padding: 0,
        destination_port: pending.destination_port,
        errno,
        destination_address: pending.destination_address,
        command: pending.command,
    });
    slot.submit(0);
    Ok(())
}

fn try_inet_sock_set_state(ctx: &TracePointContext) -> Result<(), u32> {
    let skaddr: u64 = unsafe { ctx.read_at(8).map_err(|_| 1_u32)? };
    let old_state: i32 = unsafe { ctx.read_at(16).map_err(|_| 1_u32)? };
    let new_state: i32 = unsafe { ctx.read_at(20).map_err(|_| 1_u32)? };
    let local_port: u16 = unsafe { ctx.read_at(24).map_err(|_| 1_u32)? };
    let remote_port: u16 = unsafe { ctx.read_at(26).map_err(|_| 1_u32)? };
    let family: u16 = unsafe { ctx.read_at(28).map_err(|_| 1_u32)? };
    let protocol: u16 = unsafe { ctx.read_at(30).map_err(|_| 1_u32)? };
    let transition = classify_inbound_transition(
        protocol,
        skaddr,
        old_state,
        new_state,
        local_port,
        remote_port,
    );
    if transition == InboundTransition::Ignore {
        return Ok(());
    }
    if transition == InboundTransition::Invalid {
        increment_inbound_counter(INBOUND_COUNTER_DECODE_FAILED);
        return Ok(());
    }
    let (address_family, local_address, remote_address) = match family {
        AF_INET => {
            let local: [u8; 4] = unsafe { ctx.read_at(32).map_err(|_| 1_u32)? };
            let remote: [u8; 4] = unsafe { ctx.read_at(36).map_err(|_| 1_u32)? };
            let mut local_address = [0; NETWORK_ADDRESS_LEN];
            let mut remote_address = [0; NETWORK_ADDRESS_LEN];
            local_address[..4].copy_from_slice(&local);
            remote_address[..4].copy_from_slice(&remote);
            (ADDRESS_FAMILY_IPV4, local_address, remote_address)
        }
        AF_INET6 => {
            let local: [u8; 16] = unsafe { ctx.read_at(40).map_err(|_| 1_u32)? };
            let remote: [u8; 16] = unsafe { ctx.read_at(56).map_err(|_| 1_u32)? };
            (ADDRESS_FAMILY_IPV6, local, remote)
        }
        _ => {
            increment_inbound_counter(INBOUND_COUNTER_UNSUPPORTED_FAMILY);
            return Ok(());
        }
    };
    let endpoints = InboundEndpoints {
        observed_at_ns: unsafe { bpf_ktime_get_ns() },
        local_address,
        remote_address,
        local_port,
        remote_port,
        address_family,
        padding: [0; 3],
    };
    if transition == InboundTransition::Listen {
        return emit_inbound(EVENT_KIND_NETWORK_LISTEN, &endpoints);
    }
    if transition == InboundTransition::PendingAccept {
        let _ = unsafe { PENDING_ACCEPTS.insert(&skaddr, &endpoints, 0) };
    }
    Ok(())
}

fn try_inet_csk_accept_return(ctx: &RetProbeContext) -> Result<(), u32> {
    let Some(skaddr) = ctx.ret::<u64>() else {
        increment_inbound_counter(INBOUND_COUNTER_DECODE_FAILED);
        return Ok(());
    };
    if skaddr == 0 {
        return Ok(());
    }
    let Some(endpoints_ptr) = (unsafe { PENDING_ACCEPTS.get_ptr(&skaddr) }) else {
        increment_inbound_counter(INBOUND_COUNTER_CORRELATION_MISS);
        return Ok(());
    };
    let mut endpoints = unsafe { *endpoints_ptr };
    let _ = unsafe { PENDING_ACCEPTS.remove(&skaddr) };
    endpoints.observed_at_ns = unsafe { bpf_ktime_get_ns() };
    emit_inbound(EVENT_KIND_NETWORK_ACCEPT, &endpoints)
}

fn emit_inbound(event_kind: u8, endpoints: &InboundEndpoints) -> Result<(), u32> {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    if cgroup_id == 0 {
        increment_inbound_counter(INBOUND_COUNTER_ATTRIBUTION_FAILED);
        return Ok(());
    }
    let Some(mut slot) = (unsafe { INBOUND_EVENTS.reserve::<InboundKernelEvent>(0) }) else {
        increment_inbound_counter(INBOUND_COUNTER_KERNEL_LOST);
        return Ok(());
    };
    slot.write(InboundKernelEvent {
        timestamp_ns: endpoints.observed_at_ns,
        cgroup_id,
        pid_tgid: bpf_get_current_pid_tgid(),
        local_address: endpoints.local_address,
        remote_address: endpoints.remote_address,
        local_port: endpoints.local_port,
        remote_port: endpoints.remote_port,
        event_kind,
        address_family: endpoints.address_family,
        padding: [0; 2],
        command: bpf_get_current_comm().unwrap_or([0; 16]),
    });
    slot.submit(0);
    Ok(())
}

fn increment_counter(index: u32) {
    if let Some(value) = unsafe { NETWORK_COUNTERS.get_ptr_mut(index) } {
        unsafe {
            *value = (*value).saturating_add(1);
        }
    }
}

fn increment_inbound_counter(index: u32) {
    if let Some(value) = unsafe { INBOUND_COUNTERS.get_ptr_mut(index) } {
        unsafe {
            *value = (*value).saturating_add(1);
        }
    }
}

fn increment_dns_counter(index: u32) {
    if let Some(value) = unsafe { DNS_COUNTERS.get_ptr_mut(index) } {
        unsafe {
            *value = (*value).saturating_add(1);
        }
    }
}

#[inline(always)]
fn increment_file_counter(index: u32) {
    if let Some(value) = unsafe { FILE_COUNTERS.get_ptr_mut(index) } {
        unsafe {
            *value = (*value).saturating_add(1);
        }
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
