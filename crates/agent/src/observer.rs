use std::{fs::File, path::Path};

use anyhow::{Context, Result};
use aya::{
    Ebpf, EbpfLoader,
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, KProbe, TracePoint},
};

use crate::{
    counters::{
        DnsKernelCounters, ExitKernelCounters, FileKernelCounters, InboundKernelCounters,
        NetworkKernelCounters,
    },
    kernel_event,
    syscall::Architecture,
};

pub struct Observer {
    _ebpf: Ebpf,
    events: RingBuf<aya::maps::MapData>,
    network_counters: PerCpuArray<aya::maps::MapData, u64>,
    inbound_events: RingBuf<aya::maps::MapData>,
    inbound_counters: PerCpuArray<aya::maps::MapData, u64>,
    dns_events: RingBuf<aya::maps::MapData>,
    dns_counters: PerCpuArray<aya::maps::MapData, u64>,
    file_events: RingBuf<aya::maps::MapData>,
    file_counters: PerCpuArray<aya::maps::MapData, u64>,
    exit: Option<ExitObserver>,
}

struct ExitObserver {
    _ebpf: Ebpf,
    events: RingBuf<aya::maps::MapData>,
    counters: PerCpuArray<aya::maps::MapData, u64>,
}

#[derive(Clone, Copy, Debug)]
pub struct ObservationPrograms {
    pub network_connect: ProgramState,
    pub network_listen: ProgramState,
    pub network_accept: ProgramState,
    pub dns: ProgramState,
    pub files: ProgramState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProgramState {
    Disabled,
    Enabled,
}

impl From<bool> for ProgramState {
    fn from(enabled: bool) -> Self {
        if enabled {
            Self::Enabled
        } else {
            Self::Disabled
        }
    }
}

impl ProgramState {
    const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

impl core::fmt::Debug for Observer {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("Observer").finish_non_exhaustive()
    }
}

fn attach_configured_programs(ebpf: &mut Ebpf, programs: ObservationPrograms) -> Result<()> {
    attach(ebpf, "okoscope_exec", "sched", "sched_process_exec")?;
    attach(ebpf, "okoscope_sys_enter", "raw_syscalls", "sys_enter")?;
    if programs.network_connect.is_enabled() {
        attach(
            ebpf,
            "okoscope_connect_enter",
            "syscalls",
            "sys_enter_connect",
        )?;
        attach(
            ebpf,
            "okoscope_connect_exit",
            "syscalls",
            "sys_exit_connect",
        )?;
    }
    let (state_hook, accept_hook) = inbound_hook_requirements(programs);
    if state_hook {
        attach(
            ebpf,
            "okoscope_inet_sock_set_state",
            "sock",
            "inet_sock_set_state",
        )?;
    }
    if accept_hook {
        attach_kretprobe(ebpf, "okoscope_inet_csk_accept_return", "inet_csk_accept")?;
    }
    if programs.dns.is_enabled() {
        let cgroup = File::open("/sys/fs/cgroup/kubepods")
            .or_else(|_| File::open("/sys/fs/cgroup/kubepods.slice"))
            .context("open Kubernetes cgroup v2 subtree for DNS observation")?;
        attach_cgroup(
            ebpf,
            "okoscope_dns_egress",
            &cgroup,
            CgroupSkbAttachType::Egress,
        )?;
        attach_cgroup(
            ebpf,
            "okoscope_dns_ingress",
            &cgroup,
            CgroupSkbAttachType::Ingress,
        )?;
    }
    if programs.files.is_enabled() {
        for (program, event) in [
            ("okoscope_file_open_enter", "sys_enter_openat"),
            ("okoscope_file_open_exit", "sys_exit_openat"),
            ("okoscope_file_write_enter", "sys_enter_write"),
            ("okoscope_file_write_exit", "sys_exit_write"),
            ("okoscope_file_truncate_enter", "sys_enter_truncate"),
            ("okoscope_file_truncate_exit", "sys_exit_truncate"),
            ("okoscope_file_ftruncate_enter", "sys_enter_ftruncate"),
            ("okoscope_file_ftruncate_exit", "sys_exit_ftruncate"),
            ("okoscope_file_unlink_enter", "sys_enter_unlinkat"),
            ("okoscope_file_unlink_exit", "sys_exit_unlinkat"),
            ("okoscope_file_unlink_legacy_enter", "sys_enter_unlink"),
            ("okoscope_file_unlink_legacy_exit", "sys_exit_unlink"),
            ("okoscope_file_rename_enter", "sys_enter_renameat2"),
            ("okoscope_file_rename_exit", "sys_exit_renameat2"),
            ("okoscope_file_rename_legacy_enter", "sys_enter_rename"),
            ("okoscope_file_rename_legacy_exit", "sys_exit_rename"),
            ("okoscope_file_close_enter", "sys_enter_close"),
            ("okoscope_file_close_exit", "sys_exit_close"),
        ] {
            attach(ebpf, program, "syscalls", event)?;
        }
    }
    Ok(())
}

const fn inbound_hook_requirements(programs: ObservationPrograms) -> (bool, bool) {
    (
        programs.network_listen.is_enabled() || programs.network_accept.is_enabled(),
        programs.network_accept.is_enabled(),
    )
}

impl Observer {
    pub fn load(
        path: &Path,
        syscall_names: &[String],
        programs: ObservationPrograms,
        architecture: Architecture,
    ) -> Result<Self> {
        let mut ebpf = EbpfLoader::new()
            .load_file(path)
            .context("load eBPF object")?;
        attach_configured_programs(&mut ebpf, programs)?;
        {
            let map = ebpf
                .map_mut("SYSCALL_ALLOWLIST")
                .context("missing SYSCALL_ALLOWLIST map")?;
            let mut allowlist: HashMap<_, u32, u8> = HashMap::try_from(map)?;
            for name in syscall_names {
                let number = crate::syscall::resolve(name, architecture)?;
                allowlist.insert(number, 1, 0)?;
            }
        }
        let map = ebpf
            .take_map("EVENTS")
            .context("missing EVENTS ring buffer")?;
        let events = RingBuf::try_from(map)?;
        let map = ebpf
            .take_map("NETWORK_COUNTERS")
            .context("missing NETWORK_COUNTERS map")?;
        let network_counters = PerCpuArray::try_from(map)?;
        let map = ebpf
            .take_map("INBOUND_EVENTS")
            .context("missing INBOUND_EVENTS ring buffer")?;
        let inbound_events = RingBuf::try_from(map)?;
        let map = ebpf
            .take_map("INBOUND_COUNTERS")
            .context("missing INBOUND_COUNTERS map")?;
        let inbound_counters = PerCpuArray::try_from(map)?;
        let map = ebpf
            .take_map("DNS_EVENTS")
            .context("missing DNS_EVENTS ring buffer")?;
        let dns_events = RingBuf::try_from(map)?;
        let map = ebpf
            .take_map("DNS_COUNTERS")
            .context("missing DNS_COUNTERS map")?;
        let dns_counters = PerCpuArray::try_from(map)?;
        let map = ebpf
            .take_map("FILE_EVENTS")
            .context("missing FILE_EVENTS ring buffer")?;
        let file_events = RingBuf::try_from(map)?;
        let map = ebpf
            .take_map("FILE_COUNTERS")
            .context("missing FILE_COUNTERS map")?;
        let file_counters = PerCpuArray::try_from(map)?;
        Ok(Self {
            _ebpf: ebpf,
            events,
            network_counters,
            inbound_events,
            inbound_counters,
            dns_events,
            dns_counters,
            file_events,
            file_counters,
            exit: None,
        })
    }

    pub fn enable_process_exit(&mut self, path: &Path) -> Result<()> {
        let mut ebpf = EbpfLoader::new()
            .load_file(path)
            .context("load process-exit C CO-RE object")?;
        attach(
            &mut ebpf,
            "okoscope_process_exit",
            "sched",
            "sched_process_exit",
        )?;
        let events = RingBuf::try_from(
            ebpf.take_map("EXIT_EVENTS")
                .context("missing EXIT_EVENTS ring buffer")?,
        )?;
        let counters = PerCpuArray::try_from(
            ebpf.take_map("EXIT_COUNTERS")
                .context("missing EXIT_COUNTERS map")?,
        )?;
        self.exit = Some(ExitObserver {
            _ebpf: ebpf,
            events,
            counters,
        });
        Ok(())
    }

    #[must_use]
    pub fn process_exit_enabled(&self) -> bool {
        self.exit.is_some()
    }

    pub fn next_exit_event(
        &mut self,
    ) -> Option<Result<kernel_event::DecodedExitEvent, kernel_event::ExitDecodeError>> {
        self.exit
            .as_mut()
            .and_then(|exit| exit.events.next())
            .map(|item| kernel_event::decode_exit(&item))
    }

    pub fn exit_kernel_counters(&self) -> Result<ExitKernelCounters> {
        let Some(exit) = &self.exit else {
            return Ok(ExitKernelCounters::default());
        };
        let ring_lost = exit
            .counters
            .get(&agent_ebpf_common::EXIT_COUNTER_RING_LOST, 0)?
            .iter()
            .copied()
            .sum();
        Ok(ExitKernelCounters { ring_lost })
    }

    pub fn next_file_event(
        &mut self,
    ) -> Option<Result<kernel_event::DecodedFileEvent, kernel_event::FileDecodeError>> {
        self.file_events
            .next()
            .map(|item| kernel_event::decode_file(&item))
    }

    pub fn file_kernel_counters(&self) -> Result<FileKernelCounters> {
        let total = |index: u32| -> Result<u64> {
            Ok(self.file_counters.get(&index, 0)?.iter().copied().sum())
        };
        Ok(FileKernelCounters {
            correlation_capacity: total(agent_ebpf_common::FILE_COUNTER_CORRELATION_CAPACITY)?,
            correlation_miss: total(agent_ebpf_common::FILE_COUNTER_CORRELATION_MISS)?,
            path_read_failed: total(agent_ebpf_common::FILE_COUNTER_PATH_READ_FAILED)?,
            path_relative: total(agent_ebpf_common::FILE_COUNTER_PATH_RELATIVE)?,
            path_invalid: total(agent_ebpf_common::FILE_COUNTER_PATH_INVALID)?,
            path_oversize: total(agent_ebpf_common::FILE_COUNTER_PATH_OVERSIZE)?,
            fd_miss: total(agent_ebpf_common::FILE_COUNTER_FD_MISS)?,
            filtered: total(agent_ebpf_common::FILE_COUNTER_FILTERED)?,
            kernel_lost: total(agent_ebpf_common::FILE_COUNTER_KERNEL_LOST)?,
        })
    }

    pub fn next_dns_packet(&mut self) -> Result<Option<agent_ebpf_common::DnsPacketRecord>> {
        self.dns_events
            .next()
            .map(|item| kernel_event::decode_dns_packet(&item).map_err(Into::into))
            .transpose()
    }

    pub fn next_inbound_event(&mut self) -> Result<Option<agent_ebpf_common::InboundKernelEvent>> {
        self.inbound_events
            .next()
            .map(|item| kernel_event::decode_inbound(&item).map_err(Into::into))
            .transpose()
    }

    pub fn inbound_kernel_counters(&self) -> Result<InboundKernelCounters> {
        let total = |index: u32| -> Result<u64> {
            Ok(self.inbound_counters.get(&index, 0)?.iter().copied().sum())
        };
        Ok(InboundKernelCounters {
            decode_failed: total(agent_ebpf_common::INBOUND_COUNTER_DECODE_FAILED)?,
            attribution_failed: total(agent_ebpf_common::INBOUND_COUNTER_ATTRIBUTION_FAILED)?,
            unsupported_family: total(agent_ebpf_common::INBOUND_COUNTER_UNSUPPORTED_FAMILY)?,
            kernel_lost: total(agent_ebpf_common::INBOUND_COUNTER_KERNEL_LOST)?,
            correlation_miss: total(agent_ebpf_common::INBOUND_COUNTER_CORRELATION_MISS)?,
        })
    }

    pub fn dns_kernel_counters(&self) -> Result<DnsKernelCounters> {
        let total = |index: u32| -> Result<u64> {
            Ok(self.dns_counters.get(&index, 0)?.iter().copied().sum())
        };
        Ok(DnsKernelCounters {
            unsupported_framing: total(agent_ebpf_common::DNS_COUNTER_UNSUPPORTED_FRAMING)?,
            attribution_failed: total(agent_ebpf_common::DNS_COUNTER_ATTRIBUTION_FAILED)?,
            decode_failed: total(agent_ebpf_common::DNS_COUNTER_DECODE_FAILED)?,
            oversize: total(agent_ebpf_common::DNS_COUNTER_OVERSIZE)?,
            ring_lost: total(agent_ebpf_common::DNS_COUNTER_RING_LOST)?,
        })
    }

    pub fn next_event(&mut self) -> Result<Option<agent_ebpf_common::KernelEvent>> {
        self.events
            .next()
            .map(|item| kernel_event::decode(&item).map_err(Into::into))
            .transpose()
    }

    pub fn network_counters(&self) -> Result<NetworkKernelCounters> {
        let total = |index: u32| -> Result<u64> {
            Ok(self.network_counters.get(&index, 0)?.iter().copied().sum())
        };
        Ok(NetworkKernelCounters {
            correlation_capacity: total(agent_ebpf_common::NETWORK_COUNTER_CAPACITY)?,
            correlation_miss: total(agent_ebpf_common::NETWORK_COUNTER_CORRELATION_MISS)?,
            decode_failed: total(agent_ebpf_common::NETWORK_COUNTER_DECODE_FAILED)?,
            unsupported_family: total(agent_ebpf_common::NETWORK_COUNTER_UNSUPPORTED_FAMILY)?,
            kernel_lost: total(agent_ebpf_common::NETWORK_COUNTER_KERNEL_LOST)?,
        })
    }
}

fn attach_cgroup(
    ebpf: &mut Ebpf,
    program_name: &str,
    cgroup: &File,
    attach_type: CgroupSkbAttachType,
) -> Result<()> {
    let program: &mut CgroupSkb = ebpf
        .program_mut(program_name)
        .with_context(|| format!("missing {program_name} program"))?
        .try_into()?;
    program
        .load()
        .with_context(|| format!("load {program_name}"))?;
    program
        .attach(cgroup, attach_type, CgroupAttachMode::Single)
        .with_context(|| format!("attach {program_name} to cgroup v2 root"))?;
    Ok(())
}

fn attach(ebpf: &mut Ebpf, program_name: &str, category: &str, event: &str) -> Result<()> {
    let program: &mut TracePoint = ebpf
        .program_mut(program_name)
        .with_context(|| format!("missing {program_name} program"))?
        .try_into()?;
    program
        .load()
        .with_context(|| format!("load {program_name}"))?;
    program
        .attach(category, event)
        .with_context(|| format!("attach {program_name} to {category}/{event}"))?;
    Ok(())
}

fn attach_kretprobe(ebpf: &mut Ebpf, program_name: &str, function: &str) -> Result<()> {
    let program: &mut KProbe = ebpf
        .program_mut(program_name)
        .with_context(|| format!("missing {program_name} program"))?
        .try_into()?;
    program
        .load()
        .with_context(|| format!("load {program_name}"))?;
    program
        .attach(function, 0)
        .with_context(|| format!("attach {program_name} to {function}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn programs(listen: bool, accept: bool) -> ObservationPrograms {
        ObservationPrograms {
            network_connect: ProgramState::Disabled,
            network_listen: listen.into(),
            network_accept: accept.into(),
            dns: ProgramState::Disabled,
            files: ProgramState::Disabled,
        }
    }

    #[test]
    fn inbound_hooks_are_independently_required() {
        assert_eq!(
            inbound_hook_requirements(programs(false, false)),
            (false, false)
        );
        assert_eq!(
            inbound_hook_requirements(programs(true, false)),
            (true, false)
        );
        assert_eq!(
            inbound_hook_requirements(programs(false, true)),
            (true, true)
        );
        assert_eq!(
            inbound_hook_requirements(programs(true, true)),
            (true, true)
        );
    }
}
