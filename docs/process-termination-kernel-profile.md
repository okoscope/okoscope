# Process termination kernel profile

This document records the pre-ABI kernel feasibility inventory and the bounded
C CO-RE verifier spike for `process.exit/v1`. It does not claim that the
capability is ready: production integration and the remaining correlation
fixtures are still required before the agent may advertise it.

## Supported and reference baseline

The documented production support floor remains Linux 6.1 LTS or newer with
BTF, tracefs, cgroup v2, and the agent's existing eBPF capabilities. The live
`aliens` reference cluster was inspected on 2026-08-23 after selecting the
required `aliens` Kubernetes context:

| Node | Kernel | Architecture | OS | Runtime | BTF | `sched_process_exit` |
|---|---|---|---|---|---|---|
| `worker-192.168.0.7` | `5.15.0-138-generic` | amd64 | Ubuntu 22.04.5 LTS | containerd 1.7.30 | present | present |
| `worker-192.168.0.8` | `5.15.0-139-generic` | amd64 | Ubuntu 22.04.5 LTS | containerd 1.7.30 | present | present |
| `worker-192.168.0.9` | `6.8.0-137-generic` | amd64 | Ubuntu 24.04.4 LTS | containerd 1.7.30 | present | present |

The two 5.15 nodes are reference compatibility evidence, not an expansion of
the supported production floor.

The production C companion object from
`crates/agent-ebpf-core/process_exit.bpf.c` was built once and verifier-loaded
unchanged with `bpftool prog loadall ... type tracepoint` on all three nodes on
2026-08-23. Every load succeeded. The temporary program pins and copied object
were removed immediately after verification.

## Tracepoint ABI inventory

All three nodes expose the same meaningful
`/sys/kernel/tracing/events/sched/sched_process_exit/format` fields:

| Field | Offset | Size | Notes |
|---|---:|---:|---|
| `common_pid` | 4 | 4 | tracepoint common field |
| `comm[16]` | 8 | 16 | signedness metadata differs between 5.15 and 6.8; bytes are equivalent |
| `pid` | 24 | 4 | exiting task PID |
| `prio` | 28 | 4 | scheduler priority |

The tracepoint ABI does **not** expose `exit_code`, a terminating signal, or a
core-dump bit. None of those semantics may be inferred from `pid`, `prio`, or
the process command.

## Required status access

The selected implementation obtains the current task with
`bpf_get_current_task_btf()` and performs a verifier-safe BTF/CO-RE read of the
`task_struct.exit_code` field at `sched_process_exit`. The C companion declares
only that field with `preserve_access_index`; the resulting object contains a
`BPF_CORE_FIELD_BYTE_OFFSET` relocation rather than a target-kernel offset.

The spike must prove all of the following on the supported 6.1+ build matrix and
the three live reference kernels:

- the selected task field is populated at the tracepoint and retains Linux wait
  status semantics for normal exit, signal termination, and the core bit;
- CO-RE relocation succeeds without hard-coded `task_struct` offsets;
- `bpf_get_current_pid_tgid()`, `bpf_get_current_cgroup_id()`, command capture,
  and the selected status read describe the same exiting task;
- verifier rejection, missing BTF/type/field, or fixture mismatch prevents
  `process.exit/v1` advertisement without disabling unrelated capabilities.

## Aya binding generator spike

The 2026-08-23 spike used the official Aya toolchain against a byte-stream copy
of the 6.8.0-137 reference BTF (SHA-256
`6da9f6b4ebcae9b07e6a717b517884abf7f6b524e46340e40fb164eed4a49a7c`):

```sh
cargo install bindgen-cli
cargo install --git https://github.com/aya-rs/aya --rev 875daf97 -- aya-tool
aya-tool generate --btf /path/to/vmlinux task_struct
```

The generator parsed the BTF and produced a binding containing
`task_struct.exit_code`, but the result is not suitable for this capability:

- selecting `task_struct` expands its kernel-type dependency closure to about
  1.8 MiB rather than producing a minimal field binding;
- the generated Rust contains no `preserve_access_index` annotation or other
  source-level CO-RE field relocation marker;
- the workspace's `aya-ebpf 0.1.1` exposes only an opaque built-in
  `task_struct`, so it cannot express an `exit_code` access itself.

Committing that generated layout would therefore compile an offset from the
6.8 reference BTF without establishing the cross-kernel relocation guarantee
required by this change. It MUST NOT be used as a hard-coded-layout fallback.

The selected path is the minimal C CO-RE companion under
`spikes/process-exit-core`. The same locally built object was accepted without
recompilation by all live reference kernels:

| Node/kernel | Verifier result | Translated | JIT |
|---|---|---:|---:|
| `worker-192.168.0.7` / 5.15.0-138 | accepted | 224 B | 165 B |
| `worker-192.168.0.8` / 5.15.0-139 | accepted | 224 B | 165 B |
| `worker-192.168.0.9` / 6.8.0-137 | accepted | 224 B | 138 B |

LLVM disassembly identifies the relocation as
`struct task_struct::exit_code (0:0)`. `bpftool gen min_core_btf` also consumed
the object successfully against the 6.8 reference BTF. This proves the chosen
access path and avoids checking in a generated 1.8 MiB kernel type closure.

## Raw encoding and semantic fixtures

The spike record is 48 bytes. `raw_wait_status` is a signed 32-bit field at
byte offset 24, followed by four reserved zero bytes. On the little-endian x86
reference nodes the selected fixture encodings are:

| Fixture | Raw decimal | Raw hex | Bytes at offset 24 | Decoded meaning |
|---|---:|---:|---|---|
| normal `exit(7)` | 1792 | `0x0700` | `00 07 00 00` | normal status 7 |
| `SIGTERM` | 15 | `0x000f` | `0f 00 00 00` | signal 15 |
| `SIGKILL` | 9 | `0x0009` | `09 00 00 00` | signal 9 |
| `SIGSEGV` | 139 | `0x008b` | `8b 00 00 00` | signal 11, core flag set |
| re-exec then `exit(9)` | 2304 | `0x0900` | `00 09 00 00` | normal status 9 |

The 6.8 live run observed the first four encodings directly and preserved the
fixture cgroup ID across every case. The 5.15 live run independently observed
normal status 7 and SIGTERM with the same encodings; container-runtime init and
helper exits were visible as separate PID/TGID and cgroup records. The corrected
re-exec fixture is retained for the repeatable matrix.

Linux sets the wait-status core bit for a core-dumping signal even when
`RLIMIT_CORE=0`; both bounded SIGSEGV fixtures therefore produced `0x008b`.
Consequently this bit is evidence of the kernel wait-status core flag, not proof
that a core file was written. Public models and UI wording must use
`core_dump_flag` (or equally explicit wording), not `core_dumped`.

PID-reuse/generation matching and delayed-consumer behavior belong to the
userspace correlation spike because this kernel record intentionally contains
no generation cache. Those cases remain capability gates and must not be
claimed from verifier acceptance alone.

## Capability gate

Presence of the tracepoint and `/sys/kernel/btf/vmlinux` is necessary but not
sufficient. `process.exit/v1` remains withheld when the C object cannot load or
attach, the BTF type/field relocation fails, record size/endianness is unknown,
raw status decoding fails validation, or the process-generation/cgroup match is
untrusted. Failure withholds only `process.exit/v1`. The agent must not fall
back to a hard-coded field offset or reinterpret Kubernetes exit code/reason as
kernel evidence.

## Repeatable inventory commands

```sh
kubectx aliens
kubectl get nodes -o custom-columns=NAME:.metadata.name,KERNEL:.status.nodeInfo.kernelVersion,ARCH:.status.nodeInfo.architecture,OS:.status.nodeInfo.osImage,RUNTIME:.status.nodeInfo.containerRuntimeVersion
kubectl exec -n okoscope <agent-pod> -- test -e /sys/kernel/btf/vmlinux
kubectl exec -n okoscope <agent-pod> -- sed -n 1,120p /sys/kernel/tracing/events/sched/sched_process_exit/format
```
