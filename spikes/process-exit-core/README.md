# Process exit C CO-RE spike

This spike proves the field relocation needed to read native Linux wait status
at `sched_process_exit` without compiling a target-kernel `task_struct` offset
into the agent.

`process_exit.bpf.c` deliberately declares only `task_struct.exit_code` with
`preserve_access_index`. `make verify` requires `.BTF` and `.BTF.ext` in the
object and asks `bpftool gen min_core_btf` to consume the object's CO-RE
relocation against a supplied kernel BTF. A non-empty minimal BTF is evidence
that the object contains a usable field relocation; it is not by itself a
verifier or semantic result.

Build and verify on Linux with Clang/LLVM and bpftool:

```sh
make
make verify BTF=/sys/kernel/btf/vmlinux
```

The emitted 48-byte fixed record is spike-only and is not yet the public
`agent-ebpf-common` ABI. It carries timestamp, cgroup ID, PID/TGID, raw
`task_struct.exit_code`, and the bounded 16-byte command. The runtime matrix
results and capability-withholding rules are recorded in
`docs/process-termination-kernel-profile.md`.

The companion is intentionally separate from the Rust eBPF object. Production
integration can load both objects through Aya userspace after this spike proves
the C object's behavior on every claimed kernel.

For semantic fixtures, `loader.c` is a deliberately small libbpf harness that
loads and attaches the object and prints a bounded requested number of ring
records. It is spike tooling, not a production agent dependency:

```sh
cc -O2 -Wall -Werror loader.c -lbpf -lelf -lz -o process-exit-loader
./process-exit-loader build/process_exit.bpf.o 5
./process-exit-loader build/process_exit.bpf.o 5 5000 # delay polling by 5 s
```

`fixture.c` provides deterministic normal-exit, signal, core-limit, and re-exec
cases for the live matrix. The `segv-no-core` name describes its zero
`RLIMIT_CORE`, not an expected clear wait-status bit: Linux still sets the core
flag for the core-dumping signal. Its process name keeps fixture records
distinct from container-runtime helper exits. `parent-exits-first` and
`parent-reaps-child` cover both parent/task ordering cases; the loader's
optional delay proves that the fixed ring record does not depend on `/proc`
state still existing when userspace consumes it.
