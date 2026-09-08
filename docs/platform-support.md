# MVP platform support

Okoscope MVP intentionally targets one narrow, testable Linux profile.

| Component | Initial support |
|---|---|
| Kubernetes | 1.32 or newer |
| Container runtime | containerd 2.x using CRI |
| Cgroups | v2 unified hierarchy |
| Linux kernel | 6.1 LTS or newer with BTF enabled and `/sys/kernel/btf/vmlinux` present |
| Architecture | x86_64 (`bpfel-unknown-none` eBPF target) |
| Workload owner | Pod → ReplicaSet → Deployment |

The userspace crates can be developed on other platforms, but the eBPF probe and end-to-end verification require the profile above. The agent reports its actual kernel, architecture, version, and capabilities during session setup and remains unready when a required capability cannot be attached.

Before deploying an agent, verify:

```sh
test -e /sys/kernel/btf/vmlinux
test "$(stat -fc %T /sys/fs/cgroup)" = cgroup2fs
uname -m
```

Other kernels, cgroup v1, CRI-O, ARM64, Pods without a Deployment owner, and managed-provider-specific hardened nodes are not claimed as supported by this MVP.

