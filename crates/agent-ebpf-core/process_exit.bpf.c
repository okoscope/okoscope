// SPDX-License-Identifier: GPL-2.0 OR MIT

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name

typedef unsigned int __u32;
typedef unsigned long long __u64;

enum {
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
    BPF_MAP_TYPE_RINGBUF = 27,
    BPF_FUNC_map_lookup_elem = 1,
    BPF_FUNC_ktime_get_ns = 5,
    BPF_FUNC_get_current_pid_tgid = 14,
    BPF_FUNC_get_current_comm = 16,
    BPF_FUNC_get_current_cgroup_id = 80,
    BPF_FUNC_ringbuf_output = 130,
    BPF_FUNC_get_current_task_btf = 158,
};

struct task_struct {
    int exit_code;
} __attribute__((preserve_access_index));

struct exit_kernel_event {
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u64 pid_tgid;
    int raw_wait_status;
    __u32 reserved;
    char command[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} EXIT_EVENTS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} EXIT_COUNTERS SEC(".maps");

static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
    (void *)BPF_FUNC_map_lookup_elem;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static __u64 (*bpf_get_current_pid_tgid)(void) =
    (void *)BPF_FUNC_get_current_pid_tgid;
static long (*bpf_get_current_comm)(void *buf, __u32 size) =
    (void *)BPF_FUNC_get_current_comm;
static __u64 (*bpf_get_current_cgroup_id)(void) =
    (void *)BPF_FUNC_get_current_cgroup_id;
static long (*bpf_ringbuf_output)(void *ringbuf, const void *data, __u64 size,
                                  __u64 flags) =
    (void *)BPF_FUNC_ringbuf_output;
static struct task_struct *(*bpf_get_current_task_btf)(void) =
    (void *)BPF_FUNC_get_current_task_btf;

SEC("tracepoint/sched/sched_process_exit")
int okoscope_process_exit(void *ctx)
{
    struct task_struct *task = bpf_get_current_task_btf();
    struct exit_kernel_event record = {};
    __u32 lost_index = 0;
    __u64 *lost;

    (void)ctx;
    if (!task)
        return 0;

    record.timestamp_ns = bpf_ktime_get_ns();
    record.cgroup_id = bpf_get_current_cgroup_id();
    record.pid_tgid = bpf_get_current_pid_tgid();
    record.raw_wait_status = __builtin_preserve_access_index(task->exit_code);
    bpf_get_current_comm(record.command, sizeof(record.command));
    if (bpf_ringbuf_output(&EXIT_EVENTS, &record, sizeof(record), 0) != 0) {
        lost = bpf_map_lookup_elem(&EXIT_COUNTERS, &lost_index);
        if (lost)
            __sync_fetch_and_add(lost, 1);
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
