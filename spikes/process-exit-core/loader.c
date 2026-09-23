// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <bpf/libbpf.h>

struct process_exit_record {
    uint64_t timestamp_ns;
    uint64_t cgroup_id;
    uint64_t pid_tgid;
    int32_t raw_wait_status;
    uint32_t reserved;
    char command[16];
};

static volatile sig_atomic_t stop;
static unsigned int seen;
static unsigned int wanted;

static void stop_polling(int signal_number)
{
    (void)signal_number;
    stop = 1;
}

static int print_record(void *ctx, void *data, size_t size)
{
    const struct process_exit_record *record = data;
    uint32_t pid = (uint32_t)record->pid_tgid;
    uint32_t tgid = (uint32_t)(record->pid_tgid >> 32);

    (void)ctx;
    if (size != sizeof(*record)) {
        fprintf(stderr, "unexpected record size: %zu\n", size);
        return 0;
    }

    printf("timestamp_ns=%llu cgroup_id=%llu pid=%u tgid=%u raw_wait_status=%d command=%.*s\n",
           (unsigned long long)record->timestamp_ns,
           (unsigned long long)record->cgroup_id, pid, tgid,
           record->raw_wait_status, (int)sizeof(record->command),
           record->command);
    fflush(stdout);
    if (++seen >= wanted)
        stop = 1;
    return 0;
}

int main(int argc, char **argv)
{
    struct bpf_object *object;
    struct bpf_program *program;
    struct bpf_link *link;
    struct ring_buffer *ring;
    int map_fd;
    int error;

    if (argc != 3 && argc != 4) {
        fprintf(stderr, "usage: %s OBJECT EVENT_COUNT [INITIAL_DELAY_MS]\n", argv[0]);
        return 2;
    }
    wanted = (unsigned int)strtoul(argv[2], NULL, 10);
    if (wanted == 0)
        return 2;

    signal(SIGINT, stop_polling);
    signal(SIGTERM, stop_polling);

    object = bpf_object__open_file(argv[1], NULL);
    error = libbpf_get_error(object);
    if (error) {
        fprintf(stderr, "open failed: %d\n", error);
        return 1;
    }
    error = bpf_object__load(object);
    if (error) {
        fprintf(stderr, "load failed: %d\n", error);
        bpf_object__close(object);
        return 1;
    }

    program = bpf_object__next_program(object, NULL);
    link = bpf_program__attach(program);
    error = libbpf_get_error(link);
    if (error) {
        fprintf(stderr, "attach failed: %d\n", error);
        bpf_object__close(object);
        return 1;
    }

    map_fd = bpf_object__find_map_fd_by_name(object, "EXIT_EVENTS");
    if (map_fd < 0) {
        fprintf(stderr, "ring map not found: %d\n", map_fd);
        bpf_link__destroy(link);
        bpf_object__close(object);
        return 1;
    }
    ring = ring_buffer__new(map_fd, print_record, NULL, NULL);
    error = libbpf_get_error(ring);
    if (error) {
        fprintf(stderr, "ring open failed: %d\n", error);
        bpf_link__destroy(link);
        bpf_object__close(object);
        return 1;
    }

    if (argc == 4) {
        struct timespec delay = {
            .tv_sec = strtoul(argv[3], NULL, 10) / 1000,
            .tv_nsec = (strtoul(argv[3], NULL, 10) % 1000) * 1000000,
        };

        while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
        }
    }

    while (!stop) {
        error = ring_buffer__poll(ring, 1000);
        if (error == -EINTR)
            continue;
        if (error < 0) {
            fprintf(stderr, "ring poll failed: %d\n", error);
            break;
        }
    }

    ring_buffer__free(ring);
    bpf_link__destroy(link);
    bpf_object__close(object);
    return error < 0 ? 1 : 0;
}
