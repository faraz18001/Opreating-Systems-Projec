#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "events.h"

static volatile sig_atomic_t running = 1;

static void handle_signal(int sig) {
    (void)sig;
    running = 0;
}

static const char *event_type_str(unsigned int type) {
    switch (type) {
        case EVENT_MEMFD_CREATE:  return "memfd_create";
        case EVENT_EXECVEAT:      return "execveat";
        case EVENT_EXECVE_FD:     return "execve_fd";
        case EVENT_PRCTL_NAME:    return "prctl_set_name";
        case EVENT_MPROTECT_EXEC: return "mprotect_exec";
        default:                  return "unknown";
    }
}

static void print_json_escaped(const char *s, size_t max_len) {
    putchar('"');
    for (size_t i = 0; i < max_len && s[i] != '\0'; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') {
            putchar('\\');
            putchar(c);
        } else if (c >= 0x20 && c < 0x7f) {
            putchar(c);
        } else {
            printf("\\u%04x", c);
        }
    }
    putchar('"');
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    if (data_sz < sizeof(struct sensor_event)) {
        return 0;
    }

    const struct sensor_event *ev = (const struct sensor_event *)data;
    printf("{\"ktime_ns\":%llu,\"freeze_ktime_ns\":%llu,\"vfs_ino\":%llu,\"type\":\"%s\",\"pid\":%u,\"ppid\":%u,"
           "\"uid\":%u,\"fd\":%d,\"flags\":%u,\"tracked_memfd\":%s,\"vfs_memfd\":%s,\"kernel_frozen\":%s,\"comm\":",
           ev->ktime_ns,
           ev->freeze_ktime_ns,
           ev->vfs_ino,
           event_type_str(ev->event_type),
           ev->pid,
           ev->ppid,
           ev->uid,
           ev->fd,
           ev->flags,
           ev->is_tracked_memfd ? "true" : "false",
           ev->vfs_memfd ? "true" : "false",
           ev->kernel_frozen ? "true" : "false");
    print_json_escaped(ev->comm, TASK_COMM_LEN);
    printf(",\"name\":");
    print_json_escaped(ev->name, MAX_NAME_LEN);
    printf(",\"vfs_name\":");
    print_json_escaped(ev->vfs_name, MAX_NAME_LEN);
    printf("}\n");
    fflush(stdout);
    return 0;
}

static int libbpf_print_cb(enum libbpf_print_level level, const char *fmt, va_list args) {
    if (level == LIBBPF_DEBUG) {
        return 0;
    }
    return vfprintf(stderr, fmt, args);
}

int main(int argc, char *argv[]) {
    const char *obj_path = "ebpf/build/probes.bpf.o";
    unsigned int kernel_freeze = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--kernel-freeze") == 0) {
            kernel_freeze = 1;
        } else {
            obj_path = argv[i];
        }
    }

    libbpf_set_print(libbpf_print_cb);
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) {
        fprintf(stderr, "error: failed to open BPF object: %s\n", obj_path);
        return 1;
    }

    if (bpf_object__load(obj) != 0) {
        fprintf(stderr, "error: failed to load BPF object (run with sudo/CAP_BPF)\n");
        bpf_object__close(obj);
        return 1;
    }

    int cfg_fd = bpf_object__find_map_fd_by_name(obj, "defender_cfg");
    if (cfg_fd >= 0) {
        unsigned int key = 0;
        if (bpf_map_update_elem(cfg_fd, &key, &kernel_freeze, BPF_ANY) != 0) {
            fprintf(stderr, "warning: failed to configure kernel_freeze mode\n");
        }
    }

    struct stat ns_st;
    if (stat("/proc/self/ns/pid", &ns_st) == 0) {
        int ns_map_fd = bpf_object__find_map_fd_by_name(obj, "ns_config");
        if (ns_map_fd >= 0) {
            unsigned int key = 0;
            struct pidns_cfg cfg = {
                .dev = (unsigned long long)ns_st.st_dev,
                .ino = (unsigned long long)ns_st.st_ino,
            };
            if (bpf_map_update_elem(ns_map_fd, &key, &cfg, BPF_ANY) != 0) {
                fprintf(stderr, "warning: failed to configure pidns filter: %s\n", strerror(errno));
            }
        }
    }

    struct bpf_link *links[16];
    int link_count = 0;
    struct bpf_program *prog;

    bpf_object__for_each_program(prog, obj) {
        if (link_count >= 16) {
            break;
        }
        struct bpf_link *link = bpf_program__attach(prog);
        if (!link) {
            fprintf(stderr, "error: failed to attach program %s\n", bpf_program__name(prog));
            for (int i = 0; i < link_count; i++) {
                bpf_link__destroy(links[i]);
            }
            bpf_object__close(obj);
            return 1;
        }
        links[link_count++] = link;
    }

    int map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "error: failed to find events ringbuf map\n");
        for (int i = 0; i < link_count; i++) {
            bpf_link__destroy(links[i]);
        }
        bpf_object__close(obj);
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "error: failed to create ring buffer\n");
        for (int i = 0; i < link_count; i++) {
            bpf_link__destroy(links[i]);
        }
        bpf_object__close(obj);
        return 1;
    }

    fprintf(stderr, "[sensor] attached %d eBPF tracepoints (kernel_freeze=%u)\n",
            link_count, kernel_freeze);
    fflush(stderr);

    while (running) {
        int err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            continue;
        }
        if (err < 0) {
            fprintf(stderr, "error: ring_buffer__poll failed: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    for (int i = 0; i < link_count; i++) {
        bpf_link__destroy(links[i]);
    }
    bpf_object__close(obj);
    return 0;
}
