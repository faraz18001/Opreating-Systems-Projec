#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "events.h"

#define AT_EMPTY_PATH 0x1000
#define PR_SET_NAME   15

struct memfd_pending {
    unsigned int flags;
    char name[MAX_NAME_LEN];
};

struct fd_key {
    u32 tgid;
    s32 fd;
};

struct memfd_meta {
    unsigned int flags;
    char name[MAX_NAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, struct memfd_pending);
} pending_memfd SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct fd_key);
    __type(value, struct memfd_meta);
} memfd_fds SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, u32);
} memfd_tgids SEC(".maps");

static __always_inline u32 get_ppid(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    return BPF_CORE_READ(task, real_parent, tgid);
}

static __always_inline void fill_common(struct sensor_event *ev, u32 type) {
    u64 id = bpf_get_current_pid_tgid();
    ev->ktime_ns = bpf_ktime_get_ns();
    ev->event_type = type;
    ev->pid = id >> 32;
    ev->ppid = get_ppid();
    ev->uid = (u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int tp_enter_memfd_create(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct memfd_pending pend = {};
    const char *uname = (const char *)ctx->args[0];

    pend.flags = (unsigned int)ctx->args[1];
    bpf_probe_read_user_str(&pend.name, sizeof(pend.name), uname);
    bpf_map_update_elem(&pending_memfd, &id, &pend, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_memfd_create")
int tp_exit_memfd_create(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct memfd_pending *pend = bpf_map_lookup_elem(&pending_memfd, &id);
    if (!pend) {
        return 0;
    }

    long ret = ctx->ret;
    if (ret >= 0) {
        u32 tgid = id >> 32;
        struct fd_key key = {
            .tgid = tgid,
            .fd = (s32)ret,
        };
        struct memfd_meta meta = {};
        meta.flags = pend->flags;
        __builtin_memcpy(meta.name, pend->name, sizeof(meta.name));

        bpf_map_update_elem(&memfd_fds, &key, &meta, BPF_ANY);

        u32 one = 1;
        u32 *cnt = bpf_map_lookup_elem(&memfd_tgids, &tgid);
        if (cnt) {
            __sync_fetch_and_add(cnt, 1);
        } else {
            bpf_map_update_elem(&memfd_tgids, &tgid, &one, BPF_ANY);
        }

        struct sensor_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
        if (ev) {
            fill_common(ev, EVENT_MEMFD_CREATE);
            ev->fd = (int)ret;
            ev->flags = pend->flags;
            ev->is_tracked_memfd = 1;
            __builtin_memcpy(ev->name, pend->name, sizeof(ev->name));
            bpf_ringbuf_submit(ev, 0);
        }
    }

    bpf_map_delete_elem(&pending_memfd, &id);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int tp_enter_execveat(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    int dfd = (int)ctx->args[0];
    const char *filename = (const char *)ctx->args[1];
    unsigned int flags = (unsigned int)ctx->args[4];

    struct fd_key key = {
        .tgid = tgid,
        .fd = dfd,
    };
    struct memfd_meta *meta = bpf_map_lookup_elem(&memfd_fds, &key);
    int is_empty_path = (flags & AT_EMPTY_PATH) != 0;

    if (!meta && !is_empty_path) {
        return 0;
    }

    struct sensor_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) {
        return 0;
    }

    fill_common(ev, EVENT_EXECVEAT);
    ev->fd = dfd;
    ev->flags = flags;
    ev->is_tracked_memfd = meta ? 1 : 0;

    if (meta) {
        __builtin_memcpy(ev->name, meta->name, sizeof(ev->name));
    } else if (filename) {
        bpf_probe_read_user_str(&ev->name, sizeof(ev->name), filename);
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tp_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    const char *filename = (const char *)ctx->args[0];
    char path[MAX_NAME_LEN] = {};

    if (!filename) {
        return 0;
    }

    bpf_probe_read_user_str(&path, sizeof(path), filename);

    int is_proc_path = (path[0] == '/' && path[1] == 'p' && path[2] == 'r' &&
                        path[3] == 'o' && path[4] == 'c' && path[5] == '/');
    u32 *tracked = bpf_map_lookup_elem(&memfd_tgids, &tgid);

    if (!is_proc_path && !tracked) {
        return 0;
    }

    struct sensor_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) {
        return 0;
    }

    fill_common(ev, EVENT_EXECVE_FD);
    ev->fd = -1;
    ev->flags = 0;
    ev->is_tracked_memfd = tracked ? 1 : 0;
    __builtin_memcpy(ev->name, path, sizeof(ev->name));
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_prctl")
int tp_enter_prctl(struct trace_event_raw_sys_enter *ctx) {
    int option = (int)ctx->args[0];
    if (option != PR_SET_NAME) {
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    const char *new_name = (const char *)ctx->args[1];
    char name_buf[MAX_NAME_LEN] = {};

    if (new_name) {
        bpf_probe_read_user_str(&name_buf, sizeof(name_buf), new_name);
    }

    u32 *tracked = bpf_map_lookup_elem(&memfd_tgids, &tgid);
    int looks_like_kthread = (name_buf[0] == '[');

    if (!tracked && !looks_like_kthread) {
        return 0;
    }

    struct sensor_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) {
        return 0;
    }

    fill_common(ev, EVENT_PRCTL_NAME);
    ev->fd = -1;
    ev->flags = (unsigned int)option;
    ev->is_tracked_memfd = tracked ? 1 : 0;
    __builtin_memcpy(ev->name, name_buf, sizeof(ev->name));
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
