#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "events.h"

#define AT_EMPTY_PATH 0x1000
#define PR_SET_NAME   15
#define SIGSTOP_NUM   19
#define TMPFS_MAGIC   0x01021994UL
#define PROT_WRITE    0x2
#define PROT_EXEC     0x4
#define MAP_ANONYMOUS 0x20

struct memfd_pending {
    unsigned int flags;
    char name[MAX_NAME_LEN];
};

struct mmap_pending {
    unsigned int prot;
    unsigned int flags;
};

struct addr_key {
    u32 tgid;
    u64 addr;
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
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} defender_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct pidns_cfg);
} ns_config SEC(".maps");

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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, struct mmap_pending);
} pending_mmap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct addr_key);
    __type(value, u32);
} anon_rw_maps SEC(".maps");

static __always_inline int get_ns_tgid(u32 *out_tgid) {
    u32 zero = 0;
    struct pidns_cfg *cfg = bpf_map_lookup_elem(&ns_config, &zero);
    if (cfg && cfg->ino != 0) {
        struct bpf_pidns_info ns = {};
        if (bpf_get_ns_current_pid_tgid(cfg->dev, cfg->ino, &ns, sizeof(ns)) != 0) {
            return -1;
        }
        *out_tgid = ns.tgid;
        return 0;
    }
    *out_tgid = (u32)(bpf_get_current_pid_tgid() >> 32);
    return 0;
}

static __always_inline int is_kernel_freeze_enabled(void) {
    u32 idx = 0;
    u32 *mode = bpf_map_lookup_elem(&defender_cfg, &idx);
    return (mode && *mode == 1) ? 1 : 0;
}

static __always_inline u32 get_ppid(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    return BPF_CORE_READ(task, real_parent, tgid);
}

static __always_inline int inspect_fd_vfs(int dfd, char out_name[MAX_NAME_LEN], u64 *out_ino) {
    if (dfd < 0 || dfd >= 65536) {
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files) {
        return 0;
    }

    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt) {
        return 0;
    }

    unsigned int max_fds = BPF_CORE_READ(fdt, max_fds);
    u32 ufd = (u32)dfd;
    if (ufd >= max_fds) {
        return 0;
    }

    struct file **fd_arr = BPF_CORE_READ(fdt, fd);
    if (!fd_arr) {
        return 0;
    }

    struct file *filp = NULL;
    if (bpf_probe_read_kernel(&filp, sizeof(filp), fd_arr + ufd) != 0 || !filp) {
        return 0;
    }

    struct inode *inode = BPF_CORE_READ(filp, f_inode);
    if (!inode) {
        return 0;
    }

    unsigned long magic = BPF_CORE_READ(inode, i_sb, s_magic);
    u64 ino = BPF_CORE_READ(inode, i_ino);
    const unsigned char *dname = BPF_CORE_READ(filp, f_path.dentry, d_name.name);

    char d_buf[MAX_NAME_LEN] = {};
    if (dname) {
        bpf_probe_read_kernel_str(d_buf, sizeof(d_buf), dname);
    }

    int is_memfd_dname = (d_buf[0] == 'm' && d_buf[1] == 'e' && d_buf[2] == 'm' &&
                          d_buf[3] == 'f' && d_buf[4] == 'd' && d_buf[5] == ':');
    if (magic == TMPFS_MAGIC && is_memfd_dname) {
        *out_ino = ino;
        __builtin_memcpy(out_name, d_buf, MAX_NAME_LEN);
        return 1;
    }
    return 0;
}

static __always_inline int is_jit_allowlisted_comm(const char comm[TASK_COMM_LEN]) {
    if (__builtin_memcmp(comm, "node", 5) == 0 ||
        __builtin_memcmp(comm, "java", 5) == 0 ||
        __builtin_memcmp(comm, "python3", 8) == 0 ||
        __builtin_memcmp(comm, "firefox", 7) == 0 ||
        __builtin_memcmp(comm, "chrom", 5) == 0 ||
        __builtin_memcmp(comm, "brave", 5) == 0 ||
        __builtin_memcmp(comm, "electron", 8) == 0 ||
        __builtin_memcmp(comm, "Web ", 4) == 0 ||
        __builtin_memcmp(comm, "Isolated ", 9) == 0) {
        return 1;
    }
    return 0;
}

static __always_inline int parse_digits_at(const char path[MAX_NAME_LEN], int start) {
    int val = 0;
    int digits = 0;
    #pragma unroll
    for (int j = 0; j < 6; j++) {
        int idx = start + j;
        if (idx >= MAX_NAME_LEN) {
            break;
        }
        char c = path[idx];
        if (c >= '0' && c <= '9') {
            val = val * 10 + (c - '0');
            digits++;
        } else {
            break;
        }
    }
    return digits > 0 ? val : -1;
}

static __always_inline int parse_proc_fd_path(const char path[MAX_NAME_LEN]) {
    if (!(path[0] == '/' && path[1] == 'p' && path[2] == 'r' &&
          path[3] == 'o' && path[4] == 'c' && path[5] == '/')) {
        return -1;
    }

    if (path[6] == 's' && path[7] == 'e' && path[8] == 'l' && path[9] == 'f' &&
        path[10] == '/' && path[11] == 'f' && path[12] == 'd' && path[13] == '/') {
        return parse_digits_at(path, 14);
    }

    if (path[6] == 't' && path[7] == 'h' && path[8] == 'r' && path[9] == 'e' &&
        path[10] == 'a' && path[11] == 'd' && path[12] == '-' && path[13] == 's' &&
        path[14] == 'e' && path[15] == 'l' && path[16] == 'f' && path[17] == '/' &&
        path[18] == 'f' && path[19] == 'd' && path[20] == '/') {
        return parse_digits_at(path, 21);
    }

    int saw_digit = 0;
    #pragma unroll
    for (int i = 6; i <= 16; i++) {
        char c = path[i];
        if (c >= '0' && c <= '9') {
            saw_digit = 1;
        } else if (c == '/' && saw_digit) {
            if (path[i + 1] == 'f' && path[i + 2] == 'd' && path[i + 3] == '/') {
                return parse_digits_at(path, i + 4);
            }
            return -1;
        } else {
            return -1;
        }
    }
    return -1;
}

static __always_inline void fill_common(struct sensor_event *ev, u32 type, u32 ns_tgid) {
    ev->ktime_ns = bpf_ktime_get_ns();
    ev->freeze_ktime_ns = 0;
    ev->vfs_ino = 0;
    ev->event_type = type;
    ev->pid = ns_tgid;
    ev->ppid = get_ppid();
    ev->uid = (u32)bpf_get_current_uid_gid();
    ev->vfs_memfd = 0;
    ev->kernel_frozen = 0;
    ev->vfs_name[0] = '\0';
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
}

SEC("tracepoint/sched/sched_process_fork")
int tp_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    u32 parent_ns = 0;
    if (get_ns_tgid(&parent_ns) == 0) {
        u32 *tracked = bpf_map_lookup_elem(&memfd_tgids, &parent_ns);
        if (tracked) {
            u32 child_pid = (u32)ctx->child_pid;
            u32 one = 1;
            bpf_map_update_elem(&memfd_tgids, &child_pid, &one, BPF_ANY);
        }
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int tp_enter_memfd_create(struct trace_event_raw_sys_enter *ctx) {
    u32 ns_tgid = 0;
    if (get_ns_tgid(&ns_tgid) != 0) {
        return 0;
    }

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

    u32 ns_tgid = 0;
    if (get_ns_tgid(&ns_tgid) != 0) {
        bpf_map_delete_elem(&pending_memfd, &id);
        return 0;
    }

    long ret = ctx->ret;
    if (ret >= 0) {
        struct fd_key key = {
            .tgid = ns_tgid,
            .fd = (s32)ret,
        };
        struct memfd_meta meta = {};
        meta.flags = pend->flags;
        __builtin_memcpy(meta.name, pend->name, sizeof(meta.name));

        bpf_map_update_elem(&memfd_fds, &key, &meta, BPF_ANY);

        u32 one = 1;
        u32 *cnt = bpf_map_lookup_elem(&memfd_tgids, &ns_tgid);
        if (cnt) {
            __sync_fetch_and_add(cnt, 1);
        } else {
            bpf_map_update_elem(&memfd_tgids, &ns_tgid, &one, BPF_ANY);
        }

        struct sensor_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
        if (ev) {
            fill_common(ev, EVENT_MEMFD_CREATE, ns_tgid);
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
    u32 tgid = 0;
    if (get_ns_tgid(&tgid) != 0) {
        return 0;
    }

    int dfd = (int)ctx->args[0];
    const char *filename = (const char *)ctx->args[1];
    unsigned int flags = (unsigned int)ctx->args[4];

    struct fd_key key = {
        .tgid = tgid,
        .fd = dfd,
    };
    struct memfd_meta *meta = bpf_map_lookup_elem(&memfd_fds, &key);
    int is_empty_path = (flags & AT_EMPTY_PATH) != 0;
    u32 tracked_flag = 0;

    if (meta) {
        tracked_flag = 1;
    } else {
        u32 *tracked_tgid = bpf_map_lookup_elem(&memfd_tgids, &tgid);
        if (tracked_tgid) {
            tracked_flag = 1;
        }
    }

    char vfs_name[MAX_NAME_LEN] = {};
    u64 vfs_ino = 0;
    int vfs_is_memfd = inspect_fd_vfs(dfd, vfs_name, &vfs_ino);
    if (vfs_is_memfd) {
        tracked_flag = 1;
    }

    if (!tracked_flag && !is_empty_path) {
        return 0;
    }

    struct sensor_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) {
        return 0;
    }

    fill_common(ev, EVENT_EXECVEAT, tgid);
    ev->fd = dfd;
    ev->flags = flags;
    ev->is_tracked_memfd = tracked_flag;
    ev->vfs_memfd = vfs_is_memfd ? 1 : 0;
    ev->vfs_ino = vfs_ino;
    __builtin_memcpy(ev->vfs_name, vfs_name, sizeof(ev->vfs_name));

    if ((vfs_is_memfd || meta != NULL) && is_kernel_freeze_enabled()) {
        if (bpf_send_signal(SIGSTOP_NUM) == 0) {
            ev->kernel_frozen = 1;
            ev->freeze_ktime_ns = bpf_ktime_get_ns();
        }
    }

    if (meta) {
        __builtin_memcpy(ev->name, meta->name, sizeof(ev->name));
    } else if (vfs_is_memfd) {
        __builtin_memcpy(ev->name, vfs_name, sizeof(ev->name));
    } else if (filename) {
        bpf_probe_read_user_str(&ev->name, sizeof(ev->name), filename);
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tp_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    u32 tgid = 0;
    if (get_ns_tgid(&tgid) != 0) {
        return 0;
    }

    const char *filename = (const char *)ctx->args[0];
    char path[MAX_NAME_LEN] = {};

    if (!filename) {
        return 0;
    }

    bpf_probe_read_user_str(&path, sizeof(path), filename);

    int is_proc_path = (path[0] == '/' && path[1] == 'p' && path[2] == 'r' &&
                        path[3] == 'o' && path[4] == 'c' && path[5] == '/');
    u32 *tracked = bpf_map_lookup_elem(&memfd_tgids, &tgid);

    int parsed_fd = is_proc_path ? parse_proc_fd_path(path) : -1;
    char vfs_name[MAX_NAME_LEN] = {};
    u64 vfs_ino = 0;
    int vfs_is_memfd = (parsed_fd >= 0) ? inspect_fd_vfs(parsed_fd, vfs_name, &vfs_ino) : 0;

    if (!is_proc_path && !tracked && !vfs_is_memfd) {
        return 0;
    }

    struct sensor_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) {
        return 0;
    }

    fill_common(ev, EVENT_EXECVE_FD, tgid);
    ev->fd = parsed_fd;
    ev->flags = 0;
    ev->is_tracked_memfd = (tracked || vfs_is_memfd) ? 1 : 0;
    ev->vfs_memfd = vfs_is_memfd ? 1 : 0;
    ev->vfs_ino = vfs_ino;
    __builtin_memcpy(ev->vfs_name, vfs_name, sizeof(ev->vfs_name));

    if ((vfs_is_memfd || (is_proc_path && tracked)) && is_kernel_freeze_enabled()) {
        if (bpf_send_signal(SIGSTOP_NUM) == 0) {
            ev->kernel_frozen = 1;
            ev->freeze_ktime_ns = bpf_ktime_get_ns();
        }
    }

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

    u32 tgid = 0;
    if (get_ns_tgid(&tgid) != 0) {
        return 0;
    }

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

    fill_common(ev, EVENT_PRCTL_NAME, tgid);
    ev->fd = -1;
    ev->flags = (unsigned int)option;
    ev->is_tracked_memfd = tracked ? 1 : 0;
    __builtin_memcpy(ev->name, name_buf, sizeof(ev->name));
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int tp_enter_mmap(struct trace_event_raw_sys_enter *ctx) {
    unsigned int prot = (unsigned int)ctx->args[2];
    unsigned int flags = (unsigned int)ctx->args[3];

    if ((flags & MAP_ANONYMOUS) == 0 || (prot & (PROT_WRITE | PROT_EXEC)) == 0) {
        return 0;
    }

    u32 ns_tgid = 0;
    if (get_ns_tgid(&ns_tgid) != 0) {
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();
    struct mmap_pending pend = {
        .prot = prot,
        .flags = flags,
    };
    bpf_map_update_elem(&pending_mmap, &id, &pend, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mmap")
int tp_exit_mmap(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct mmap_pending *pend = bpf_map_lookup_elem(&pending_mmap, &id);
    if (!pend) {
        return 0;
    }

    u32 ns_tgid = 0;
    if (get_ns_tgid(&ns_tgid) != 0) {
        bpf_map_delete_elem(&pending_mmap, &id);
        return 0;
    }

    long ret = ctx->ret;
    if (ret > 0) {
        u32 prot = pend->prot;
        if ((prot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC)) {
            struct sensor_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
            if (ev) {
                fill_common(ev, EVENT_MPROTECT_EXEC, ns_tgid);
                ev->fd = -1;
                ev->flags = prot;
                ev->is_tracked_memfd = 0;
                __builtin_memcpy(ev->name, "anon_rwx_mmap", 14);
                if (is_kernel_freeze_enabled() && !is_jit_allowlisted_comm(ev->comm)) {
                    if (bpf_send_signal(SIGSTOP_NUM) == 0) {
                        ev->kernel_frozen = 1;
                        ev->freeze_ktime_ns = bpf_ktime_get_ns();
                    }
                }
                bpf_ringbuf_submit(ev, 0);
            }
        } else if ((prot & PROT_WRITE) != 0) {
            struct addr_key akey = {
                .tgid = ns_tgid,
                .addr = (u64)ret,
            };
            u32 one = 1;
            bpf_map_update_elem(&anon_rw_maps, &akey, &one, BPF_ANY);
        }
    }

    bpf_map_delete_elem(&pending_mmap, &id);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int tp_enter_mprotect(struct trace_event_raw_sys_enter *ctx) {
    unsigned int prot = (unsigned int)ctx->args[2];
    if ((prot & PROT_EXEC) == 0) {
        return 0;
    }

    u32 ns_tgid = 0;
    if (get_ns_tgid(&ns_tgid) != 0) {
        return 0;
    }

    u64 addr = (u64)ctx->args[0];
    struct addr_key akey = {
        .tgid = ns_tgid,
        .addr = addr,
    };
    u32 *tracked = bpf_map_lookup_elem(&anon_rw_maps, &akey);
    if (!tracked) {
        return 0;
    }
    bpf_map_delete_elem(&anon_rw_maps, &akey);

    struct sensor_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) {
        return 0;
    }

    fill_common(ev, EVENT_MPROTECT_EXEC, ns_tgid);
    ev->fd = -1;
    ev->flags = prot;
    ev->is_tracked_memfd = 0;
    __builtin_memcpy(ev->name, "anon_w_to_x", 12);

    if (is_kernel_freeze_enabled() && !is_jit_allowlisted_comm(ev->comm)) {
        if (bpf_send_signal(SIGSTOP_NUM) == 0) {
            ev->kernel_frozen = 1;
            ev->freeze_ktime_ns = bpf_ktime_get_ns();
        }
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
