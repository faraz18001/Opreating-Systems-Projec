#ifndef EBPF_EVENTS_H
#define EBPF_EVENTS_H

#define EVENT_MEMFD_CREATE 1
#define EVENT_EXECVEAT     2
#define EVENT_EXECVE_FD    3
#define EVENT_PRCTL_NAME   4

#define TASK_COMM_LEN 16
#define MAX_NAME_LEN  64

struct pidns_cfg {
    unsigned long long dev;
    unsigned long long ino;
};

struct sensor_event {
    unsigned long long ktime_ns;
    unsigned long long freeze_ktime_ns;
    unsigned long long vfs_ino;
    unsigned int event_type;
    unsigned int pid;
    unsigned int ppid;
    unsigned int uid;
    int fd;
    unsigned int flags;
    unsigned int is_tracked_memfd;
    unsigned int vfs_memfd;
    unsigned int kernel_frozen;
    char comm[TASK_COMM_LEN];
    char name[MAX_NAME_LEN];
    char vfs_name[MAX_NAME_LEN];
};

#endif
