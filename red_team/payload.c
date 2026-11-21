#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    const char *fake_name = "[kworker/u8:2]";
    int masquerade = 1;
    int ticks = 8;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-masquerade") == 0) {
            masquerade = 0;
        } else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc) {
            fake_name = argv[++i];
        } else if (strcmp(argv[i], "--ticks") == 0 && i + 1 < argc) {
            ticks = atoi(argv[++i]);
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
