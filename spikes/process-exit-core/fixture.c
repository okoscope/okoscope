// SPDX-License-Identifier: Apache-2.0

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    struct rlimit no_core = {0, 0};

    if (argc != 2)
        return 64;
    if (strcmp(argv[1], "exit7") == 0)
        return 7;
    if (strcmp(argv[1], "exit9") == 0)
        return 9;
    if (strcmp(argv[1], "term") == 0)
        return raise(SIGTERM) == 0 ? 70 : 71;
    if (strcmp(argv[1], "kill") == 0)
        return raise(SIGKILL) == 0 ? 72 : 73;
    if (strcmp(argv[1], "segv-no-core") == 0) {
        if (setrlimit(RLIMIT_CORE, &no_core) != 0)
            return 74;
        return raise(SIGSEGV) == 0 ? 75 : 76;
    }
    if (strcmp(argv[1], "segv-core") == 0)
        return raise(SIGSEGV) == 0 ? 77 : 78;
    if (strcmp(argv[1], "reexec-exit9") == 0) {
        execl(argv[0], argv[0], "exit9", NULL);
        return 79;
    }
    if (strcmp(argv[1], "parent-exits-first") == 0) {
        pid_t child = fork();

        if (child < 0)
            return 80;
        if (child == 0) {
            usleep(100000);
            _exit(12);
        }
        return 11;
    }
    if (strcmp(argv[1], "parent-reaps-child") == 0) {
        pid_t child = fork();
        int status;

        if (child < 0)
            return 81;
        if (child == 0)
            _exit(13);
        if (waitpid(child, &status, 0) != child)
            return 82;
        return WIFEXITED(status) && WEXITSTATUS(status) == 13 ? 14 : 83;
    }
    return 65;
}
