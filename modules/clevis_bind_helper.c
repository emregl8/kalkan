#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "usage: clevis-bind-helper <device> <tpm2-config>\n");
        return 1;
    }

    char passphrase[4096];
    explicit_bzero(passphrase, sizeof(passphrase));

    size_t len = 0;
    int c;
    while (len < sizeof(passphrase) - 1) {
        c = getchar();
        if (c == EOF || c == '\n') break;
        passphrase[len++] = (char)c;
    }

    int pfd[2];
    if (pipe(pfd) != 0) {
        explicit_bzero(passphrase, sizeof(passphrase));
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        explicit_bzero(passphrase, sizeof(passphrase));
        close(pfd[0]);
        close(pfd[1]);
        return 1;
    }

    if (pid == 0) {
        close(pfd[1]);
        if (dup2(pfd[0], STDIN_FILENO) < 0) _exit(127);
        close(pfd[0]);
        execlp("sudo", "sudo", "clevis", "luks", "bind",
               "-d", argv[1], "tpm2", argv[2], NULL);
        _exit(127);
    }

    close(pfd[0]);
    write(pfd[1], passphrase, len);
    write(pfd[1], "\n", 1);
    close(pfd[1]);

    explicit_bzero(passphrase, sizeof(passphrase));

    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
