#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        puts("child");
        FILE *file = fopen("/etc/hostname", "r");
        if (!file) {
            perror("fopen /etc/hostname");
            return 1;
        }

        char line[256];
        while (fgets(line, sizeof(line), file))
            fputs(line, stdout);

        int failed = ferror(file);
        fclose(file);
        return failed ? 1 : 0;
    }

    int status;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            perror("waitpid");
            return 1;
        }
    }

    puts("Parent");
    FILE *file = fopen("/bin/ls", "r");
    if (!file) {
        perror("fopen /bin/ls");
        return 1;
    }
    fclose(file);

    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}