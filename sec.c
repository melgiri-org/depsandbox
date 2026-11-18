#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void log_json_string(FILE *file, const char *value)
{
    fputc('"', file);
    for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
        if (*p == '"' || *p == '\\') {
            fputc('\\', file);
            fputc(*p, file);
        } else if (*p < 0x20) {
            fprintf(file, "\\u%04x", (unsigned int)*p);
        } else {
            fputc(*p, file);
        }
    }
    fputc('"', file);
}

static pid_t get_parent_pid(pid_t pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);

    FILE *file = fopen(path, "r");
    if (!file)
        return -1;

    char line[128];
    pid_t parent = -1;
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "PPid:", 5) == 0) {
            sscanf(line + 5, "%d", &parent);
            break;
        }
    }
    fclose(file);
    return parent;
}

static int send_fd(int socket_fd, int fd)
{
    char byte = ' ';
    struct iovec data = { .iov_base = &byte, .iov_len = 1 };
    union {
        struct cmsghdr alignment;
        unsigned char bytes[CMSG_SPACE(sizeof(int))];
    } control = {0};

    struct msghdr message = {
        .msg_iov = &data,
        .msg_iovlen = 1,
        .msg_control = control.bytes,
        .msg_controllen = sizeof(control.bytes)
    };

    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &fd, sizeof(fd));
    return sendmsg(socket_fd, &message, 0);
}

static int recv_fd(int socket_fd)
{
    char byte;
    struct iovec data = { .iov_base = &byte, .iov_len = 1 };
    union {
        struct cmsghdr alignment;
        unsigned char bytes[CMSG_SPACE(sizeof(int))];
    } control = {0};

    struct msghdr message = {
        .msg_iov = &data,
        .msg_iovlen = 1,
        .msg_control = control.bytes,
        .msg_controllen = sizeof(control.bytes)
    };

    if (recvmsg(socket_fd, &message, 0) <= 0)
        return -1;

    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    if (!header || header->cmsg_level != SOL_SOCKET ||
        header->cmsg_type != SCM_RIGHTS ||
        header->cmsg_len < CMSG_LEN(sizeof(int))) {
        return -1;
    }

    int fd;
    memcpy(&fd, CMSG_DATA(header), sizeof(fd));
    return fd;
}

static void log_syscall(FILE *file, const struct seccomp_notif *req)
{
    unsigned int pid = req->pid;
    pid_t parent = get_parent_pid(pid);
    int syscall_number = req->data.nr;

    time_t now = time(NULL);
    struct tm *utc = gmtime(&now);
    char timestamp[64] = "";
    if (utc)
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", utc);

    if (syscall_number == SCMP_SYS(clone) ||
        syscall_number == SCMP_SYS(clone3) ||
        syscall_number == SCMP_SYS(vfork)) {
        fprintf(file,
                "{\"timestamp\":\"%s\",\"pid\":%u,\"ppid\":%d,"
                "\"intent\":\"CLONE\",\"action\":\"ALLOW\"}\n",
                timestamp, pid, parent);
    } else if (syscall_number == SCMP_SYS(openat) ||
               syscall_number == SCMP_SYS(unlinkat)) {
        const char *intent = "FILE_DELETE";

        if (syscall_number == SCMP_SYS(openat)) {
            unsigned long flags = req->data.args[2];
            unsigned long mode = flags & O_ACCMODE;
            intent = (mode == O_WRONLY || mode == O_RDWR ||
                      (flags & (O_CREAT | O_TRUNC)))
                         ? "FILE_WRITE" : "FILE_READ";
        }

        char path[256] = {0};
        if (req->data.args[1] != 0) {
            struct iovec local = { .iov_base = path, .iov_len = sizeof(path) };
            struct iovec remote = {
                .iov_base = (void *)req->data.args[1],
                .iov_len = sizeof(path)
            };
            ssize_t bytes = process_vm_readv(pid, &local, 1, &remote, 1, 0);
            if (bytes <= 0 || !memchr(path, '\0', (size_t)bytes))
                path[0] = '\0';
        }

        fprintf(file,
                "{\"timestamp\":\"%s\",\"pid\":%u,\"ppid\":%d,"
                "\"intent\":\"%s\",\"path\":",
                timestamp, pid, parent, intent);
        log_json_string(file, path);
        fputs(",\"action\":\"ALLOW\"}\n", file);
    } else if (syscall_number == SCMP_SYS(socket)) {
        unsigned long type = req->data.args[1];
        type &= ~(unsigned long)(SOCK_CLOEXEC | SOCK_NONBLOCK);

        const char *protocol = "UNKNOWN";
        if (type == SOCK_STREAM)
            protocol = "TCP (SOCK_STREAM)";
        else if (type == SOCK_DGRAM)
            protocol = "UDP (SOCK_DGRAM)";
        else if (type == SOCK_RAW)
            protocol = "RAW/ICMP";

        fprintf(file,
                "{\"timestamp\":\"%s\",\"pid\":%u,\"ppid\":%d,"
                "\"event\":\"SOCKET_CREATE\",\"protocol\":\"%s\"}\n",
                timestamp, pid, parent, protocol);
    } else if (syscall_number == SCMP_SYS(connect)) {
        struct sockaddr_in address = {0};
        char ip[INET_ADDRSTRLEN] = "";
        int port = 0;

        if (req->data.args[1] != 0 &&
            req->data.args[2] >= sizeof(address)) {
            struct iovec local = {
                .iov_base = &address, .iov_len = sizeof(address)
            };
            struct iovec remote = {
                .iov_base = (void *)req->data.args[1],
                .iov_len = sizeof(address)
            };
            ssize_t bytes = process_vm_readv(pid, &local, 1, &remote, 1, 0);
            if (bytes == (ssize_t)sizeof(address) &&
                address.sin_family == AF_INET) {
                inet_ntop(AF_INET, &address.sin_addr, ip, sizeof(ip));
                port = ntohs(address.sin_port);
            }
        }

        fprintf(file,
                "{\"timestamp\":\"%s\",\"pid\":%u,\"ppid\":%d,"
                "\"event\":\"CONNECT\",\"dest_ip\":\"%s\",\"dest_port\":%d}\n",
                timestamp, pid, parent, ip, port);
    } else if (syscall_number == SCMP_SYS(sendto) ||
               syscall_number == SCMP_SYS(send)) {
        fprintf(file,
                "{\"timestamp\":\"%s\",\"pid\":%u,\"ppid\":%d,"
                "\"event\":\"DATA_TRANSMIT\",\"payload_bytes\":%zu}\n",
                timestamp, pid, parent, (size_t)req->data.args[2]);
    }

    fflush(file);
}

int main(void)
{
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
        perror("socketpair");
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        close(sockets[0]);
        close(sockets[1]);
        return 1;
    }

    if (pid == 0) {
        close(sockets[0]);

        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
            perror("prctl");
            _exit(1);
        }

        scmp_filter_ctx filter = seccomp_init(SCMP_ACT_ALLOW);
        if (!filter) {
            perror("seccomp_init");
            _exit(1);
        }

        seccomp_rule_add(filter, SCMP_ACT_NOTIFY, SCMP_SYS(unlinkat), 0);
        seccomp_rule_add(filter, SCMP_ACT_NOTIFY, SCMP_SYS(openat), 0);
        seccomp_rule_add(filter, SCMP_ACT_NOTIFY, SCMP_SYS(clone), 0);
        seccomp_rule_add(filter, SCMP_ACT_NOTIFY, SCMP_SYS(clone3), 0);
        seccomp_rule_add(filter, SCMP_ACT_NOTIFY, SCMP_SYS(vfork), 0);
        seccomp_rule_add(filter, SCMP_ACT_NOTIFY, SCMP_SYS(socket), 0);
        seccomp_rule_add(filter, SCMP_ACT_NOTIFY, SCMP_SYS(connect), 0);
        seccomp_rule_add(filter, SCMP_ACT_NOTIFY, SCMP_SYS(sendto), 0);
        seccomp_rule_add(filter, SCMP_ACT_NOTIFY, SCMP_SYS(send), 0);

        int result = seccomp_load(filter);
        if (result < 0) {
            fprintf(stderr, "seccomp_load: %s\n", strerror(-result));
            seccomp_release(filter);
            _exit(1);
        }

        int listener = seccomp_notify_fd(filter);
        if (listener < 0 || send_fd(sockets[1], listener) < 0) {
            fprintf(stderr, "Could not send the seccomp listener to the supervisor\n");
            seccomp_release(filter);
            _exit(1);
        }
        seccomp_release(filter);
        close(listener);
        close(sockets[1]);

        char *args[] = {
            "/bin/unshare", "-p", "--map-root-user", "-f", "-U",
            "-R", "root/", "/bin/bash", NULL
        };
        execvp(args[0], args);
        perror("execvp");
        _exit(1);
    }

    close(sockets[1]);
    int listener = recv_fd(sockets[0]);
    close(sockets[0]);
    if (listener < 0) {
        fprintf(stderr, "Could not receive the seccomp listener\n");
        waitpid(pid, NULL, 0);
        return 1;
    }

    FILE *file = fopen("depsandbox.log", "a");
    if (!file) {
        perror("fopen depsandbox.log");
        close(listener);
        waitpid(pid, NULL, 0);
        return 1;
    }

    fprintf(file, "[depsandbox_log] [INFO] Supervisor active for child PID %d\n", pid);
    fflush(file);

    for (;;) {
        struct seccomp_notif request = {0};
        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &request) < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        log_syscall(file, &request);

        struct seccomp_notif_resp response = {
            .id = request.id,
            .flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE
        };
        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &response) < 0) {
            if (errno == ENOENT)
                continue;
            break;
        }
    }

    close(listener);
    int status;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            perror("waitpid");
            fclose(file);
            return 1;
        }
    }

    fputs("[depsandbox_log] [INFO] Child process exited\n", file);
    fclose(file);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}