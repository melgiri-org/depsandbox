#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <seccomp.h>
#include <time.h>

pid_t get_parent_pid(pid_t target_pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", target_pid);
    
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[128];
    pid_t ppid = -1;

    // Read through the status file line by line looking for "PPid:"
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "PPid:", 5) == 0) {
            sscanf(line + 5, "%d", &ppid);
            break;
        }
    }
    fclose(f);
    return ppid;
}

// Helper function to send a file descriptor over a UNIX domain socket
int send_fd(int socket, int fd) {
    struct msghdr msg = {0};
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(sizeof(int))] = {0};
    char dummy = ' ';
    struct iovec io = { &dummy, 1 };

    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *((int *)CMSG_DATA(cmsg)) = fd;

    return sendmsg(socket, &msg, 0);
}

// Helper function to receive a file descriptor over a UNIX domain socket
int recv_fd(int socket) {
    struct msghdr msg = {0};
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(sizeof(int))] = {0};
    char dummy;
    struct iovec io = { &dummy, 1 };

    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    if (recvmsg(socket, &msg, 0) < 0) return -1;

    cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == NULL || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) return -1;

    return *((int *)CMSG_DATA(cmsg));
}

int main() {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        perror("socketpair");
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        // ==================== CHILD PROCESS (Sandbox) ====================
        close(sv[0]); // Close parent socket end

        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
            perror("prctl(NO_NEW_PRIVS)");
            exit(1);
        }

        // Initialize filter context (Default allow)
        scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
        if (!ctx) {
            perror("seccomp_init");
            exit(1);
        }

        // Add rules to intercept unlink and unlinkat via User Notifications
        seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(unlinkat), 0);
		seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(openat), 0);
		seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(clone), 0);
		seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(clone3), 0);
		seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(vfork), 0);

        if (seccomp_load(ctx) < 0) {
            perror("seccomp_load");
            seccomp_release(ctx);
            exit(1);
        }

        // Export the kernel notification file descriptor
        int notif_fd = seccomp_notify_fd(ctx);
        seccomp_release(ctx);

        if (notif_fd < 0) {
            perror("seccomp_export_notif_fd");
            exit(1);
        }

        // Send notif_fd to the parent supervisor process
        if (send_fd(sv[1], notif_fd) < 0) {
            perror("send_fd");
            close(notif_fd);
            exit(1);
        }
        close(notif_fd);
        close(sv[1]);

        // Launch target shell / environment
        char *args[] = {"/bin/unshare", "-U" ,"--net", "-R" ,"root/" ,"/bin/bash", NULL};
        execvp(args[0], args);
        perror("execvp");
        exit(1);

    } else {
        // ==================== PARENT PROCESS (Supervisor) ====================
        close(sv[1]); // Close child socket end

        // Receive the notification file descriptor from the child
        int notif_fd = recv_fd(sv[0]);
        close(sv[0]);

        if (notif_fd < 0) {
            perror("recv_fd failed");
            waitpid(pid, NULL, 0);
            return 1;
        }

        // Open local telemetry log file
        FILE *log_file = fopen("depsandbox.log", "a");
        if (!log_file) {
            perror("fopen depsandbox.log");
            close(notif_fd);
            return 1;
        }

        fprintf(log_file, "[depsandbox_log] [INFO] Supervisor active for child PID %d, listening for syscall notifications...\n", pid);
        fflush(log_file);

        // Supervisor Event Loop
        struct seccomp_notif req;
        struct seccomp_notif_resp resp;

        while (1) {
			memset(&req, 0, sizeof(req));
            // Wait for child syscall notification from the kerne
            if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
                if (errno == EINTR) continue;
                // If child exits, ioctl returns ENOENT or ENODEV
                break;
            }

			// Determine path argument position based on syscall number
			// unlink(pathname) -> args[0]
			// unlinkat(dirfd, pathname, flags) -> args[1]
			unsigned long path_ptr = 0;
			unsigned long flags = 0;

			printf("%d\n", req.data.nr);

			time_t now = time(NULL);
			struct tm *t = gmtime(&now);
			char timestamp[64];
			strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", t);


			if (req.data.nr != SCMP_SYS(clone) || req.data.nr != SCMP_SYS(vfork) || req.data.nr != SCMP_SYS(clone3)){
				if (req.data.nr == SCMP_SYS(unlinkat)) {
					path_ptr = req.data.args[1];
				} else if (req.data.nr == SCMP_SYS(openat)) {
					path_ptr = req.data.args[1];
					flags = req.data.args[2];
				}

				char path_buf[256] = {0};
				if (path_ptr != 0) {
					struct iovec local_iov = { .iov_base = path_buf, .iov_len = sizeof(path_buf) - 1 };
					struct iovec remote_iov = { .iov_base = (void *)path_ptr, .iov_len = sizeof(path_buf) - 1 };
					process_vm_readv(req.pid, &local_iov, 1, &remote_iov, 1, 0);
				}


				// Determine if intent is Read or Write based on open flags
				// (O_ACCMODE mask extracts O_RDONLY (0), O_WRONLY (1), or O_RDWR (2))
				int access_mode = flags & O_ACCMODE;
				const char *intent = "UNKNOWN";
				if (access_mode == O_RDONLY) {
					intent = "FILE_READ";
				} else if (access_mode == O_WRONLY || access_mode == O_RDWR || (flags & O_CREAT)) {
					intent = "FILE_WRITE";
				}
				// Log structured telemetry (matching Section 2.6 spec)
				fprintf(log_file, "{\"timestamp\": \"%s\", \"pid\": %d, \"intent\": \"%s\", \"path\": \"%s\", \"action\": \"ALLOW\"}, \"ppid\":%u}\n",
						timestamp, req.pid, intent, path_buf, get_parent_pid(req.pid));
				fflush(log_file);
			}  else {
				fprintf(log_file, "{\"timestamp\": \"%s\", \"pid\": %d, \"intent\": \"CLONE\", \"action\": \"ALLOW\", \"ppid\":%u}\n",
						timestamp, req.pid, get_parent_pid(req.pid));
				fflush(log_file);
			}


			// Prepare response: allow the syscall to proceed normally
			memset(&resp, 0, sizeof(resp));
			resp.id = req.id;
			resp.val = 0; // Return 0 (success)
			resp.error = 0;
			resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE; // Let kernel execute the call

			if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0) {
				// If child died concurrently, send might fail
				if (errno == ENOENT) continue;
				break;
			}
		}

        // Clean up
        waitpid(pid, NULL, 0);
        fprintf(log_file, "[depsandbox_log] [INFO] Child process exited. Supervisor shutting down.\n");
        fclose(log_file);
        close(notif_fd);
		// TODO: Analysis
    }

    return 0;
}
