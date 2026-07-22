/*
 * Trace completed futex waits in a child workspace-diagnostic workload.
 *
 * The standalone driver synchronizes the measured interval with this helper by
 * sending an active/complete datagram and waiting for the corresponding ack.
 * The child installs a seccomp filter that produces ptrace events only for
 * futex syscalls. A counted wait attempt is therefore a kernel futex-wait
 * entry from the exact acknowledged request interval, not a polling observation.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <linux/filter.h>
#include <linux/futex.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(__x86_64__)
#error "workspace_diagnostic_futex_probe currently supports x86_64 Linux only"
#endif

#define MAX_THREADS 256
#define MAX_ADDRESSES 1024

struct tracee {
    pid_t tid;
    bool active;
};

struct address_stat {
    unsigned long long address;
    unsigned long long attempts;
};

struct statistics {
    unsigned long long futex_wait_attempts;
    unsigned long long max_address_attempts;
    struct address_stat addresses[MAX_ADDRESSES];
    size_t address_count;
};

struct control_state {
    bool interval_active;
    bool interval_started;
    bool interval_complete;
    const char *ack_path;
};

static struct tracee tracees[MAX_THREADS];

static void fail(const char *message) {
    fprintf(stderr, "workspace_diagnostic_futex_probe: %s: %s\n", message, strerror(errno));
    exit(EXIT_FAILURE);
}

static struct tracee *find_tracee(pid_t tid) {
    for (size_t index = 0; index < MAX_THREADS; index++) {
        if (tracees[index].active && tracees[index].tid == tid) {
            return &tracees[index];
        }
    }
    return NULL;
}

static void add_tracee(pid_t tid) {
    if (find_tracee(tid) != NULL) {
        return;
    }

    for (size_t index = 0; index < MAX_THREADS; index++) {
        if (!tracees[index].active) {
            tracees[index] = (struct tracee){
                .tid = tid,
                .active = true,
            };
            return;
        }
    }

    fprintf(stderr, "workspace_diagnostic_futex_probe: exceeded %d traced threads\n", MAX_THREADS);
    exit(EXIT_FAILURE);
}

static void remove_tracee(pid_t tid) {
    struct tracee *tracee = find_tracee(tid);
    if (tracee != NULL) {
        tracee->active = false;
    }
}

static size_t active_tracees(void) {
    size_t count = 0;
    for (size_t index = 0; index < MAX_THREADS; index++) {
        if (tracees[index].active) {
            count++;
        }
    }
    return count;
}

static void resume_continue(pid_t tid, int signal_to_deliver) {
    if (ptrace(PTRACE_CONT, tid, 0, signal_to_deliver) == -1 && errno != ESRCH) {
        fail("failed to resume traced thread");
    }
}

static struct address_stat *address_stat_for(struct statistics *statistics,
                                              unsigned long long address) {
    for (size_t index = 0; index < statistics->address_count; index++) {
        if (statistics->addresses[index].address == address) {
            return &statistics->addresses[index];
        }
    }

    if (statistics->address_count == MAX_ADDRESSES) {
        fprintf(stderr, "workspace_diagnostic_futex_probe: exceeded %d futex addresses\n", MAX_ADDRESSES);
        exit(EXIT_FAILURE);
    }

    struct address_stat *statistic = &statistics->addresses[statistics->address_count++];
    *statistic = (struct address_stat){
        .address = address,
    };
    return statistic;
}

static void record_wait_attempt(struct statistics *statistics, unsigned long long address) {
    statistics->futex_wait_attempts++;
    struct address_stat *address_statistic = address_stat_for(statistics, address);
    address_statistic->attempts++;
    if (address_statistic->attempts > statistics->max_address_attempts) {
        statistics->max_address_attempts = address_statistic->attempts;
    }
}

static void sockaddr_from_path(struct sockaddr_un *address, const char *path) {
    if (strlen(path) >= sizeof(address->sun_path)) {
        errno = ENAMETOOLONG;
        fail("Unix socket path is too long");
    }
    *address = (struct sockaddr_un){0};
    address->sun_family = AF_UNIX;
    memcpy(address->sun_path, path, strlen(path) + 1);
}

static int create_control_socket(const char *path) {
    const int socket_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (socket_fd == -1) {
        fail("failed to create control socket");
    }

    struct sockaddr_un address;
    sockaddr_from_path(&address, path);
    if (unlink(path) == -1 && errno != ENOENT) {
        fail("failed to remove stale control socket");
    }
    if (bind(socket_fd, (const struct sockaddr *)&address, sizeof(address)) == -1) {
        fail("failed to bind control socket");
    }
    return socket_fd;
}

static void acknowledge_marker(const char *ack_path, unsigned char marker) {
    const int socket_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (socket_fd == -1) {
        fail("failed to create acknowledgement socket");
    }

    struct sockaddr_un address;
    sockaddr_from_path(&address, ack_path);
    if (sendto(socket_fd, &marker, 1, 0, (const struct sockaddr *)&address, sizeof(address)) != 1) {
        close(socket_fd);
        fail("failed to acknowledge control marker");
    }
    close(socket_fd);
}

static void drain_control(int socket_fd, struct control_state *control) {
    for (;;) {
        unsigned char message[32];
        const ssize_t received = recv(socket_fd, message, sizeof(message), MSG_DONTWAIT);
        if (received == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            fail("failed to receive control marker");
        }

        for (ssize_t index = 0; index < received; index++) {
            switch (message[index]) {
            case 'A':
                if (control->interval_started || control->interval_complete) {
                    errno = EPROTO;
                    fail("received an invalid active marker");
                }
                control->interval_started = true;
                control->interval_active = true;
                acknowledge_marker(control->ack_path, 'A');
                break;
            case 'C':
                if (!control->interval_started || control->interval_complete) {
                    errno = EPROTO;
                    fail("received an invalid complete marker");
                }
                control->interval_active = false;
                control->interval_complete = true;
                acknowledge_marker(control->ack_path, 'C');
                break;
            default:
                errno = EPROTO;
                fail("received an unknown control marker");
            }
        }
    }
}

static bool futex_wait_address(const struct user_regs_struct *registers,
                               unsigned long long *address) {
    const unsigned int operation = (unsigned int)registers->rsi & FUTEX_CMD_MASK;
    const bool is_wait = registers->orig_rax == SYS_futex &&
                         (operation == FUTEX_WAIT || operation == FUTEX_WAIT_BITSET ||
                          operation == FUTEX_WAIT_REQUEUE_PI);
    if (is_wait) {
        *address = (unsigned long long)registers->rdi;
    }
    return is_wait;
}

static void observe_seccomp_stop(struct tracee *tracee, const struct control_state *control,
                                 struct statistics *statistics) {
    struct user_regs_struct registers;
    if (ptrace(PTRACE_GETREGS, tracee->tid, 0, &registers) == -1) {
        if (errno == ESRCH) {
            remove_tracee(tracee->tid);
            return;
        }
        fail("failed to read futex syscall registers");
    }

    unsigned long long address = 0;
    if (control->interval_active && futex_wait_address(&registers, &address)) {
        record_wait_attempt(statistics, address);
    }
    resume_continue(tracee->tid, 0);
}

static void process_stop(pid_t tid, int status, int socket_fd, struct control_state *control,
                         struct statistics *statistics) {
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        remove_tracee(tid);
        return;
    }
    if (!WIFSTOPPED(status)) {
        return;
    }

    drain_control(socket_fd, control);
    struct tracee *tracee = find_tracee(tid);
    if (tracee == NULL) {
        return;
    }

    const int signal_number = WSTOPSIG(status);
    const unsigned int event = (unsigned int)status >> 16;
    if (signal_number == SIGTRAP && event == PTRACE_EVENT_CLONE) {
        unsigned long child_tid = 0;
        if (ptrace(PTRACE_GETEVENTMSG, tid, 0, &child_tid) == -1) {
            fail("failed to read cloned thread id");
        }
        add_tracee((pid_t)child_tid);
        resume_continue(tid, 0);
        return;
    }

    if (signal_number == SIGTRAP && event == PTRACE_EVENT_SECCOMP) {
        observe_seccomp_stop(tracee, control, statistics);
        return;
    }

    if (signal_number == SIGTRAP || signal_number == SIGSTOP) {
        resume_continue(tid, 0);
    } else {
        resume_continue(tid, signal_number);
    }
}

static void install_futex_trace_filter(void) {
    const struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        /* Skip the futex-operation filter unless this is SYS_futex. */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_futex, 0, 8),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, FUTEX_CMD_MASK),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FUTEX_WAIT, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FUTEX_WAIT_BITSET, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FUTEX_WAIT_REQUEUE_PI, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    const struct sock_fprog program = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = (struct sock_filter *)filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 ||
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == -1) {
        perror("workspace_diagnostic_futex_probe: failed to install seccomp filter");
        _exit(EXIT_FAILURE);
    }
}

static pid_t start_child(char *const child_argv[]) {
    int start_pipe[2];
    if (pipe(start_pipe) == -1) {
        fail("failed to create startup pipe");
    }

    const pid_t child = fork();
    if (child == -1) {
        fail("failed to fork workload child");
    }
    if (child == 0) {
        close(start_pipe[1]);
        char start = 0;
        if (read(start_pipe[0], &start, 1) != 1) {
            _exit(EXIT_FAILURE);
        }
        close(start_pipe[0]);
        install_futex_trace_filter();
        execvp(child_argv[0], child_argv);
        perror("workspace_diagnostic_futex_probe: failed to exec workload");
        _exit(EXIT_FAILURE);
    }

    close(start_pipe[0]);
    if (ptrace(PTRACE_SEIZE, child, 0,
               PTRACE_O_TRACECLONE | PTRACE_O_TRACESECCOMP | PTRACE_O_EXITKILL) == -1) {
        fail("failed to seize workload child");
    }
    if (ptrace(PTRACE_INTERRUPT, child, 0, 0) == -1) {
        fail("failed to interrupt workload child for setup");
    }

    int status = 0;
    if (waitpid(child, &status, __WALL) != child || !WIFSTOPPED(status)) {
        fail("failed to observe initial workload stop");
    }
    add_tracee(child);

    if (write(start_pipe[1], "s", 1) != 1) {
        fail("failed to release workload child");
    }
    close(start_pipe[1]);
    resume_continue(child, 0);
    return child;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <workload-binary> <workload-argument> [args...]\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *socket_path = getenv("PERFLOOP_PROBE_CONTROL_SOCKET");
    const char *ack_path = getenv("PERFLOOP_PROBE_ACK_SOCKET");
    if (socket_path == NULL || socket_path[0] == '\0' || ack_path == NULL || ack_path[0] == '\0') {
        fprintf(stderr, "workspace_diagnostic_futex_probe: control and acknowledgement sockets are required\n");
        return EXIT_FAILURE;
    }

    const int socket_fd = create_control_socket(socket_path);
    const pid_t child = start_child(&argv[1]);
    struct control_state control = {
        .ack_path = ack_path,
    };
    struct statistics statistics = {0};

    while (active_tracees() > 0) {
        drain_control(socket_fd, &control);

        int status = 0;
        const pid_t tid = waitpid(-1, &status, __WALL | WNOHANG);
        if (tid > 0) {
            process_stop(tid, status, socket_fd, &control, &statistics);
            continue;
        }
        if (tid == -1 && errno != ECHILD && errno != EINTR) {
            fail("failed while tracing workload");
        }
        if (tid == -1 && errno == ECHILD) {
            break;
        }

        struct pollfd control_poll = {
            .fd = socket_fd,
            .events = POLLIN,
        };
        if (poll(&control_poll, 1, 20) == -1 && errno != EINTR) {
            fail("failed while waiting for a control marker");
        }
    }

    (void)child;
    close(socket_fd);
    if (unlink(socket_path) == -1 && errno != ENOENT) {
        fail("failed to remove control socket");
    }
    if (!control.interval_started || !control.interval_complete) {
        errno = EPROTO;
        fail("workload did not complete the measured control interval");
    }

    printf("futex_wait_attempts=%llu\n", statistics.futex_wait_attempts);
    printf("futex_wait_addresses=%zu\n", statistics.address_count);
    printf("futex_wait_max_address_attempts=%llu\n", statistics.max_address_attempts);
    return EXIT_SUCCESS;
}
