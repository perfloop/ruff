/*
 * Sample futex waiters in a child workspace-diagnostic workload.
 *
 * This probe intentionally lives outside the Rust server implementation. It
 * traces a child process with ptrace, sampling register state only while the
 * standalone driver says its workspace/diagnostic request is active. That
 * avoids target-source timing instrumentation while still exposing whether
 * multiple worker threads are blocked in the same futex wait.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <linux/futex.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(__x86_64__)
#error "workspace_diagnostic_futex_probe currently supports x86_64 Linux only"
#endif

#define MAX_THREADS 256
#define MAX_ADDRESSES 1024

enum marker_state {
    MARKER_WAITING,
    MARKER_ACTIVE,
    MARKER_COMPLETE,
};

struct tracee {
    pid_t tid;
    bool active;
};

struct address_stat {
    unsigned long long address;
    unsigned long long samples;
};

struct statistics {
    unsigned long long wait_samples;
    unsigned long long max_address_samples;
    unsigned int max_same_address_waiters;
    struct address_stat addresses[MAX_ADDRESSES];
    size_t address_count;
};

struct sampled_address {
    unsigned long long address;
    unsigned int waiters;
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
            tracees[index].active = true;
            tracees[index].tid = tid;
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

static void resume_tracee(pid_t tid, int signal_to_deliver) {
    if (ptrace(PTRACE_CONT, tid, 0, signal_to_deliver) == -1 && errno != ESRCH) {
        fail("failed to resume traced thread");
    }
}

static void record_address(struct statistics *statistics, unsigned long long address) {
    for (size_t index = 0; index < statistics->address_count; index++) {
        if (statistics->addresses[index].address == address) {
            statistics->addresses[index].samples++;
            if (statistics->addresses[index].samples > statistics->max_address_samples) {
                statistics->max_address_samples = statistics->addresses[index].samples;
            }
            return;
        }
    }

    if (statistics->address_count == MAX_ADDRESSES) {
        fprintf(stderr, "workspace_diagnostic_futex_probe: exceeded %d futex addresses\n", MAX_ADDRESSES);
        exit(EXIT_FAILURE);
    }

    statistics->addresses[statistics->address_count].address = address;
    statistics->addresses[statistics->address_count].samples = 1;
    statistics->address_count++;
    if (statistics->max_address_samples == 0) {
        statistics->max_address_samples = 1;
    }
}

static enum marker_state marker_state(const char *path) {
    FILE *marker = fopen(path, "r");
    if (marker == NULL) {
        return MARKER_WAITING;
    }

    char value[32] = {0};
    const bool read_value = fgets(value, sizeof(value), marker) != NULL;
    fclose(marker);
    if (!read_value) {
        return MARKER_WAITING;
    }
    if (strncmp(value, "active", strlen("active")) == 0) {
        return MARKER_ACTIVE;
    }
    if (strncmp(value, "complete", strlen("complete")) == 0) {
        return MARKER_COMPLETE;
    }
    return MARKER_WAITING;
}

static void process_stop(pid_t tid, int status) {
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        remove_tracee(tid);
        return;
    }
    if (!WIFSTOPPED(status)) {
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
        resume_tracee(tid, 0);
        return;
    }

    if (signal_number == SIGTRAP || signal_number == SIGSTOP) {
        resume_tracee(tid, 0);
    } else {
        resume_tracee(tid, signal_number);
    }
}

static void drain_events(void) {
    for (;;) {
        int status = 0;
        const pid_t tid = waitpid(-1, &status, __WALL | WNOHANG);
        if (tid == 0) {
            return;
        }
        if (tid == -1) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == ECHILD) {
                return;
            }
            fail("failed while draining ptrace events");
        }
        process_stop(tid, status);
    }
}

static bool futex_wait_address(pid_t tid, unsigned long long *address) {
    if (ptrace(PTRACE_INTERRUPT, tid, 0, 0) == -1) {
        if (errno == ESRCH) {
            remove_tracee(tid);
            return false;
        }
        fail("failed to interrupt traced thread");
    }

    int status = 0;
    for (;;) {
        const pid_t waited = waitpid(tid, &status, __WALL);
        if (waited == -1) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == ECHILD || errno == ESRCH) {
                remove_tracee(tid);
                return false;
            }
            fail("failed to wait for interrupted thread");
        }
        break;
    }

    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        remove_tracee(tid);
        return false;
    }
    if (!WIFSTOPPED(status)) {
        return false;
    }

    const int signal_number = WSTOPSIG(status);
    const unsigned int event = (unsigned int)status >> 16;
    if (signal_number != SIGTRAP || event != PTRACE_EVENT_STOP) {
        process_stop(tid, status);
        return false;
    }

    struct user_regs_struct registers;
    if (ptrace(PTRACE_GETREGS, tid, 0, &registers) == -1) {
        if (errno == ESRCH) {
            remove_tracee(tid);
            return false;
        }
        fail("failed to read traced thread registers");
    }

    const unsigned int operation = (unsigned int)registers.rsi & FUTEX_CMD_MASK;
    const bool is_wait = registers.orig_rax == SYS_futex &&
                         (operation == FUTEX_WAIT || operation == FUTEX_WAIT_BITSET ||
                          operation == FUTEX_WAIT_REQUEUE_PI);
    if (is_wait) {
        *address = (unsigned long long)registers.rdi;
    }
    resume_tracee(tid, 0);
    return is_wait;
}

static void sample_waiters(struct statistics *statistics) {
    struct sampled_address addresses[MAX_THREADS] = {0};
    size_t address_count = 0;

    for (size_t index = 0; index < MAX_THREADS; index++) {
        if (!tracees[index].active) {
            continue;
        }

        unsigned long long address = 0;
        if (!futex_wait_address(tracees[index].tid, &address)) {
            continue;
        }

        statistics->wait_samples++;
        record_address(statistics, address);

        size_t address_index = 0;
        while (address_index < address_count && addresses[address_index].address != address) {
            address_index++;
        }
        if (address_index == address_count) {
            addresses[address_count].address = address;
            addresses[address_count].waiters = 0;
            address_count++;
        }
        addresses[address_index].waiters++;
        if (addresses[address_index].waiters > statistics->max_same_address_waiters) {
            statistics->max_same_address_waiters = addresses[address_index].waiters;
        }
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
        execvp(child_argv[0], child_argv);
        perror("workspace_diagnostic_futex_probe: failed to exec workload");
        _exit(EXIT_FAILURE);
    }

    close(start_pipe[0]);
    if (ptrace(PTRACE_SEIZE, child, 0, PTRACE_O_TRACECLONE | PTRACE_O_EXITKILL) == -1) {
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
    resume_tracee(child, 0);
    return child;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <workload-binary> <workload-argument> [args...]\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *status_path = getenv("PERFLOOP_PROBE_STATUS_FILE");
    if (status_path == NULL || status_path[0] == '\0') {
        fprintf(stderr, "workspace_diagnostic_futex_probe: PERFLOOP_PROBE_STATUS_FILE is required\n");
        return EXIT_FAILURE;
    }

    const pid_t child = start_child(&argv[1]);
    struct statistics statistics = {0};
    bool saw_active = false;
    bool saw_complete = false;

    while (active_tracees() > 0) {
        drain_events();
        const enum marker_state state = marker_state(status_path);
        if (state == MARKER_ACTIVE) {
            saw_active = true;
            sample_waiters(&statistics);
        } else if (state == MARKER_COMPLETE) {
            saw_complete = true;
        }
        usleep(500);
    }

    (void)child;
    if (!saw_active || !saw_complete) {
        fprintf(stderr, "workspace_diagnostic_futex_probe: workload did not expose an active and complete marker\n");
        return EXIT_FAILURE;
    }

    printf("futex_wait_samples=%llu\n", statistics.wait_samples);
    printf("futex_wait_addresses=%zu\n", statistics.address_count);
    printf("futex_wait_max_address_samples=%llu\n", statistics.max_address_samples);
    printf("futex_wait_max_same_address=%u\n", statistics.max_same_address_waiters);
    return EXIT_SUCCESS;
}
