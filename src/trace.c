#include "sysgaze/trace.h"

#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/audit.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "sysgaze/decoder.h"
#include "sysgaze/output.h"
#include "sysgaze/stats.h"
#include "sysgaze/syscall_catalog.h"
#include "sysgaze/tracee.h"
#include "sysgaze/tracee_table.h"

#if !defined(__linux__) || !defined(__x86_64__)
#error "Sysgaze currently supports native x86-64 Linux only"
#endif

#define SG_RESTART_SYS 512
#define SG_RESTART_NOINTR 513
#define SG_RESTART_NOHAND 514
#define SG_RESTART_RESTARTBLOCK 516

struct trace_context {
    const struct sg_config *config;
    struct sg_tracee_table tracees;
    struct sg_decoder decoder;
    struct sg_output output;
    struct sg_stats stats;
    FILE *stream;
    pid_t root_tid;
    int root_status;
    bool root_status_known;
    bool show_tids;
    uint64_t event_count;
};

static volatile sig_atomic_t shutdown_signal;
static uint64_t ptrace_call_count;

static void set_error(char *error, size_t error_size, const char *format, ...);

static long measured_ptrace(enum __ptrace_request request, pid_t pid,
                            void *address, void *data)
{
    ++ptrace_call_count;
    return ptrace(request, pid, address, data);
}

static bool write_benchmark_metrics(const struct trace_context *context,
                                    char *error, size_t error_size)
{
    const char *text = getenv("SYSGAZE_BENCHMARK_FD");
    char *end = NULL;
    long descriptor;

    if (text == NULL || *text == '\0') {
        return true;
    }
    errno = 0;
    descriptor = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || descriptor < 0 ||
        descriptor > INT_MAX) {
        set_error(error, error_size,
                  "invalid internal benchmark descriptor");
        return false;
    }
    if (dprintf((int)descriptor,
                "events=%" PRIu64 " ptrace_calls=%" PRIu64 "\n",
                context->event_count, ptrace_call_count) < 0) {
        set_error(error, error_size, "cannot write benchmark metrics: %s",
                  strerror(errno));
        return false;
    }
    return true;
}

static void set_error(char *error, size_t error_size, const char *format, ...)
{
    va_list arguments;

    if (error == NULL || error_size == 0U) {
        return;
    }
    va_start(arguments, format);
    (void)vsnprintf(error, error_size, format, arguments);
    va_end(arguments);
}

static bool validate_runtime_options(const struct sg_config *config,
                                     char *error, size_t error_size)
{
    if (config->format == SG_FORMAT_JSON && !config->summary) {
        set_error(error, error_size,
                  "JSON event output is not supported; use NDJSON");
        return false;
    }
    if (config->seccomp_bpf) {
        set_error(error, error_size,
                  "seccomp-BPF mode is not implemented until Stage 8");
        return false;
    }
    return true;
}

static FILE *open_output(const char *path, char *error, size_t error_size)
{
    int descriptor;
    FILE *stream;

    if (path == NULL) {
        return stderr;
    }
    descriptor = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (descriptor < 0) {
        set_error(error, error_size, "cannot open output '%s': %s", path,
                  strerror(errno));
        return NULL;
    }
    stream = fdopen(descriptor, "w");
    if (stream == NULL) {
        int saved_errno = errno;
        (void)close(descriptor);
        set_error(error, error_size, "cannot create output stream '%s': %s",
                  path, strerror(saved_errno));
        return NULL;
    }
    return stream;
}

static void child_fail(const char *operation, const char *subject)
{
    int saved_errno = errno;

    if (subject == NULL) {
        (void)dprintf(STDERR_FILENO, "sysgaze: child %s failed: %s\n",
                      operation, strerror(saved_errno));
    } else {
        (void)dprintf(STDERR_FILENO, "sysgaze: cannot execute '%s': %s\n",
                      subject, strerror(saved_errno));
    }
    _exit(127);
}

static pid_t launch_tracee(char *const command_argv[], char *error,
                           size_t error_size)
{
    pid_t child = fork();

    if (child < 0) {
        set_error(error, error_size, "fork failed: %s", strerror(errno));
        return -1;
    }
    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            child_fail("PTRACE_TRACEME", NULL);
        }
        if (raise(SIGSTOP) != 0) {
            child_fail("synchronization stop", NULL);
        }
        execvp(command_argv[0], command_argv);
        child_fail("execvp", command_argv[0]);
    }
    return child;
}

static bool wait_for_initial_stop(pid_t child, char *error, size_t error_size)
{
    int status;
    pid_t waited;

    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited < 0) {
        set_error(error, error_size, "initial waitpid failed: %s",
                  strerror(errno));
        return false;
    }
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
        set_error(error, error_size,
                  "tracee did not enter the synchronization stop");
        return false;
    }
    return true;
}

static unsigned long ptrace_options(const struct sg_config *config,
                                    bool launched)
{
    unsigned long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC;

    if (launched) {
        options |= PTRACE_O_EXITKILL;
    }
    if (config->follow) {
        options |= PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                   PTRACE_O_TRACECLONE;
    }
    return options;
}

static bool install_ptrace_options(pid_t child,
                                   const struct sg_config *config,
                                   char *error, size_t error_size)
{
    unsigned long options = ptrace_options(config, true);

    if (measured_ptrace(PTRACE_SETOPTIONS, child, NULL,
                        (void *)(uintptr_t)options) < 0) {
        set_error(error, error_size, "PTRACE_SETOPTIONS failed: %s",
                  strerror(errno));
        return false;
    }
    return true;
}

static bool resume_tracee(pid_t tid, int signal_number,
                          char *error, size_t error_size)
{
    if (measured_ptrace(PTRACE_SYSCALL, tid, NULL,
                        (void *)(uintptr_t)(unsigned int)signal_number) < 0) {
        set_error(error, error_size, "PTRACE_SYSCALL for %ld failed: %s",
                  (long)tid, strerror(errno));
        return false;
    }
    return true;
}

static bool listen_tracee(pid_t tid, char *error, size_t error_size)
{
    if (measured_ptrace(PTRACE_LISTEN, tid, NULL, NULL) < 0) {
        set_error(error, error_size, "PTRACE_LISTEN for %ld failed: %s",
                  (long)tid, strerror(errno));
        return false;
    }
    return true;
}

static bool is_stopping_signal(int signal_number)
{
    return signal_number == SIGSTOP || signal_number == SIGTSTP ||
           signal_number == SIGTTIN || signal_number == SIGTTOU;
}

static bool is_restart_result(int64_t result)
{
    return result == -SG_RESTART_SYS || result == -SG_RESTART_NOINTR ||
           result == -SG_RESTART_NOHAND ||
           result == -SG_RESTART_RESTARTBLOCK;
}

static bool selected(const struct trace_context *context, long number)
{
    return !context->config->filter.active ||
           sg_filter_contains(&context->config->filter, number);
}

static bool read_tracee_memory(void *opaque, pid_t tid, uintptr_t address,
                               void *destination, size_t length,
                               size_t *bytes_read)
{
    struct iovec local = {.iov_base = destination, .iov_len = length};
    struct iovec remote = {
        .iov_base = (void *)address,
        .iov_len = length
    };
    ssize_t amount;

    (void)opaque;
    *bytes_read = 0U;
    if (length == 0U) {
        return true;
    }
    amount = process_vm_readv(tid, &local, 1UL, &remote, 1UL, 0UL);
    if (amount < 0) {
        return false;
    }
    *bytes_read = (size_t)amount;
    return true;
}

static void move_syscall_event(struct sg_syscall_event *destination,
                               struct sg_syscall_event *source)
{
    *destination = *source;
    memset(source, 0, sizeof(*source));
}

static bool emit_event(struct trace_context *context,
                       const struct sg_event *event,
                       char *error, size_t error_size)
{
    return sg_output_write_event(&context->output, event, error, error_size);
}

static bool stamp_event(struct sg_event *event, char *error,
                        size_t error_size)
{
    if (clock_gettime(CLOCK_MONOTONIC, &event->observed_at) < 0) {
        set_error(error, error_size, "clock_gettime failed: %s",
                  strerror(errno));
        return false;
    }
    return true;
}

static bool flush_unfinished_syscalls(struct trace_context *context,
                                      pid_t except_tid,
                                      char *error, size_t error_size)
{
    size_t index;

    if (context->config->summary) {
        return true;
    }

    for (index = 0U; index < context->tracees.capacity; ++index) {
        struct sg_tracee *tracee;
        struct sg_syscall_event *syscall = NULL;
        struct sg_event event = {0};

        if (context->tracees.slots[index].state != SG_TRACEE_SLOT_OCCUPIED) {
            continue;
        }
        tracee = &context->tracees.slots[index].tracee;
        if (tracee->tid == except_tid) {
            continue;
        }
        if (tracee->has_pending_syscall) {
            syscall = &tracee->pending_syscall;
        } else if (tracee->has_interrupted_syscall) {
            syscall = &tracee->interrupted_syscall;
        }
        if (syscall == NULL || !selected(context, syscall->number)) {
            continue;
        }
        event.kind = SG_EVENT_SYSCALL;
        event.tid = tracee->tid;
        event.tgid = tracee->tgid;
        event.observed_at = syscall->entered_at;
        event.data.syscall = *syscall;
        event.data.syscall.completed = false;
        if (!emit_event(context, &event, error, error_size)) {
            return false;
        }
    }
    return true;
}

static bool write_syscall(struct trace_context *context,
                          const struct sg_tracee *tracee,
                          const struct sg_syscall_event *event,
                          char *error, size_t error_size)
{
    struct sg_event output_event = {0};

    if (!selected(context, event->number)) {
        return true;
    }
    ++context->event_count;
    if (context->config->summary) {
        if (!sg_stats_record(&context->stats, event)) {
            set_error(error, error_size,
                      "cannot aggregate statistics for syscall %ld",
                      event->number);
            return false;
        }
        return true;
    }
    if (!flush_unfinished_syscalls(context, tracee->tid, error, error_size)) {
        return false;
    }
    output_event.kind = SG_EVENT_SYSCALL;
    output_event.tid = tracee->tid;
    output_event.tgid = tracee->tgid;
    output_event.observed_at = event->exited_at;
    output_event.data.syscall = *event;
    return emit_event(context, &output_event, error, error_size);
}

static bool write_signal(struct trace_context *context,
                         const struct sg_tracee *tracee,
                         const siginfo_t *signal_info,
                         char *error, size_t error_size)
{
    struct sg_event event = {0};
    int signal_number = signal_info->si_signo;

    if (!flush_unfinished_syscalls(context, -1, error, error_size)) {
        return false;
    }
    event.kind = SG_EVENT_SIGNAL;
    event.tid = tracee->tid;
    event.tgid = tracee->tgid;
    if (!stamp_event(&event, error, error_size)) {
        return false;
    }
    event.data.signal.signal_number = signal_number;
    event.data.signal.signal_code = signal_info->si_code;
    if (signal_info->si_code > 0 &&
        (signal_number == SIGILL || signal_number == SIGFPE ||
         signal_number == SIGSEGV || signal_number == SIGBUS ||
         signal_number == SIGTRAP)) {
        event.data.signal.fault_address =
            (uintptr_t)signal_info->si_addr;
    }
    return emit_event(context, &event, error, error_size);
}

static bool write_exit(struct trace_context *context,
                       const struct sg_tracee *tracee, int status,
                       char *error, size_t error_size)
{
    struct sg_event event = {0};

    if (!flush_unfinished_syscalls(context, -1, error, error_size)) {
        return false;
    }
    event.kind = SG_EVENT_PROCESS_EXIT;
    event.tid = tracee->tid;
    event.tgid = tracee->tgid;
    if (!stamp_event(&event, error, error_size)) {
        return false;
    }
    event.data.lifecycle.status = WIFEXITED(status) ? WEXITSTATUS(status)
                                                    : WTERMSIG(status);
    event.data.lifecycle.signaled = WIFSIGNALED(status);
    return emit_event(context, &event, error, error_size);
}

static bool begin_syscall(struct trace_context *context,
                          struct sg_tracee *tracee,
                          const struct ptrace_syscall_info *info,
                          char *error, size_t error_size)
{
    struct sg_syscall_event event = {0};
    uint64_t number = info->entry.nr;
    size_t index;

    if (number > (uint64_t)LONG_MAX) {
        set_error(error, error_size, "syscall number is outside native range");
        return false;
    }

    if (tracee->has_pending_syscall) {
        if (tracee->pending_syscall.number == SYS_execve
#ifdef SYS_execveat
            || tracee->pending_syscall.number == SYS_execveat
#endif
        ) {
            tracee->pending_syscall.result = 0;
            tracee->pending_syscall.error_number = 0;
            tracee->pending_syscall.completed = true;
            if (clock_gettime(CLOCK_MONOTONIC,
                              &tracee->pending_syscall.exited_at) < 0) {
                set_error(error, error_size, "clock_gettime failed: %s",
                          strerror(errno));
                return false;
            }
            if (!write_syscall(context, tracee, &tracee->pending_syscall, error,
                               error_size)) {
                return false;
            }
            sg_decoder_release_event(&tracee->pending_syscall);
            tracee->has_pending_syscall = false;
        } else {
            set_error(error, error_size,
                      "received syscall entry before the previous exit");
            return false;
        }
    }

    if (tracee->has_interrupted_syscall &&
        tracee->interrupted_restart_ready &&
        ((long)number == tracee->interrupted_syscall.number ||
         (long)number == SYS_restart_syscall)) {
        if (!flush_unfinished_syscalls(context, tracee->tid, error,
                                       error_size)) {
            return false;
        }
        move_syscall_event(&tracee->pending_syscall,
                           &tracee->interrupted_syscall);
        tracee->has_interrupted_syscall = false;
        tracee->interrupted_restart_ready = false;
        tracee->has_pending_syscall = true;
        tracee->phase = SG_TRACEE_IN_SYSCALL;
        return true;
    }

    if (tracee->has_interrupted_syscall &&
        tracee->interrupted_restart_ready) {
        /* The first post-sigreturn entry was not the interrupted call, so the
         * kernel exposed EINTR to user space instead of restarting it. */
        tracee->interrupted_syscall.result = -1;
        tracee->interrupted_syscall.error_number = EINTR;
        tracee->interrupted_syscall.completed = true;
        if (clock_gettime(CLOCK_MONOTONIC,
                          &tracee->interrupted_syscall.exited_at) < 0) {
            set_error(error, error_size, "clock_gettime failed: %s",
                      strerror(errno));
            return false;
        }
        if (!write_syscall(context, tracee, &tracee->interrupted_syscall,
                           error, error_size)) {
            return false;
        }
        sg_decoder_release_event(&tracee->interrupted_syscall);
        tracee->has_interrupted_syscall = false;
        tracee->interrupted_restart_ready = false;
    }

    event.number = (long)number;
    for (index = 0U; index < 6U; ++index) {
        event.arguments[index] = info->entry.args[index];
    }
    if (selected(context, event.number) &&
        clock_gettime(CLOCK_MONOTONIC, &event.entered_at) < 0) {
        set_error(error, error_size, "clock_gettime failed: %s",
                  strerror(errno));
        return false;
    }
    if (selected(context, event.number) && !context->config->summary &&
        !sg_decoder_capture_entry(&context->decoder, tracee->tid, &event)) {
        set_error(error, error_size,
                  "cannot capture syscall arguments: allocation failed");
        return false;
    }
    if (selected(context, event.number) &&
        !flush_unfinished_syscalls(context, tracee->tid, error, error_size)) {
        sg_decoder_release_event(&event);
        return false;
    }
    move_syscall_event(&tracee->pending_syscall, &event);
    tracee->has_pending_syscall = true;
    tracee->phase = SG_TRACEE_IN_SYSCALL;
    return true;
}

static bool finish_syscall(struct trace_context *context,
                           struct sg_tracee *tracee,
                           const struct ptrace_syscall_info *info,
                           char *error, size_t error_size)
{
    struct sg_syscall_event *event;
    int64_t result;

    if (!tracee->has_pending_syscall) {
        tracee->phase = SG_TRACEE_STOPPED;
        return true;
    }
    event = &tracee->pending_syscall;
    result = info->exit.rval;
    if (is_restart_result(result)) {
        if (tracee->has_interrupted_syscall) {
            sg_decoder_release_event(&tracee->interrupted_syscall);
        }
        move_syscall_event(&tracee->interrupted_syscall, event);
        tracee->has_interrupted_syscall = true;
        tracee->interrupted_restart_ready = false;
        tracee->has_pending_syscall = false;
        tracee->phase = SG_TRACEE_STOPPED;
        return true;
    }

    event->result = result;
    event->error_number = info->exit.is_error != 0U && result < 0 &&
                                  result >= -INT_MAX
                              ? (int)-result
                              : 0;
    if (selected(context, event->number) &&
        clock_gettime(CLOCK_MONOTONIC, &event->exited_at) < 0) {
        set_error(error, error_size, "clock_gettime failed: %s",
                  strerror(errno));
        return false;
    }
    event->completed = true;
    if (!write_syscall(context, tracee, event, error, error_size)) {
        return false;
    }
    if (tracee->has_interrupted_syscall) {
        if (event->number == SYS_rt_sigreturn) {
            tracee->interrupted_restart_ready = true;
        } else if (!tracee->interrupted_restart_ready &&
                   event->number == tracee->interrupted_syscall.number) {
            /* A handler invoked the same syscall, or an ignored signal caused
             * an immediate fresh entry. Either way, future work is traced as
             * a new call rather than being paired with stale arguments. */
            tracee->has_interrupted_syscall = false;
            sg_decoder_release_event(&tracee->interrupted_syscall);
        }
    }
    sg_decoder_release_event(event);
    tracee->has_pending_syscall = false;
    tracee->phase = SG_TRACEE_STOPPED;
    return true;
}

static bool handle_syscall_stop(struct trace_context *context,
                                struct sg_tracee *tracee,
                                char *error, size_t error_size)
{
    struct ptrace_syscall_info info = {0};
    long result;

    result = measured_ptrace(PTRACE_GET_SYSCALL_INFO, tracee->tid,
                             (void *)(uintptr_t)sizeof(info), &info);
    if (result < 0) {
        set_error(error, error_size, "PTRACE_GET_SYSCALL_INFO failed: %s",
                  strerror(errno));
        return false;
    }
    if ((size_t)result < offsetof(struct ptrace_syscall_info, arch) +
                             sizeof(info.arch)) {
        set_error(error, error_size,
                  "PTRACE_GET_SYSCALL_INFO returned a truncated header");
        return false;
    }
    if (info.arch != AUDIT_ARCH_X86_64) {
        set_error(error, error_size,
                  "tracee ABI is not native x86-64 (audit arch 0x%x)",
                  info.arch);
        return false;
    }
    if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
        if ((size_t)result < offsetof(struct ptrace_syscall_info, entry.args) +
                                 sizeof(info.entry.args)) {
            set_error(error, error_size,
                      "PTRACE_GET_SYSCALL_INFO returned a truncated entry");
            return false;
        }
        return begin_syscall(context, tracee, &info, error, error_size);
    }
    if (info.op == PTRACE_SYSCALL_INFO_EXIT) {
        if ((size_t)result <
            offsetof(struct ptrace_syscall_info, exit.is_error) +
                sizeof(info.exit.is_error)) {
            set_error(error, error_size,
                      "PTRACE_GET_SYSCALL_INFO returned a truncated exit");
            return false;
        }
        return finish_syscall(context, tracee, &info, error, error_size);
    }
    set_error(error, error_size, "unexpected syscall-stop operation %u",
              (unsigned int)info.op);
    return false;
}

static void release_tracee(struct sg_tracee *tracee)
{
    sg_decoder_release_event(&tracee->pending_syscall);
    sg_decoder_release_event(&tracee->interrupted_syscall);
}

static bool add_tracee(struct trace_context *context, pid_t tid, pid_t tgid,
                       bool attached, bool newborn,
                       char *error, size_t error_size)
{
    bool inserted;
    struct sg_tracee *tracee;

    if (!sg_tracee_table_insert(&context->tracees, tid, tgid, attached,
                                &inserted)) {
        set_error(error, error_size, "cannot allocate tracee state for %ld",
                  (long)tid);
        return false;
    }
    tracee = sg_tracee_table_get(&context->tracees, tid);
    if (inserted) {
        tracee->newborn = newborn;
        tracee->options_installed = true;
    }
    return true;
}

static pid_t read_tgid(pid_t tid)
{
    char path[64];
    char line[256];
    FILE *stream;
    long value;

    if (snprintf(path, sizeof(path), "/proc/%ld/status", (long)tid) < 0) {
        return -1;
    }
    stream = fopen(path, "r");
    if (stream == NULL) {
        return -1;
    }
    while (fgets(line, sizeof(line), stream) != NULL) {
        if (sscanf(line, "Tgid:%ld", &value) == 1 && value > 0 &&
            value <= INT_MAX) {
            (void)fclose(stream);
            return (pid_t)value;
        }
    }
    (void)fclose(stream);
    return -1;
}

static bool validate_native_executable(pid_t pid, char *error,
                                       size_t error_size)
{
    char path[64];
    Elf64_Ehdr header;
    ssize_t amount;
    int descriptor;

    if (snprintf(path, sizeof(path), "/proc/%ld/exe", (long)pid) < 0) {
        set_error(error, error_size, "cannot construct /proc executable path");
        return false;
    }
    descriptor = open(path, O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) {
        set_error(error, error_size, "cannot inspect target %ld: %s",
                  (long)pid, strerror(errno));
        return false;
    }
    amount = read(descriptor, &header, sizeof(header));
    (void)close(descriptor);
    if (amount != (ssize_t)sizeof(header) ||
        memcmp(header.e_ident, ELFMAG, SELFMAG) != 0 ||
        header.e_ident[EI_CLASS] != ELFCLASS64 ||
        header.e_ident[EI_DATA] != ELFDATA2LSB || header.e_machine != EM_X86_64) {
        set_error(error, error_size,
                  "target %ld is not a native x86-64 ELF process", (long)pid);
        return false;
    }
    return true;
}

static bool collect_task_ids(pid_t pid, pid_t **ids, size_t *count,
                             char *error, size_t error_size)
{
    char path[64];
    DIR *directory;
    struct dirent *entry;
    pid_t *values = NULL;
    size_t used = 0U;
    size_t capacity = 0U;

    if (snprintf(path, sizeof(path), "/proc/%ld/task", (long)pid) < 0) {
        set_error(error, error_size, "cannot construct task directory path");
        return false;
    }
    directory = opendir(path);
    if (directory == NULL) {
        set_error(error, error_size, "cannot enumerate target %ld: %s",
                  (long)pid, strerror(errno));
        return false;
    }
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        char *end = NULL;
        long value;

        if (entry->d_name[0] == '.') {
            continue;
        }
        errno = 0;
        value = strtol(entry->d_name, &end, 10);
        if (errno != 0 || end == entry->d_name || *end != '\0' || value <= 0 ||
            value > INT_MAX) {
            continue;
        }
        if (used == capacity) {
            size_t new_capacity = capacity == 0U ? 16U : capacity * 2U;
            pid_t *resized;

            if (new_capacity < capacity ||
                new_capacity > SIZE_MAX / sizeof(*values)) {
                free(values);
                (void)closedir(directory);
                set_error(error, error_size, "task list is too large");
                return false;
            }
            resized = realloc(values, new_capacity * sizeof(*values));
            if (resized == NULL) {
                free(values);
                (void)closedir(directory);
                set_error(error, error_size, "cannot allocate task list");
                return false;
            }
            values = resized;
            capacity = new_capacity;
        }
        values[used++] = (pid_t)value;
    }
    if (errno != 0) {
        int saved_errno = errno;
        free(values);
        (void)closedir(directory);
        set_error(error, error_size, "cannot read task directory: %s",
                  strerror(saved_errno));
        return false;
    }
    (void)closedir(directory);
    *ids = values;
    *count = used;
    return true;
}

static bool snapshot_tids(const struct sg_tracee_table *table,
                          pid_t **ids, size_t *count)
{
    size_t used = 0U;
    size_t index;

    *ids = NULL;
    *count = 0U;
    if (table->count == 0U) {
        return true;
    }
    *ids = malloc(table->count * sizeof(**ids));
    if (*ids == NULL) {
        return false;
    }
    for (index = 0U; index < table->capacity; ++index) {
        if (table->slots[index].state == SG_TRACEE_SLOT_OCCUPIED) {
            (*ids)[used++] = table->slots[index].tracee.tid;
        }
    }
    *count = used;
    return true;
}

static bool prepare_attach(struct trace_context *context,
                           char *error, size_t error_size)
{
    unsigned long options = ptrace_options(context->config, false);
    unsigned int round;

    if (!validate_native_executable(context->config->attach_pid, error,
                                    error_size)) {
        return false;
    }
    for (round = 0U; round < 64U; ++round) {
        pid_t *ids = NULL;
        size_t count = 0U;
        size_t index;
        size_t added = 0U;

        if (!collect_task_ids(context->config->attach_pid, &ids, &count,
                              error, error_size)) {
            return false;
        }
        for (index = 0U; index < count; ++index) {
            struct sg_tracee removed;

            if (sg_tracee_table_get(&context->tracees, ids[index]) != NULL) {
                continue;
            }
            if (!add_tracee(context, ids[index], context->config->attach_pid,
                            true, true, error, error_size)) {
                free(ids);
                return false;
            }
            if (measured_ptrace(PTRACE_SEIZE, ids[index], NULL,
                                (void *)(uintptr_t)options) < 0) {
                int saved_errno = errno;
                pid_t failed_tid = ids[index];

                (void)sg_tracee_table_remove(&context->tracees, ids[index],
                                             &removed);
                release_tracee(&removed);
                if (saved_errno == ESRCH) {
                    continue;
                }
                free(ids);
                set_error(error, error_size,
                          "cannot seize TID %ld: %s (check ptrace_scope/Yama)",
                          (long)failed_tid, strerror(saved_errno));
                return false;
            }
            ++added;
        }
        free(ids);
        if (added == 0U) {
            break;
        }
    }
    if (round == 64U || context->tracees.count == 0U) {
        set_error(error, error_size, "target task set did not stabilize");
        return false;
    }

    {
        size_t count;
        pid_t *ids;
        size_t index;

        if (!snapshot_tids(&context->tracees, &ids, &count)) {
            set_error(error, error_size, "cannot allocate attach snapshot");
            return false;
        }
        for (index = 0U; index < count; ++index) {
            if (measured_ptrace(PTRACE_INTERRUPT, ids[index], NULL, NULL) < 0 &&
                errno != ESRCH) {
                int saved_errno = errno;
                pid_t failed_tid = ids[index];

                free(ids);
                set_error(error, error_size, "cannot interrupt TID %ld: %s",
                          (long)failed_tid, strerror(saved_errno));
                return false;
            }
        }
        free(ids);
    }
    context->root_tid = context->config->attach_pid;
    return true;
}

static bool write_process_start(struct trace_context *context,
                                const struct sg_tracee *parent, pid_t child,
                                unsigned int ptrace_event,
                                char *error, size_t error_size)
{
    struct sg_event event = {0};

    if (!flush_unfinished_syscalls(context, -1, error, error_size)) {
        return false;
    }
    event.kind = SG_EVENT_PROCESS_START;
    event.tid = parent->tid;
    event.tgid = parent->tgid;
    if (!stamp_event(&event, error, error_size)) {
        return false;
    }
    event.data.lifecycle.related_tid = child;
    event.data.lifecycle.ptrace_event = ptrace_event;
    return emit_event(context, &event, error, error_size);
}

static bool handle_ptrace_event(struct trace_context *context,
                                struct sg_tracee *tracee,
                                unsigned int event,
                                char *error, size_t error_size)
{
    unsigned long message = 0UL;

    if (event == PTRACE_EVENT_EXEC) {
        if (tracee->has_pending_syscall) {
            tracee->pending_syscall.result = 0;
            tracee->pending_syscall.error_number = 0;
            tracee->pending_syscall.completed = true;
            if (clock_gettime(CLOCK_MONOTONIC,
                              &tracee->pending_syscall.exited_at) < 0) {
                set_error(error, error_size, "clock_gettime failed: %s",
                          strerror(errno));
                return false;
            }
            if (!write_syscall(context, tracee, &tracee->pending_syscall,
                               error, error_size)) {
                return false;
            }
            sg_decoder_release_event(&tracee->pending_syscall);
            tracee->has_pending_syscall = false;
            tracee->phase = SG_TRACEE_STOPPED;
        }
        tracee->newborn = false;
        return true;
    }
    if (event != PTRACE_EVENT_FORK && event != PTRACE_EVENT_VFORK &&
        event != PTRACE_EVENT_CLONE) {
        set_error(error, error_size, "unexpected ptrace event %u", event);
        return false;
    }
    if (measured_ptrace(PTRACE_GETEVENTMSG, tracee->tid, NULL, &message) < 0 ||
        message == 0UL || message > (unsigned long)INT_MAX) {
        set_error(error, error_size, "cannot read child TID for %ld: %s",
                  (long)tracee->tid, strerror(errno));
        return false;
    }
    {
        pid_t child = (pid_t)message;
        pid_t tgid = read_tgid(child);
        pid_t parent_tid = tracee->tid;
        bool attached = tracee->attached;

        if (tgid <= 0) {
            tgid = event == PTRACE_EVENT_CLONE ? tracee->tgid : child;
        }
        if (!add_tracee(context, child, tgid, attached, true,
                        error, error_size)) {
            if (attached) {
                (void)measured_ptrace(PTRACE_DETACH, child, NULL, NULL);
            } else {
                (void)kill(child, SIGKILL);
            }
            return false;
        }
        tracee = sg_tracee_table_get(&context->tracees, parent_tid);
        if (tracee == NULL ||
            !write_process_start(context, tracee, child, event, error,
                                 error_size)) {
            return false;
        }
    }
    return true;
}

static bool migrate_exec_tid(struct trace_context *context, pid_t waited,
                             pid_t former, char *error, size_t error_size)
{
    struct sg_tracee source = {0};
    struct sg_tracee replaced = {0};
    bool have_source;
    bool have_replaced;
    struct sg_tracee *destination;

    if (former == waited) {
        return true;
    }
    have_source = sg_tracee_table_remove(&context->tracees, former, &source);
    have_replaced = sg_tracee_table_remove(&context->tracees, waited, &replaced);
    if (have_source && have_replaced) {
        release_tracee(&replaced);
    } else if (!have_source && have_replaced) {
        source = replaced;
        have_source = true;
    }
    if (!have_source) {
        bool added = add_tracee(context, waited, waited,
                               context->config->mode == SG_RUN_ATTACH, false,
                               error, error_size);

        if (added) {
            sg_output_migrate_tid(&context->output, former, waited);
        }
        return added;
    }
    source.tid = waited;
    source.tgid = waited;
    source.newborn = false;
    if (!add_tracee(context, waited, waited, source.attached, false,
                    error, error_size)) {
        release_tracee(&source);
        return false;
    }
    destination = sg_tracee_table_get(&context->tracees, waited);
    *destination = source;
    sg_output_migrate_tid(&context->output, former, waited);
    if (context->root_tid == former) {
        context->root_tid = waited;
    }
    return true;
}

static void record_exit_status(struct trace_context *context, pid_t tid,
                               int status)
{
    if (tid == context->root_tid) {
        context->root_status = WIFEXITED(status)
                                   ? WEXITSTATUS(status)
                                   : 128 + WTERMSIG(status);
        context->root_status_known = true;
    }
}

static void shutdown_handler(int signal_number)
{
    shutdown_signal = signal_number;
}

static bool install_shutdown_handlers(struct sigaction *old_interrupt,
                                      struct sigaction *old_terminate,
                                      char *error, size_t error_size)
{
    struct sigaction action = {0};
    int saved_errno;

    action.sa_handler = shutdown_handler;
    shutdown_signal = 0;
    if (sigemptyset(&action.sa_mask) < 0 ||
        sigaction(SIGINT, &action, old_interrupt) < 0) {
        set_error(error, error_size, "cannot install shutdown handlers: %s",
                  strerror(errno));
        return false;
    }
    if (sigaction(SIGTERM, &action, old_terminate) < 0) {
        saved_errno = errno;
        (void)sigaction(SIGINT, old_interrupt, NULL);
        set_error(error, error_size, "cannot install shutdown handlers: %s",
                  strerror(saved_errno));
        return false;
    }
    return true;
}

static void restore_shutdown_handlers(const struct sigaction *old_interrupt,
                                      const struct sigaction *old_terminate)
{
    (void)sigaction(SIGINT, old_interrupt, NULL);
    (void)sigaction(SIGTERM, old_terminate, NULL);
}

static void release_all_tracees(struct trace_context *context)
{
    size_t index;

    for (index = 0U; index < context->tracees.capacity; ++index) {
        if (context->tracees.slots[index].state == SG_TRACEE_SLOT_OCCUPIED) {
            release_tracee(&context->tracees.slots[index].tracee);
        }
    }
    sg_tracee_table_destroy(&context->tracees);
}

static void kill_all_tracees(struct trace_context *context)
{
    size_t index;
    int status;
    pid_t waited;

    for (index = 0U; index < context->tracees.capacity; ++index) {
        if (context->tracees.slots[index].state == SG_TRACEE_SLOT_OCCUPIED) {
            (void)kill(context->tracees.slots[index].tracee.tid, SIGKILL);
        }
    }
    if (context->root_tid > 0 &&
        sg_tracee_table_get(&context->tracees, context->root_tid) == NULL) {
        (void)kill(context->root_tid, SIGKILL);
    }
    do {
        waited = waitpid(-1, &status, __WALL | WCONTINUED);
    } while (waited > 0 || (waited < 0 && errno == EINTR));
}

static void interrupt_running_tracees(struct trace_context *context)
{
    size_t index;

    for (index = 0U; index < context->tracees.capacity; ++index) {
        struct sg_tracee *tracee;

        if (context->tracees.slots[index].state != SG_TRACEE_SLOT_OCCUPIED) {
            continue;
        }
        tracee = &context->tracees.slots[index].tracee;
        if (!tracee->in_ptrace_stop &&
            measured_ptrace(PTRACE_INTERRUPT, tracee->tid, NULL, NULL) < 0 &&
            errno == ESRCH) {
            tracee->phase = SG_TRACEE_GONE;
        }
    }
}

static void detach_all_tracees(struct trace_context *context)
{
    size_t index;

    interrupt_running_tracees(context);
    for (index = 0U; index < context->tracees.capacity; ++index) {
        struct sg_tracee *tracee;
        int signal_number = 0;

        if (context->tracees.slots[index].state != SG_TRACEE_SLOT_OCCUPIED) {
            continue;
        }
        tracee = &context->tracees.slots[index].tracee;
        if (tracee->phase == SG_TRACEE_GONE) {
            continue;
        }
        if (!tracee->in_ptrace_stop) {
            int status;
            pid_t waited;

            do {
                waited = waitpid(tracee->tid, &status, __WALL);
            } while (waited < 0 && errno == EINTR);
            if (waited < 0) {
                continue;
            }
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                continue;
            }
            if (WIFSTOPPED(status)) {
                int stop = WSTOPSIG(status);
                unsigned int event = (unsigned int)status >> 16;

                if (stop != (SIGTRAP | 0x80) &&
                    !(stop == SIGTRAP && event != 0U)) {
                    signal_number = stop;
                }
            }
        } else {
            signal_number = tracee->pending_signal;
        }
        (void)measured_ptrace(PTRACE_DETACH, tracee->tid, NULL,
                              (void *)(uintptr_t)(unsigned int)signal_number);
    }
}

static bool trace_loop(struct trace_context *context, int *command_status,
                       char *error, size_t error_size)
{
    if (context->config->mode == SG_RUN_LAUNCH) {
        struct sg_tracee *root =
            sg_tracee_table_get(&context->tracees, context->root_tid);

        if (root == NULL ||
            !resume_tracee(root->tid, 0, error, error_size)) {
            return false;
        }
        root->in_ptrace_stop = false;
    }

    while (context->tracees.count != 0U) {
        int status;
        pid_t waited;
        struct sg_tracee *tracee;
        unsigned int ptrace_event;

        waited = waitpid(-1, &status, __WALL);
        if (waited < 0) {
            if (errno == EINTR && shutdown_signal != 0) {
                *command_status = 128 + shutdown_signal;
                return true;
            }
            if (errno == EINTR) {
                continue;
            }
            set_error(error, error_size, "waitpid failed: %s", strerror(errno));
            return false;
        }

        ptrace_event = WIFSTOPPED(status) ? (unsigned int)status >> 16 : 0U;
        if (WIFSTOPPED(status) && ptrace_event == PTRACE_EVENT_EXEC) {
            unsigned long former = 0UL;

            if (measured_ptrace(PTRACE_GETEVENTMSG, waited, NULL, &former) < 0) {
                set_error(error, error_size,
                          "cannot read former exec TID for %ld: %s",
                          (long)waited, strerror(errno));
                return false;
            }
            if (former > (unsigned long)INT_MAX) {
                set_error(error, error_size,
                          "former exec TID is outside the native range");
                return false;
            }
            if (!migrate_exec_tid(context, waited, (pid_t)former, error,
                                  error_size)) {
                return false;
            }
        }
        tracee = sg_tracee_table_get(&context->tracees, waited);
        if (tracee == NULL && WIFSTOPPED(status) && context->config->follow) {
            pid_t tgid = read_tgid(waited);

            if (tgid <= 0) {
                tgid = waited;
            }
            if (!add_tracee(context, waited, tgid,
                            context->config->mode == SG_RUN_ATTACH, true,
                            error, error_size)) {
                return false;
            }
            tracee = sg_tracee_table_get(&context->tracees, waited);
        }
        if (tracee == NULL) {
            continue;
        }

        if (WIFCONTINUED(status)) {
            tracee->phase = SG_TRACEE_RUNNING;
            tracee->in_ptrace_stop = false;
            continue;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            struct sg_tracee removed;

            tracee->phase = SG_TRACEE_GONE;
            if (!write_exit(context, tracee, status, error, error_size)) {
                return false;
            }
            record_exit_status(context, waited, status);
            (void)sg_tracee_table_remove(&context->tracees, waited, &removed);
            release_tracee(&removed);
            continue;
        }
        if (!WIFSTOPPED(status)) {
            continue;
        }

        {
            int stop = WSTOPSIG(status);
            int delivery_signal = 0;
            bool listen = false;

            tracee->in_ptrace_stop = true;
            tracee->phase = SG_TRACEE_STOPPED;
            if (stop == (SIGTRAP | 0x80)) {
                if (!handle_syscall_stop(context, tracee, error, error_size)) {
                    return false;
                }
            } else if (ptrace_event == PTRACE_EVENT_STOP) {
                tracee->newborn = false;
                if (stop != SIGTRAP) {
                    tracee->phase = SG_TRACEE_GROUP_STOPPED;
                    listen = tracee->attached;
                }
            } else if (ptrace_event != 0U) {
                if (!handle_ptrace_event(context, tracee, ptrace_event,
                                         error, error_size)) {
                    return false;
                }
            } else if (tracee->newborn && stop == SIGSTOP) {
                tracee->newborn = false;
            } else {
                siginfo_t signal_info = {0};

                if (measured_ptrace(PTRACE_GETSIGINFO, waited, NULL,
                                    &signal_info) < 0) {
                    if (errno == EINVAL && is_stopping_signal(stop)) {
                        tracee->phase = SG_TRACEE_GROUP_STOPPED;
                        listen = tracee->attached;
                    } else {
                        set_error(error, error_size,
                                  "PTRACE_GETSIGINFO for %ld failed: %s",
                                  (long)waited, strerror(errno));
                        return false;
                    }
                } else {
                    tracee->newborn = false;
                    tracee->pending_signal = stop;
                    if (!write_signal(context, tracee, &signal_info, error,
                                      error_size)) {
                        return false;
                    }
                    delivery_signal = stop;
                }
            }

            tracee = sg_tracee_table_get(&context->tracees, waited);
            if (tracee == NULL) {
                continue;
            }
            if (listen ? !listen_tracee(waited, error, error_size)
                       : !resume_tracee(waited, delivery_signal, error,
                                       error_size)) {
                if (errno == ESRCH) {
                    continue;
                }
                return false;
            }
            tracee->in_ptrace_stop = false;
            tracee->pending_signal = 0;
            if (!listen) {
                tracee->phase = SG_TRACEE_RUNNING;
            }
        }
        if (shutdown_signal != 0) {
            *command_status = 128 + shutdown_signal;
            return true;
        }
    }

    *command_status = context->config->mode == SG_RUN_ATTACH
                          ? 0
                          : context->root_status_known ? context->root_status : 0;
    return true;
}

bool sg_trace_run(const struct sg_config *config, int *command_status,
                  char *error, size_t error_size)
{
    struct trace_context context = {0};
    struct sigaction old_interrupt;
    struct sigaction old_terminate;
    bool handlers_installed = false;
    bool success;

    if (config == NULL || command_status == NULL) {
        set_error(error, error_size, "invalid tracing configuration");
        return false;
    }
    if (!validate_runtime_options(config, error, error_size)) {
        return false;
    }
    ptrace_call_count = 0U;
    context.config = config;
    context.decoder.string_limit = config->string_limit;
    context.decoder.memory.read = read_tracee_memory;
    context.show_tids = config->follow || config->mode == SG_RUN_ATTACH;
    sg_tracee_table_init(&context.tracees);
    sg_stats_init(&context.stats);
    context.stream = open_output(config->output_path, error, error_size);
    if (context.stream == NULL) {
        return false;
    }
    if (!sg_output_init(&context.output, context.stream, config->format,
                        &context.decoder, context.show_tids, config->summary,
                        error, error_size)) {
        if (context.stream != stderr) {
            (void)fclose(context.stream);
        }
        sg_stats_destroy(&context.stats);
        return false;
    }

    if (config->mode == SG_RUN_LAUNCH) {
        pid_t child = launch_tracee(config->command_argv, error, error_size);

        success = child >= 0;
        if (success) {
            context.root_tid = child;
            success = add_tracee(&context, child, child, false, false,
                                  error, error_size);
        }
        if (success) {
            success = wait_for_initial_stop(child, error, error_size);
        }
        if (success) {
            struct sg_tracee *root =
                sg_tracee_table_get(&context.tracees, child);

            root->in_ptrace_stop = true;
            root->phase = SG_TRACEE_STOPPED;
            success = install_ptrace_options(child, config, error, error_size);
            root->options_installed = success;
        }
    } else {
        success = prepare_attach(&context, error, error_size);
    }
    if (success) {
        success = install_shutdown_handlers(&old_interrupt, &old_terminate,
                                            error, error_size);
        handlers_installed = success;
    }
    if (success) {
        success = trace_loop(&context, command_status, error, error_size);
    }

    if (shutdown_signal != 0 || !success) {
        if (config->mode == SG_RUN_ATTACH) {
            detach_all_tracees(&context);
        } else {
            kill_all_tracees(&context);
        }
    }
    if (handlers_installed) {
        restore_shutdown_handlers(&old_interrupt, &old_terminate);
    }
    shutdown_signal = 0;
    release_all_tracees(&context);

    if (success) {
        success = sg_output_write_summary(&context.output, &context.stats,
                                          error, error_size);
    }
    if (success) {
        success = sg_output_finish(&context.output, error, error_size);
    }
    if (success) {
        success = write_benchmark_metrics(&context, error, error_size);
    }
    sg_output_destroy(&context.output);
    sg_stats_destroy(&context.stats);
    if (context.stream != stderr && fclose(context.stream) == EOF && success) {
        set_error(error, error_size, "cannot close trace output '%s': %s",
                  config->output_path, strerror(errno));
        success = false;
    }
    return success;
}
