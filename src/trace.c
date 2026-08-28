#include "sysgaze/trace.h"

#include <errno.h>
#include <fcntl.h>
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

#include "sysgaze/buffer.h"
#include "sysgaze/decoder.h"
#include "sysgaze/syscall_catalog.h"
#include "sysgaze/tracee.h"

#if !defined(__linux__) || !defined(__x86_64__)
#error "Sysgaze currently supports native x86-64 Linux only"
#endif

#define SG_RESTART_SYS 512
#define SG_RESTART_NOINTR 513
#define SG_RESTART_NOHAND 514
#define SG_RESTART_RESTARTBLOCK 516

struct trace_context {
    const struct sg_config *config;
    struct sg_tracee tracee;
    struct sg_decoder decoder;
    FILE *output;
};

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

static bool validate_stage_two_options(const struct sg_config *config,
                                       char *error, size_t error_size)
{
    if (config->mode != SG_RUN_LAUNCH) {
        set_error(error, error_size,
                  "attach mode is not implemented until Stage 4");
        return false;
    }
    if (config->follow) {
        set_error(error, error_size,
                  "follow mode is not implemented until Stage 4");
        return false;
    }
    if (config->summary) {
        set_error(error, error_size,
                  "summary mode is not implemented until Stage 6");
        return false;
    }
    if (config->format != SG_FORMAT_TEXT) {
        set_error(error, error_size,
                  "structured output is not implemented until Stage 5");
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

static bool install_ptrace_options(pid_t child, char *error, size_t error_size)
{
    const unsigned long options = PTRACE_O_TRACESYSGOOD |
                                  PTRACE_O_TRACEEXEC |
                                  PTRACE_O_EXITKILL;

    if (ptrace(PTRACE_SETOPTIONS, child, NULL,
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
    if (ptrace(PTRACE_SYSCALL, tid, NULL,
               (void *)(uintptr_t)(unsigned int)signal_number) < 0) {
        set_error(error, error_size, "PTRACE_SYSCALL for %ld failed: %s",
                  (long)tid, strerror(errno));
        return false;
    }
    return true;
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

static bool write_syscall(struct trace_context *context,
                          const struct sg_syscall_event *event,
                          char *error, size_t error_size)
{
    struct sg_buffer rendered;
    bool decoded;

    if (!selected(context, event->number)) {
        return true;
    }
    sg_buffer_init(&rendered);
    decoded = sg_decode_syscall(&context->decoder, context->tracee.tid, event,
                                &rendered) &&
              sg_buffer_append_cstr(&rendered, "\n");
    if (!decoded) {
        sg_buffer_destroy(&rendered);
        set_error(error, error_size,
                  "cannot decode syscall %ld: allocation failed",
                  event->number);
        return false;
    }
    if (fwrite(rendered.data, 1U, rendered.length, context->output) !=
            rendered.length ||
        fflush(context->output) == EOF) {
        sg_buffer_destroy(&rendered);
        goto output_failure;
    }
    sg_buffer_destroy(&rendered);
    return true;

output_failure:
    set_error(error, error_size, "cannot write trace output: %s",
              strerror(errno));
    return false;
}

static bool write_signal(struct trace_context *context, int signal_number,
                         char *error, size_t error_size)
{
    const char *description = strsignal(signal_number);

    if (fprintf(context->output, "--- signal %d (%s) ---\n", signal_number,
                description == NULL ? "unknown" : description) < 0 ||
        fflush(context->output) == EOF) {
        set_error(error, error_size, "cannot write trace output: %s",
                  strerror(errno));
        return false;
    }
    return true;
}

static bool write_exit(struct trace_context *context, int status,
                       char *error, size_t error_size)
{
    int result;

    if (WIFEXITED(status)) {
        result = fprintf(context->output, "+++ exited with %d +++\n",
                         WEXITSTATUS(status));
    } else {
        int signal_number = WTERMSIG(status);
        const char *description = strsignal(signal_number);

        result = fprintf(context->output, "+++ killed by signal %d (%s) +++\n",
                         signal_number,
                         description == NULL ? "unknown" : description);
    }
    if (result < 0 || fflush(context->output) == EOF) {
        set_error(error, error_size, "cannot write trace output: %s",
                  strerror(errno));
        return false;
    }
    return true;
}

static bool begin_syscall(struct trace_context *context,
                          const struct ptrace_syscall_info *info,
                          char *error, size_t error_size)
{
    struct sg_tracee *tracee = &context->tracee;
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
            if (!write_syscall(context, &tracee->pending_syscall, error,
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
        sg_decoder_release_event(&tracee->interrupted_syscall);
        tracee->has_interrupted_syscall = false;
        tracee->interrupted_restart_ready = false;
    }

    event.number = (long)number;
    for (index = 0U; index < 6U; ++index) {
        event.arguments[index] = info->entry.args[index];
    }
    if (clock_gettime(CLOCK_MONOTONIC, &event.entered_at) < 0) {
        set_error(error, error_size, "clock_gettime failed: %s",
                  strerror(errno));
        return false;
    }
    if (selected(context, event.number) &&
        !sg_decoder_capture_entry(&context->decoder, tracee->tid, &event)) {
        set_error(error, error_size,
                  "cannot capture syscall arguments: allocation failed");
        return false;
    }
    move_syscall_event(&tracee->pending_syscall, &event);
    tracee->has_pending_syscall = true;
    tracee->phase = SG_TRACEE_IN_SYSCALL;
    return true;
}

static bool finish_syscall(struct trace_context *context,
                           const struct ptrace_syscall_info *info,
                           char *error, size_t error_size)
{
    struct sg_tracee *tracee = &context->tracee;
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
    if (clock_gettime(CLOCK_MONOTONIC, &event->exited_at) < 0) {
        set_error(error, error_size, "clock_gettime failed: %s",
                  strerror(errno));
        return false;
    }
    event->completed = true;
    if (!write_syscall(context, event, error, error_size)) {
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
                                char *error, size_t error_size)
{
    struct ptrace_syscall_info info = {0};
    long result;

    result = ptrace(PTRACE_GET_SYSCALL_INFO, context->tracee.tid,
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
        return begin_syscall(context, &info, error, error_size);
    }
    if (info.op == PTRACE_SYSCALL_INFO_EXIT) {
        if ((size_t)result <
            offsetof(struct ptrace_syscall_info, exit.is_error) +
                sizeof(info.exit.is_error)) {
            set_error(error, error_size,
                      "PTRACE_GET_SYSCALL_INFO returned a truncated exit");
            return false;
        }
        return finish_syscall(context, &info, error, error_size);
    }
    set_error(error, error_size, "unexpected syscall-stop operation %u",
              (unsigned int)info.op);
    return false;
}

static void terminate_tracee(pid_t child)
{
    int status;

    if (kill(child, SIGKILL) < 0 && errno != ESRCH) {
        return;
    }
    while (waitpid(child, &status, __WALL) < 0 && errno == EINTR) {
    }
}

static bool trace_loop(struct trace_context *context, int *command_status,
                       char *error, size_t error_size)
{
    const pid_t child = context->tracee.tid;

    if (!resume_tracee(child, 0, error, error_size)) {
        return false;
    }
    for (;;) {
        int status;
        pid_t waited;

        do {
            waited = waitpid(child, &status, __WALL);
        } while (waited < 0 && errno == EINTR);
        if (waited < 0) {
            set_error(error, error_size, "waitpid failed: %s", strerror(errno));
            return false;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            context->tracee.phase = SG_TRACEE_GONE;
            if (!write_exit(context, status, error, error_size)) {
                return false;
            }
            *command_status = WIFEXITED(status)
                                  ? WEXITSTATUS(status)
                                  : 128 + WTERMSIG(status);
            return true;
        }
        if (!WIFSTOPPED(status)) {
            continue;
        }

        {
            int stop_signal = WSTOPSIG(status);
            unsigned int ptrace_event = (unsigned int)status >> 16;
            int delivery_signal = 0;

            context->tracee.phase = SG_TRACEE_STOPPED;
            if (stop_signal == (SIGTRAP | 0x80)) {
                if (!handle_syscall_stop(context, error, error_size)) {
                    return false;
                }
            } else if (stop_signal == SIGTRAP && ptrace_event != 0U) {
                if (ptrace_event != PTRACE_EVENT_EXEC) {
                    set_error(error, error_size,
                              "unexpected ptrace event %u", ptrace_event);
                    return false;
                }
                if (context->tracee.has_pending_syscall) {
                    context->tracee.phase = SG_TRACEE_IN_SYSCALL;
                }
            } else if (stop_signal == SIGTRAP) {
                /* A synthetic trap is tracer machinery, not a signal for the
                 * tracee. Full stop classification arrives in Stage 5. */
            } else {
                if (!write_signal(context, stop_signal, error, error_size)) {
                    return false;
                }
                delivery_signal = stop_signal;
                context->tracee.pending_signal = stop_signal;
            }
            if (!resume_tracee(child, delivery_signal, error, error_size)) {
                return false;
            }
            context->tracee.pending_signal = 0;
        }
    }
}

bool sg_trace_run(const struct sg_config *config, int *command_status,
                  char *error, size_t error_size)
{
    struct trace_context context = {0};
    pid_t child;
    bool success;

    if (config == NULL || command_status == NULL) {
        set_error(error, error_size, "invalid tracing configuration");
        return false;
    }
    if (!validate_stage_two_options(config, error, error_size)) {
        return false;
    }
    context.config = config;
    context.decoder.string_limit = config->string_limit;
    context.decoder.memory.read = read_tracee_memory;
    context.output = open_output(config->output_path, error, error_size);
    if (context.output == NULL) {
        return false;
    }

    child = launch_tracee(config->command_argv, error, error_size);
    if (child < 0) {
        if (context.output != stderr) {
            (void)fclose(context.output);
        }
        return false;
    }
    context.tracee.tid = child;
    context.tracee.tgid = child;
    context.tracee.phase = SG_TRACEE_NEW;

    success = wait_for_initial_stop(child, error, error_size);
    if (success) {
        success = install_ptrace_options(child, error, error_size);
        context.tracee.options_installed = success;
    }
    if (success) {
        context.tracee.phase = SG_TRACEE_STOPPED;
        success = trace_loop(&context, command_status, error, error_size);
    }
    if (!success && context.tracee.phase != SG_TRACEE_GONE) {
        terminate_tracee(child);
    }
    sg_decoder_release_event(&context.tracee.pending_syscall);
    sg_decoder_release_event(&context.tracee.interrupted_syscall);

    if (context.output != stderr && fclose(context.output) == EOF && success) {
        set_error(error, error_size, "cannot close trace output '%s': %s",
                  config->output_path, strerror(errno));
        success = false;
    }
    return success;
}
