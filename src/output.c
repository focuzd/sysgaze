#include "sysgaze/output.h"

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sysgaze/buffer.h"
#include "sysgaze/syscall_catalog.h"

#define SG_SCHEMA "sysgaze.trace/v1"

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

static bool append_json_string(struct sg_buffer *buffer, const char *value)
{
    const unsigned char *cursor = (const unsigned char *)value;

    if (!sg_buffer_append_cstr(buffer, "\"")) {
        return false;
    }
    while (*cursor != '\0') {
        unsigned char byte = *cursor++;

        if (byte == '"' || byte == '\\') {
            char escaped[2] = {'\\', (char)byte};

            if (!sg_buffer_append(buffer, escaped, sizeof(escaped))) {
                return false;
            }
        } else if (byte == '\b') {
            if (!sg_buffer_append_cstr(buffer, "\\b")) {
                return false;
            }
        } else if (byte == '\f') {
            if (!sg_buffer_append_cstr(buffer, "\\f")) {
                return false;
            }
        } else if (byte == '\n') {
            if (!sg_buffer_append_cstr(buffer, "\\n")) {
                return false;
            }
        } else if (byte == '\r') {
            if (!sg_buffer_append_cstr(buffer, "\\r")) {
                return false;
            }
        } else if (byte == '\t') {
            if (!sg_buffer_append_cstr(buffer, "\\t")) {
                return false;
            }
        } else if (byte < 0x20U) {
            if (!sg_buffer_append_format(buffer, "\\u%04x",
                                         (unsigned int)byte)) {
                return false;
            }
        } else if (!sg_buffer_append(buffer, &byte, 1U)) {
            return false;
        }
    }
    return sg_buffer_append_cstr(buffer, "\"");
}

static bool write_buffer(struct sg_output *output, struct sg_buffer *buffer,
                         char *error, size_t error_size)
{
    if (!sg_buffer_append_cstr(buffer, "\n")) {
        set_error(error, error_size, "cannot allocate trace output");
        return false;
    }
    if (fwrite(buffer->data, 1U, buffer->length, output->stream) !=
            buffer->length ||
        fflush(output->stream) == EOF) {
        set_error(error, error_size, "cannot write trace output: %s",
                  strerror(errno));
        return false;
    }
    return true;
}

static bool append_tid_prefix(const struct sg_output *output,
                              const struct sg_event *event,
                              struct sg_buffer *buffer)
{
    return !output->show_tids ||
           sg_buffer_append_format(buffer, "[pid %ld] ", (long)event->tid);
}

static bool unfinished_contains(const struct sg_output *output, pid_t tid,
                                size_t *position)
{
    size_t index;

    for (index = 0U; index < output->unfinished_count; ++index) {
        if (output->unfinished_tids[index] == tid) {
            if (position != NULL) {
                *position = index;
            }
            return true;
        }
    }
    return false;
}

static bool unfinished_add(struct sg_output *output, pid_t tid)
{
    pid_t *resized;
    size_t capacity;

    if (unfinished_contains(output, tid, NULL)) {
        return true;
    }
    if (output->unfinished_count < output->unfinished_capacity) {
        output->unfinished_tids[output->unfinished_count++] = tid;
        return true;
    }
    capacity = output->unfinished_capacity == 0U
                   ? 8U
                   : output->unfinished_capacity * 2U;
    if (capacity < output->unfinished_capacity ||
        capacity > SIZE_MAX / sizeof(*output->unfinished_tids)) {
        return false;
    }
    resized = realloc(output->unfinished_tids,
                      capacity * sizeof(*output->unfinished_tids));
    if (resized == NULL) {
        return false;
    }
    output->unfinished_tids = resized;
    output->unfinished_capacity = capacity;
    output->unfinished_tids[output->unfinished_count++] = tid;
    return true;
}

static bool unfinished_remove(struct sg_output *output, pid_t tid)
{
    size_t position;

    if (!unfinished_contains(output, tid, &position)) {
        return false;
    }
    --output->unfinished_count;
    output->unfinished_tids[position] =
        output->unfinished_tids[output->unfinished_count];
    return true;
}

static const char *syscall_name(long number, char *fallback,
                                size_t fallback_size)
{
    const struct sg_syscall_descriptor *descriptor =
        sg_syscall_by_number(number);

    if (descriptor != NULL) {
        return descriptor->name;
    }
    (void)snprintf(fallback, fallback_size, "syscall_%ld", number);
    return fallback;
}

static bool write_text_syscall(struct sg_output *output,
                               const struct sg_event *event,
                               char *error, size_t error_size)
{
    const struct sg_syscall_event *syscall = &event->data.syscall;
    struct sg_buffer rendered;
    bool ok;

    sg_buffer_init(&rendered);
    ok = append_tid_prefix(output, event, &rendered);
    if (!syscall->completed) {
        if (unfinished_contains(output, event->tid, NULL)) {
            sg_buffer_destroy(&rendered);
            return true;
        }
        ok = ok && sg_decode_syscall_entry(output->decoder, event->tid, syscall,
                                           &rendered) &&
             sg_buffer_append_cstr(&rendered, " <unfinished ...>") &&
             unfinished_add(output, event->tid);
    } else if (unfinished_remove(output, event->tid)) {
        char fallback[64];
        const char *name = syscall_name(syscall->number, fallback,
                                        sizeof(fallback));

        ok = ok && sg_buffer_append_format(&rendered, "<... %s resumed>)", name) &&
             sg_decode_syscall_result(syscall, &rendered);
    } else {
        ok = ok && sg_decode_syscall(output->decoder, event->tid, syscall,
                                     &rendered);
    }
    if (!ok) {
        sg_buffer_destroy(&rendered);
        set_error(error, error_size, "cannot render syscall %ld",
                  syscall->number);
        return false;
    }
    ok = write_buffer(output, &rendered, error, error_size);
    sg_buffer_destroy(&rendered);
    return ok;
}

static bool append_signal_name(struct sg_buffer *buffer, int signal_number)
{
    const char *abbreviation = sigabbrev_np(signal_number);

    if (abbreviation == NULL) {
        return sg_buffer_append_format(buffer, "signal %d", signal_number);
    }
    return sg_buffer_append_format(buffer, "SIG%s", abbreviation);
}

static bool write_text_event(struct sg_output *output,
                             const struct sg_event *event,
                             char *error, size_t error_size)
{
    struct sg_buffer rendered;
    bool ok;

    if (event->kind == SG_EVENT_SYSCALL) {
        return write_text_syscall(output, event, error, error_size);
    }
    sg_buffer_init(&rendered);
    ok = append_tid_prefix(output, event, &rendered);
    if (event->kind == SG_EVENT_SIGNAL) {
        ok = ok && sg_buffer_append_cstr(&rendered, "--- ") &&
             append_signal_name(&rendered, event->data.signal.signal_number) &&
             sg_buffer_append_format(&rendered, " {si_code=%d}",
                                     event->data.signal.signal_code);
        if (event->data.signal.fault_address != 0U) {
            ok = ok && sg_buffer_append_format(
                           &rendered, " {si_addr=0x%" PRIxPTR "}",
                           event->data.signal.fault_address);
        }
        ok = ok && sg_buffer_append_cstr(&rendered, " ---");
    } else if (event->kind == SG_EVENT_PROCESS_START) {
        ok = ok && sg_buffer_append_format(
                       &rendered, "+++ spawned %ld +++",
                       (long)event->data.lifecycle.related_tid);
    } else if (event->data.lifecycle.signaled) {
        (void)unfinished_remove(output, event->tid);
        ok = ok && sg_buffer_append_cstr(&rendered, "+++ killed by ") &&
             append_signal_name(&rendered, event->data.lifecycle.status) &&
             sg_buffer_append_cstr(&rendered, " +++");
    } else {
        (void)unfinished_remove(output, event->tid);
        ok = ok && sg_buffer_append_format(
                       &rendered, "+++ exited with %d +++",
                       event->data.lifecycle.status);
    }
    if (!ok) {
        sg_buffer_destroy(&rendered);
        set_error(error, error_size, "cannot allocate trace output");
        return false;
    }
    ok = write_buffer(output, &rendered, error, error_size);
    sg_buffer_destroy(&rendered);
    return ok;
}

static uint64_t elapsed_nanoseconds(const struct sg_syscall_event *event)
{
    int64_t seconds = (int64_t)event->exited_at.tv_sec -
                      (int64_t)event->entered_at.tv_sec;
    int64_t nanoseconds = (int64_t)event->exited_at.tv_nsec -
                          (int64_t)event->entered_at.tv_nsec;

    if (seconds < 0 || (seconds == 0 && nanoseconds < 0)) {
        return 0U;
    }
    if (nanoseconds < 0) {
        --seconds;
        nanoseconds += INT64_C(1000000000);
    }
    return (uint64_t)seconds * UINT64_C(1000000000) +
           (uint64_t)nanoseconds;
}

static bool append_json_header(struct sg_buffer *buffer, const char *type,
                               const struct sg_event *event)
{
    if (!sg_buffer_append_cstr(buffer, "{\"schema\":\"") ||
        !sg_buffer_append_cstr(buffer, SG_SCHEMA) ||
        !sg_buffer_append_cstr(buffer, "\",\"type\":") ||
        !append_json_string(buffer, type)) {
        return false;
    }
    if (event == NULL) {
        return true;
    }
    return sg_buffer_append_format(
        buffer,
        ",\"tid\":%ld,\"tgid\":%ld,\"timestamp_ns\":\"%" PRIu64 "\"",
        (long)event->tid, (long)event->tgid,
        event->observed_at.tv_sec < 0
            ? UINT64_C(0)
            : (uint64_t)event->observed_at.tv_sec * UINT64_C(1000000000) +
                  (uint64_t)event->observed_at.tv_nsec);
}

static bool append_json_syscall(struct sg_output *output,
                                const struct sg_event *event,
                                struct sg_buffer *buffer)
{
    const struct sg_syscall_event *syscall = &event->data.syscall;
    char fallback[64];
    const char *name = syscall_name(syscall->number, fallback, sizeof(fallback));
    struct sg_buffer text;
    size_t index;
    bool ok;

    sg_buffer_init(&text);
    ok = sg_decode_syscall(output->decoder, event->tid, syscall, &text) &&
         append_json_header(buffer, "syscall", event) &&
         sg_buffer_append_format(buffer, ",\"number\":\"%ld\",\"name\":",
                                 syscall->number) &&
         append_json_string(buffer, name) &&
         sg_buffer_append_cstr(buffer, ",\"arguments\":[");
    for (index = 0U; ok && index < syscall->argument_count; ++index) {
        ok = (index == 0U || sg_buffer_append_cstr(buffer, ",")) &&
             sg_buffer_append_format(buffer, "\"0x%" PRIx64 "\"",
                                     syscall->arguments[index]);
    }
    ok = ok && sg_buffer_append_format(
                   buffer, "],\"result\":\"%" PRId64 "\",\"error\":",
                   syscall->result);
    if (ok && syscall->error_number == 0) {
        ok = sg_buffer_append_cstr(buffer, "null");
    } else if (ok) {
        const char *error_name = strerrorname_np(syscall->error_number);

        ok = sg_buffer_append_format(buffer, "{\"number\":%d,\"name\":",
                                     syscall->error_number) &&
             (error_name == NULL ? sg_buffer_append_cstr(buffer, "null")
                                 : append_json_string(buffer, error_name)) &&
             sg_buffer_append_cstr(buffer, "}");
    }
    ok = ok && sg_buffer_append_format(
                   buffer, ",\"duration_ns\":\"%" PRIu64 "\",\"text\":",
                   elapsed_nanoseconds(syscall)) &&
         append_json_string(buffer, text.data == NULL ? "" : text.data) &&
         sg_buffer_append_cstr(buffer, "}");
    sg_buffer_destroy(&text);
    return ok;
}

static bool append_json_event(struct sg_output *output,
                              const struct sg_event *event,
                              struct sg_buffer *buffer)
{
    if (event->kind == SG_EVENT_SYSCALL) {
        return append_json_syscall(output, event, buffer);
    }
    if (event->kind == SG_EVENT_SIGNAL) {
        const char *abbreviation =
            sigabbrev_np(event->data.signal.signal_number);

        return append_json_header(buffer, "signal", event) &&
               sg_buffer_append_format(
                   buffer, ",\"number\":%d,\"name\":",
                   event->data.signal.signal_number) &&
               (abbreviation == NULL
                    ? sg_buffer_append_cstr(buffer, "null")
                    : sg_buffer_append_format(buffer, "\"SIG%s\"",
                                              abbreviation)) &&
               sg_buffer_append_format(
                   buffer, ",\"code\":%d,\"fault_address\":",
                   event->data.signal.signal_code) &&
               (event->data.signal.fault_address == 0U
                    ? sg_buffer_append_cstr(buffer, "null}")
                    : sg_buffer_append_format(
                          buffer, "\"0x%" PRIxPTR "\"}",
                          event->data.signal.fault_address));
    }
    if (event->kind == SG_EVENT_PROCESS_START) {
        return append_json_header(buffer, "process-start", event) &&
               sg_buffer_append_format(
                   buffer,
                   ",\"child_tid\":%ld,\"ptrace_event\":%u}",
                   (long)event->data.lifecycle.related_tid,
                   event->data.lifecycle.ptrace_event);
    }
    return append_json_header(buffer, "process-exit", event) &&
           sg_buffer_append_format(
               buffer, ",\"status\":%d,\"signaled\":%s}",
               event->data.lifecycle.status,
               event->data.lifecycle.signaled ? "true" : "false");
}

bool sg_output_init(struct sg_output *output, FILE *stream,
                    enum sg_output_format format,
                    const struct sg_decoder *decoder, bool show_tids,
                    char *error, size_t error_size)
{
    struct sg_buffer metadata;
    bool ok;

    memset(output, 0, sizeof(*output));
    output->stream = stream;
    output->decoder = decoder;
    output->format = format;
    output->show_tids = show_tids;
    if (format == SG_FORMAT_TEXT) {
        return true;
    }
    sg_buffer_init(&metadata);
    ok = append_json_header(&metadata, "metadata", NULL) &&
         sg_buffer_append_cstr(
             &metadata,
             ",\"architecture\":\"x86_64\",\"format\":\"ndjson\"}");
    if (!ok) {
        sg_buffer_destroy(&metadata);
        set_error(error, error_size, "cannot allocate trace metadata");
        return false;
    }
    ok = write_buffer(output, &metadata, error, error_size);
    sg_buffer_destroy(&metadata);
    return ok;
}

bool sg_output_write_event(struct sg_output *output,
                           const struct sg_event *event,
                           char *error, size_t error_size)
{
    struct sg_buffer rendered;
    bool ok;

    if (output->format == SG_FORMAT_TEXT) {
        return write_text_event(output, event, error, error_size);
    }
    if (event->kind == SG_EVENT_SYSCALL && !event->data.syscall.completed) {
        return true;
    }
    sg_buffer_init(&rendered);
    ok = append_json_event(output, event, &rendered);
    if (!ok) {
        sg_buffer_destroy(&rendered);
        set_error(error, error_size, "cannot allocate NDJSON event");
        return false;
    }
    ok = write_buffer(output, &rendered, error, error_size);
    sg_buffer_destroy(&rendered);
    return ok;
}

void sg_output_migrate_tid(struct sg_output *output, pid_t former_tid,
                           pid_t current_tid)
{
    size_t position;

    if (former_tid == current_tid ||
        !unfinished_contains(output, former_tid, &position)) {
        return;
    }
    if (unfinished_contains(output, current_tid, NULL)) {
        (void)unfinished_remove(output, former_tid);
    } else {
        output->unfinished_tids[position] = current_tid;
    }
}

bool sg_output_finish(struct sg_output *output, char *error, size_t error_size)
{
    if (fflush(output->stream) == EOF) {
        set_error(error, error_size, "cannot flush trace output: %s",
                  strerror(errno));
        return false;
    }
    return true;
}

void sg_output_destroy(struct sg_output *output)
{
    free(output->unfinished_tids);
    memset(output, 0, sizeof(*output));
}
