#ifndef SYSGAZE_EVENT_H
#define SYSGAZE_EVENT_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

enum sg_event_kind {
    SG_EVENT_SYSCALL,
    SG_EVENT_SIGNAL,
    SG_EVENT_PROCESS_START,
    SG_EVENT_PROCESS_EXIT
};

struct sg_syscall_event {
    long number;
    uint64_t arguments[6];
    int64_t result;
    int error_number;
    struct timespec entered_at;
    struct timespec exited_at;
    char *decoded_arguments[6];
    uint8_t argument_count;
    bool completed;
};

struct sg_signal_event {
    int signal_number;
    int signal_code;
    uintptr_t fault_address;
};

struct sg_lifecycle_event {
    pid_t related_tid;
    int status;
    unsigned int ptrace_event;
    bool signaled;
};

struct sg_event {
    enum sg_event_kind kind;
    pid_t tid;
    pid_t tgid;
    struct timespec observed_at;
    union {
        struct sg_syscall_event syscall;
        struct sg_signal_event signal;
        struct sg_lifecycle_event lifecycle;
    } data;
};

#endif
