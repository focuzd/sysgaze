#ifndef SYSGAZE_TRACEE_H
#define SYSGAZE_TRACEE_H

#include <stdbool.h>
#include <sys/types.h>

#include "sysgaze/event.h"

enum sg_tracee_phase {
    SG_TRACEE_NEW,
    SG_TRACEE_STOPPED,
    SG_TRACEE_IN_SYSCALL,
    SG_TRACEE_GROUP_STOPPED,
    SG_TRACEE_EXITING,
    SG_TRACEE_GONE
};

struct sg_tracee {
    pid_t tid;
    pid_t tgid;
    enum sg_tracee_phase phase;
    int pending_signal;
    bool attached;
    bool options_installed;
    bool has_pending_syscall;
    bool has_interrupted_syscall;
    bool interrupted_restart_ready;
    struct sg_syscall_event pending_syscall;
    struct sg_syscall_event interrupted_syscall;
};

#endif
