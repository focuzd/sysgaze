#ifndef SYSGAZE_SYSCALL_CATALOG_H
#define SYSGAZE_SYSCALL_CATALOG_H

#include <stdint.h>
#include <stddef.h>

#include "sysgaze/filter.h"

enum sg_argument_kind {
    ARG_HEX,
    ARG_S32,
    ARG_U64,
    ARG_SIZE,
    ARG_FD,
    ARG_DIRFD,
    ARG_POINTER,
    ARG_STRING,
    ARG_STRING_OUT,
    ARG_BUFFER_IN,
    ARG_BUFFER_OUT,
    ARG_ARGV,
    ARG_MODE,
    ARG_OPEN_FLAGS,
    ARG_FD_FLAGS,
    ARG_PROT_FLAGS,
    ARG_MAP_FLAGS,
    ARG_CLONE_FLAGS,
    ARG_ACCESS_FLAGS,
    ARG_AT_FLAGS,
    ARG_SOCKET_DOMAIN,
    ARG_SOCKET_TYPE,
    ARG_SIGNAL,
    ARG_SIGMASK_HOW,
    ARG_SHUTDOWN_HOW,
    ARG_FCNTL_COMMAND,
    ARG_EPOLL_OPERATION,
    ARG_WHENCE,
    ARG_SOCKADDR_IN,
    ARG_TIMESPEC_IN,
    ARG_PIPE_OUT,
    ARG_UTS_OUT,
    SG_ARGUMENT_KIND_COUNT
};

enum sg_result_kind {
    RESULT_INTEGER,
    RESULT_POINTER,
    SG_RESULT_KIND_COUNT
};

struct sg_argument_spec {
    enum sg_argument_kind kind;
    uint8_t auxiliary;
};

struct sg_syscall_descriptor {
    long number;
    const char *name;
    uint8_t arity;
    uint32_t classes;
    enum sg_result_kind result_kind;
    struct sg_argument_spec arguments[6];
};

const struct sg_syscall_descriptor *sg_syscall_catalog(size_t *count);
const struct sg_syscall_descriptor *sg_syscall_by_name(const char *name);
const struct sg_syscall_descriptor *sg_syscall_by_number(long number);
size_t sg_syscall_name_count(void);
long sg_syscall_name_max_number(void);
unsigned int sg_syscall_argument_count(long number);
const char *sg_syscall_class_name(unsigned int class_bit);
bool sg_syscall_class_by_name(const char *name, uint32_t *class_mask);

#endif
