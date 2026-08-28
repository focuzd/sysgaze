#include "sysgaze/decoder.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/sched.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "sysgaze/syscall_catalog.h"

#define SG_SOCK_TYPE_MASK UINT32_C(0x0f)

enum argument_kind {
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
    ARG_UTS_OUT
};

enum result_kind {
    RESULT_INTEGER,
    RESULT_POINTER
};

struct argument_spec {
    enum argument_kind kind;
    uint8_t auxiliary;
};

struct syscall_signature {
    long number;
    uint8_t argument_count;
    enum result_kind result_kind;
    struct argument_spec arguments[6];
};

struct flag_name {
    uint64_t value;
    const char *name;
};

#define ARG(kind_value) { (kind_value), 0U }
#define ARG_AUX(kind_value, auxiliary_value) \
    { (kind_value), (auxiliary_value) }
#define SIG0(syscall_name) \
    { SYS_##syscall_name, 0U, RESULT_INTEGER, {{0}} }
#define SIG(syscall_name, result, count, ...) \
    { SYS_##syscall_name, (count), (result), {__VA_ARGS__} }

static const struct syscall_signature signatures[] = {
    SIG(read, RESULT_INTEGER, 3U,
        ARG(ARG_FD), ARG_AUX(ARG_BUFFER_OUT, 2U), ARG(ARG_SIZE)),
    SIG(write, RESULT_INTEGER, 3U,
        ARG(ARG_FD), ARG_AUX(ARG_BUFFER_IN, 2U), ARG(ARG_SIZE)),
    SIG(open, RESULT_INTEGER, 3U,
        ARG(ARG_STRING), ARG(ARG_OPEN_FLAGS), ARG(ARG_MODE)),
    SIG(close, RESULT_INTEGER, 1U, ARG(ARG_FD)),
    SIG(stat, RESULT_INTEGER, 2U, ARG(ARG_STRING), ARG(ARG_POINTER)),
    SIG(fstat, RESULT_INTEGER, 2U, ARG(ARG_FD), ARG(ARG_POINTER)),
    SIG(lstat, RESULT_INTEGER, 2U, ARG(ARG_STRING), ARG(ARG_POINTER)),
    SIG(poll, RESULT_INTEGER, 3U,
        ARG(ARG_POINTER), ARG(ARG_U64), ARG(ARG_S32)),
    SIG(lseek, RESULT_INTEGER, 3U,
        ARG(ARG_FD), ARG(ARG_U64), ARG(ARG_WHENCE)),
    SIG(mmap, RESULT_POINTER, 6U,
        ARG(ARG_POINTER), ARG(ARG_SIZE), ARG(ARG_PROT_FLAGS),
        ARG(ARG_MAP_FLAGS), ARG(ARG_FD), ARG(ARG_U64)),
    SIG(mprotect, RESULT_INTEGER, 3U,
        ARG(ARG_POINTER), ARG(ARG_SIZE), ARG(ARG_PROT_FLAGS)),
    SIG(munmap, RESULT_INTEGER, 2U, ARG(ARG_POINTER), ARG(ARG_SIZE)),
    SIG(brk, RESULT_POINTER, 1U, ARG(ARG_POINTER)),
    SIG(rt_sigaction, RESULT_INTEGER, 4U,
        ARG(ARG_SIGNAL), ARG(ARG_POINTER), ARG(ARG_POINTER), ARG(ARG_SIZE)),
    SIG(rt_sigprocmask, RESULT_INTEGER, 4U,
        ARG(ARG_SIGMASK_HOW), ARG(ARG_POINTER), ARG(ARG_POINTER), ARG(ARG_SIZE)),
    SIG0(rt_sigreturn),
    SIG(ioctl, RESULT_INTEGER, 3U,
        ARG(ARG_FD), ARG(ARG_HEX), ARG(ARG_POINTER)),
    SIG(pread64, RESULT_INTEGER, 4U,
        ARG(ARG_FD), ARG_AUX(ARG_BUFFER_OUT, 2U), ARG(ARG_SIZE), ARG(ARG_U64)),
    SIG(pwrite64, RESULT_INTEGER, 4U,
        ARG(ARG_FD), ARG_AUX(ARG_BUFFER_IN, 2U), ARG(ARG_SIZE), ARG(ARG_U64)),
    SIG(readv, RESULT_INTEGER, 3U,
        ARG(ARG_FD), ARG(ARG_POINTER), ARG(ARG_U64)),
    SIG(writev, RESULT_INTEGER, 3U,
        ARG(ARG_FD), ARG(ARG_POINTER), ARG(ARG_U64)),
    SIG(access, RESULT_INTEGER, 2U, ARG(ARG_STRING), ARG(ARG_ACCESS_FLAGS)),
    SIG(pipe, RESULT_INTEGER, 1U, ARG(ARG_PIPE_OUT)),
    SIG(select, RESULT_INTEGER, 5U,
        ARG(ARG_S32), ARG(ARG_POINTER), ARG(ARG_POINTER), ARG(ARG_POINTER),
        ARG(ARG_POINTER)),
    SIG0(sched_yield),
    SIG(mremap, RESULT_POINTER, 5U,
        ARG(ARG_POINTER), ARG(ARG_SIZE), ARG(ARG_SIZE), ARG(ARG_HEX),
        ARG(ARG_POINTER)),
    SIG(msync, RESULT_INTEGER, 3U,
        ARG(ARG_POINTER), ARG(ARG_SIZE), ARG(ARG_HEX)),
    SIG(mincore, RESULT_INTEGER, 3U,
        ARG(ARG_POINTER), ARG(ARG_SIZE), ARG(ARG_POINTER)),
    SIG(madvise, RESULT_INTEGER, 3U,
        ARG(ARG_POINTER), ARG(ARG_SIZE), ARG(ARG_S32)),
    SIG(dup, RESULT_INTEGER, 1U, ARG(ARG_FD)),
    SIG(dup2, RESULT_INTEGER, 2U, ARG(ARG_FD), ARG(ARG_FD)),
    SIG(nanosleep, RESULT_INTEGER, 2U,
        ARG(ARG_TIMESPEC_IN), ARG(ARG_POINTER)),
    SIG0(getpid),
    SIG(sendfile, RESULT_INTEGER, 4U,
        ARG(ARG_FD), ARG(ARG_FD), ARG(ARG_POINTER), ARG(ARG_SIZE)),
    SIG(socket, RESULT_INTEGER, 3U,
        ARG(ARG_SOCKET_DOMAIN), ARG(ARG_SOCKET_TYPE), ARG(ARG_S32)),
    SIG(connect, RESULT_INTEGER, 3U,
        ARG(ARG_FD), ARG_AUX(ARG_SOCKADDR_IN, 2U), ARG(ARG_SIZE)),
    SIG(accept, RESULT_INTEGER, 3U,
        ARG(ARG_FD), ARG(ARG_POINTER), ARG(ARG_POINTER)),
    SIG(sendto, RESULT_INTEGER, 6U,
        ARG(ARG_FD), ARG_AUX(ARG_BUFFER_IN, 2U), ARG(ARG_SIZE), ARG(ARG_HEX),
        ARG_AUX(ARG_SOCKADDR_IN, 5U), ARG(ARG_SIZE)),
    SIG(recvfrom, RESULT_INTEGER, 6U,
        ARG(ARG_FD), ARG_AUX(ARG_BUFFER_OUT, 2U), ARG(ARG_SIZE), ARG(ARG_HEX),
        ARG(ARG_POINTER), ARG(ARG_POINTER)),
    SIG(sendmsg, RESULT_INTEGER, 3U,
        ARG(ARG_FD), ARG(ARG_POINTER), ARG(ARG_HEX)),
    SIG(recvmsg, RESULT_INTEGER, 3U,
        ARG(ARG_FD), ARG(ARG_POINTER), ARG(ARG_HEX)),
    SIG(shutdown, RESULT_INTEGER, 2U, ARG(ARG_FD), ARG(ARG_SHUTDOWN_HOW)),
    SIG(bind, RESULT_INTEGER, 3U,
        ARG(ARG_FD), ARG_AUX(ARG_SOCKADDR_IN, 2U), ARG(ARG_SIZE)),
    SIG(listen, RESULT_INTEGER, 2U, ARG(ARG_FD), ARG(ARG_S32)),
    SIG(getsockname, RESULT_INTEGER, 3U,
        ARG(ARG_FD), ARG(ARG_POINTER), ARG(ARG_POINTER)),
    SIG(getpeername, RESULT_INTEGER, 3U,
        ARG(ARG_FD), ARG(ARG_POINTER), ARG(ARG_POINTER)),
    SIG(socketpair, RESULT_INTEGER, 4U,
        ARG(ARG_SOCKET_DOMAIN), ARG(ARG_SOCKET_TYPE), ARG(ARG_S32),
        ARG(ARG_PIPE_OUT)),
    SIG(setsockopt, RESULT_INTEGER, 5U,
        ARG(ARG_FD), ARG(ARG_S32), ARG(ARG_S32), ARG(ARG_POINTER), ARG(ARG_SIZE)),
    SIG(getsockopt, RESULT_INTEGER, 5U,
        ARG(ARG_FD), ARG(ARG_S32), ARG(ARG_S32), ARG(ARG_POINTER), ARG(ARG_POINTER)),
    SIG(clone, RESULT_INTEGER, 5U,
        ARG(ARG_CLONE_FLAGS), ARG(ARG_POINTER), ARG(ARG_POINTER),
        ARG(ARG_POINTER), ARG(ARG_HEX)),
    SIG0(fork),
    SIG0(vfork),
    SIG(execve, RESULT_INTEGER, 3U,
        ARG(ARG_STRING), ARG(ARG_ARGV), ARG(ARG_POINTER)),
    SIG(exit, RESULT_INTEGER, 1U, ARG(ARG_S32)),
    SIG(wait4, RESULT_INTEGER, 4U,
        ARG(ARG_S32), ARG(ARG_POINTER), ARG(ARG_HEX), ARG(ARG_POINTER)),
    SIG(kill, RESULT_INTEGER, 2U, ARG(ARG_S32), ARG(ARG_SIGNAL)),
    SIG(uname, RESULT_INTEGER, 1U, ARG(ARG_UTS_OUT)),
    SIG(fcntl, RESULT_INTEGER, 3U,
        ARG(ARG_FD), ARG(ARG_FCNTL_COMMAND), ARG(ARG_HEX)),
    SIG(fsync, RESULT_INTEGER, 1U, ARG(ARG_FD)),
    SIG(fdatasync, RESULT_INTEGER, 1U, ARG(ARG_FD)),
    SIG(truncate, RESULT_INTEGER, 2U, ARG(ARG_STRING), ARG(ARG_U64)),
    SIG(ftruncate, RESULT_INTEGER, 2U, ARG(ARG_FD), ARG(ARG_U64)),
    SIG(getdents, RESULT_INTEGER, 3U,
        ARG(ARG_FD), ARG(ARG_POINTER), ARG(ARG_SIZE)),
    SIG(getcwd, RESULT_INTEGER, 2U,
        ARG_AUX(ARG_STRING_OUT, 1U), ARG(ARG_SIZE)),
    SIG(chdir, RESULT_INTEGER, 1U, ARG(ARG_STRING)),
    SIG(rename, RESULT_INTEGER, 2U, ARG(ARG_STRING), ARG(ARG_STRING)),
    SIG(mkdir, RESULT_INTEGER, 2U, ARG(ARG_STRING), ARG(ARG_MODE)),
    SIG(rmdir, RESULT_INTEGER, 1U, ARG(ARG_STRING)),
    SIG(creat, RESULT_INTEGER, 2U, ARG(ARG_STRING), ARG(ARG_MODE)),
    SIG(link, RESULT_INTEGER, 2U, ARG(ARG_STRING), ARG(ARG_STRING)),
    SIG(unlink, RESULT_INTEGER, 1U, ARG(ARG_STRING)),
    SIG(symlink, RESULT_INTEGER, 2U, ARG(ARG_STRING), ARG(ARG_STRING)),
    SIG(readlink, RESULT_INTEGER, 3U,
        ARG(ARG_STRING), ARG_AUX(ARG_BUFFER_OUT, 2U), ARG(ARG_SIZE)),
    SIG(chmod, RESULT_INTEGER, 2U, ARG(ARG_STRING), ARG(ARG_MODE)),
    SIG(fchmod, RESULT_INTEGER, 2U, ARG(ARG_FD), ARG(ARG_MODE)),
    SIG(chown, RESULT_INTEGER, 3U,
        ARG(ARG_STRING), ARG(ARG_U64), ARG(ARG_U64)),
    SIG(fchown, RESULT_INTEGER, 3U,
        ARG(ARG_FD), ARG(ARG_U64), ARG(ARG_U64)),
    SIG0(getuid),
    SIG0(getgid),
    SIG0(geteuid),
    SIG0(getegid),
    SIG0(getppid),
    SIG0(setsid),
    SIG(sigaltstack, RESULT_INTEGER, 2U, ARG(ARG_POINTER), ARG(ARG_POINTER)),
    SIG(arch_prctl, RESULT_INTEGER, 2U, ARG(ARG_S32), ARG(ARG_POINTER)),
    SIG(futex, RESULT_INTEGER, 6U,
        ARG(ARG_POINTER), ARG(ARG_S32), ARG(ARG_U64), ARG(ARG_POINTER),
        ARG(ARG_POINTER), ARG(ARG_U64)),
    SIG(exit_group, RESULT_INTEGER, 1U, ARG(ARG_S32)),
    SIG(epoll_wait, RESULT_INTEGER, 4U,
        ARG(ARG_FD), ARG(ARG_POINTER), ARG(ARG_S32), ARG(ARG_S32)),
    SIG(epoll_ctl, RESULT_INTEGER, 4U,
        ARG(ARG_FD), ARG(ARG_EPOLL_OPERATION), ARG(ARG_FD), ARG(ARG_POINTER)),
    SIG(openat, RESULT_INTEGER, 4U,
        ARG(ARG_DIRFD), ARG(ARG_STRING), ARG(ARG_OPEN_FLAGS), ARG(ARG_MODE)),
    SIG(newfstatat, RESULT_INTEGER, 4U,
        ARG(ARG_DIRFD), ARG(ARG_STRING), ARG(ARG_POINTER), ARG(ARG_AT_FLAGS)),
    SIG(unlinkat, RESULT_INTEGER, 3U,
        ARG(ARG_DIRFD), ARG(ARG_STRING), ARG(ARG_AT_FLAGS)),
    SIG(renameat, RESULT_INTEGER, 4U,
        ARG(ARG_DIRFD), ARG(ARG_STRING), ARG(ARG_DIRFD), ARG(ARG_STRING)),
    SIG(linkat, RESULT_INTEGER, 5U,
        ARG(ARG_DIRFD), ARG(ARG_STRING), ARG(ARG_DIRFD), ARG(ARG_STRING),
        ARG(ARG_AT_FLAGS)),
    SIG(symlinkat, RESULT_INTEGER, 3U,
        ARG(ARG_STRING), ARG(ARG_DIRFD), ARG(ARG_STRING)),
    SIG(readlinkat, RESULT_INTEGER, 4U,
        ARG(ARG_DIRFD), ARG(ARG_STRING), ARG_AUX(ARG_BUFFER_OUT, 3U),
        ARG(ARG_SIZE)),
    SIG(pselect6, RESULT_INTEGER, 6U,
        ARG(ARG_S32), ARG(ARG_POINTER), ARG(ARG_POINTER), ARG(ARG_POINTER),
        ARG(ARG_POINTER), ARG(ARG_POINTER)),
    SIG(ppoll, RESULT_INTEGER, 5U,
        ARG(ARG_POINTER), ARG(ARG_U64), ARG(ARG_POINTER), ARG(ARG_POINTER),
        ARG(ARG_SIZE)),
    SIG(unshare, RESULT_INTEGER, 1U, ARG(ARG_CLONE_FLAGS)),
    SIG(splice, RESULT_INTEGER, 6U,
        ARG(ARG_FD), ARG(ARG_POINTER), ARG(ARG_FD), ARG(ARG_POINTER),
        ARG(ARG_SIZE), ARG(ARG_HEX)),
    SIG(tee, RESULT_INTEGER, 4U,
        ARG(ARG_FD), ARG(ARG_FD), ARG(ARG_SIZE), ARG(ARG_HEX)),
    SIG(vmsplice, RESULT_INTEGER, 4U,
        ARG(ARG_FD), ARG(ARG_POINTER), ARG(ARG_U64), ARG(ARG_HEX)),
    SIG(accept4, RESULT_INTEGER, 4U,
        ARG(ARG_FD), ARG(ARG_POINTER), ARG(ARG_POINTER), ARG(ARG_SOCKET_TYPE)),
    SIG(dup3, RESULT_INTEGER, 3U,
        ARG(ARG_FD), ARG(ARG_FD), ARG(ARG_FD_FLAGS)),
    SIG(pipe2, RESULT_INTEGER, 2U, ARG(ARG_PIPE_OUT), ARG(ARG_FD_FLAGS)),
    SIG(preadv, RESULT_INTEGER, 5U,
        ARG(ARG_FD), ARG(ARG_POINTER), ARG(ARG_U64), ARG(ARG_U64), ARG(ARG_U64)),
    SIG(pwritev, RESULT_INTEGER, 5U,
        ARG(ARG_FD), ARG(ARG_POINTER), ARG(ARG_U64), ARG(ARG_U64), ARG(ARG_U64)),
    SIG(process_vm_readv, RESULT_INTEGER, 6U,
        ARG(ARG_S32), ARG(ARG_POINTER), ARG(ARG_U64), ARG(ARG_POINTER),
        ARG(ARG_U64), ARG(ARG_HEX)),
    SIG(process_vm_writev, RESULT_INTEGER, 6U,
        ARG(ARG_S32), ARG(ARG_POINTER), ARG(ARG_U64), ARG(ARG_POINTER),
        ARG(ARG_U64), ARG(ARG_HEX)),
    SIG(execveat, RESULT_INTEGER, 5U,
        ARG(ARG_DIRFD), ARG(ARG_STRING), ARG(ARG_ARGV), ARG(ARG_POINTER),
        ARG(ARG_AT_FLAGS)),
    SIG(preadv2, RESULT_INTEGER, 6U,
        ARG(ARG_FD), ARG(ARG_POINTER), ARG(ARG_U64), ARG(ARG_U64), ARG(ARG_U64),
        ARG(ARG_HEX)),
    SIG(pwritev2, RESULT_INTEGER, 6U,
        ARG(ARG_FD), ARG(ARG_POINTER), ARG(ARG_U64), ARG(ARG_U64), ARG(ARG_U64),
        ARG(ARG_HEX)),
    SIG(clone3, RESULT_INTEGER, 2U, ARG(ARG_POINTER), ARG(ARG_SIZE)),
    SIG(close_range, RESULT_INTEGER, 3U,
        ARG(ARG_U64), ARG(ARG_U64), ARG(ARG_HEX)),
    SIG(openat2, RESULT_INTEGER, 4U,
        ARG(ARG_DIRFD), ARG(ARG_STRING), ARG(ARG_POINTER), ARG(ARG_SIZE)),
    SIG(getrandom, RESULT_INTEGER, 3U,
        ARG_AUX(ARG_BUFFER_OUT, 1U), ARG(ARG_SIZE), ARG(ARG_HEX)),
    SIG(statx, RESULT_INTEGER, 5U,
        ARG(ARG_DIRFD), ARG(ARG_STRING), ARG(ARG_AT_FLAGS), ARG(ARG_HEX),
        ARG(ARG_POINTER))
};

static const struct flag_name open_flag_names[] = {
    {O_CREAT, "O_CREAT"}, {O_EXCL, "O_EXCL"}, {O_NOCTTY, "O_NOCTTY"},
    {O_TRUNC, "O_TRUNC"}, {O_APPEND, "O_APPEND"},
    {O_NONBLOCK, "O_NONBLOCK"}, {O_SYNC, "O_SYNC"},
    {O_DSYNC, "O_DSYNC"},
    {O_DIRECT, "O_DIRECT"}, {O_LARGEFILE, "O_LARGEFILE"},
    {O_TMPFILE, "O_TMPFILE"}, {O_DIRECTORY, "O_DIRECTORY"},
    {O_NOFOLLOW, "O_NOFOLLOW"},
    {O_CLOEXEC, "O_CLOEXEC"},
    {O_PATH, "O_PATH"}
};

static const struct flag_name prot_flag_names[] = {
    {PROT_READ, "PROT_READ"}, {PROT_WRITE, "PROT_WRITE"},
    {PROT_EXEC, "PROT_EXEC"}, {PROT_GROWSDOWN, "PROT_GROWSDOWN"},
    {PROT_GROWSUP, "PROT_GROWSUP"}
};

static const struct flag_name map_flag_names[] = {
#ifdef MAP_SHARED_VALIDATE
    {MAP_SHARED_VALIDATE, "MAP_SHARED_VALIDATE"},
#endif
    {MAP_SHARED, "MAP_SHARED"}, {MAP_PRIVATE, "MAP_PRIVATE"},
    {MAP_FIXED, "MAP_FIXED"}, {MAP_ANONYMOUS, "MAP_ANONYMOUS"},
    {MAP_GROWSDOWN, "MAP_GROWSDOWN"}, {MAP_DENYWRITE, "MAP_DENYWRITE"},
    {MAP_EXECUTABLE, "MAP_EXECUTABLE"}, {MAP_LOCKED, "MAP_LOCKED"},
    {MAP_NORESERVE, "MAP_NORESERVE"}, {MAP_POPULATE, "MAP_POPULATE"},
    {MAP_NONBLOCK, "MAP_NONBLOCK"}, {MAP_STACK, "MAP_STACK"},
    {MAP_HUGETLB, "MAP_HUGETLB"}, {MAP_SYNC, "MAP_SYNC"},
    {MAP_FIXED_NOREPLACE, "MAP_FIXED_NOREPLACE"}
};

static const struct flag_name clone_flag_names[] = {
    {CLONE_VM, "CLONE_VM"}, {CLONE_FS, "CLONE_FS"},
    {CLONE_FILES, "CLONE_FILES"}, {CLONE_SIGHAND, "CLONE_SIGHAND"},
    {CLONE_PIDFD, "CLONE_PIDFD"}, {CLONE_PTRACE, "CLONE_PTRACE"},
    {CLONE_VFORK, "CLONE_VFORK"}, {CLONE_PARENT, "CLONE_PARENT"},
    {CLONE_THREAD, "CLONE_THREAD"}, {CLONE_NEWNS, "CLONE_NEWNS"},
    {CLONE_SYSVSEM, "CLONE_SYSVSEM"}, {CLONE_SETTLS, "CLONE_SETTLS"},
    {CLONE_PARENT_SETTID, "CLONE_PARENT_SETTID"},
    {CLONE_CHILD_CLEARTID, "CLONE_CHILD_CLEARTID"},
    {CLONE_DETACHED, "CLONE_DETACHED"},
    {CLONE_UNTRACED, "CLONE_UNTRACED"},
    {CLONE_CHILD_SETTID, "CLONE_CHILD_SETTID"},
    {CLONE_NEWCGROUP, "CLONE_NEWCGROUP"}, {CLONE_NEWUTS, "CLONE_NEWUTS"},
    {CLONE_NEWIPC, "CLONE_NEWIPC"}, {CLONE_NEWUSER, "CLONE_NEWUSER"},
    {CLONE_NEWPID, "CLONE_NEWPID"}, {CLONE_NEWNET, "CLONE_NEWNET"},
    {CLONE_IO, "CLONE_IO"}
};

static const struct syscall_signature *find_signature(long number)
{
    size_t index;

    for (index = 0U; index < sizeof(signatures) / sizeof(signatures[0]);
         ++index) {
        if (signatures[index].number == number) {
            return &signatures[index];
        }
    }
    return NULL;
}

static uint8_t effective_argument_count(
    const struct syscall_signature *signature,
    const struct sg_syscall_event *event)
{
    uint64_t flags;

    if (event->number == SYS_open) {
        flags = event->arguments[1];
    } else if (event->number == SYS_openat) {
        flags = event->arguments[2];
    } else if (event->number == SYS_fcntl) {
        int command = (int)(uint32_t)event->arguments[1];

        return command == F_GETFD || command == F_GETFL
                   ? 2U
                   : signature->argument_count;
    } else {
        return signature->argument_count;
    }
    return (flags & ((uint64_t)O_CREAT | (uint64_t)O_TMPFILE)) != 0U
               ? signature->argument_count
               : (uint8_t)(signature->argument_count - 1U);
}

static bool append_pointer(struct sg_buffer *output, uint64_t value)
{
    return value == 0U ? sg_buffer_append_cstr(output, "NULL")
                       : sg_buffer_append_format(output, "0x%" PRIx64, value);
}

static bool read_memory(const struct sg_decoder *decoder, pid_t tid,
                        uint64_t address, void *destination, size_t length,
                        size_t *bytes_read)
{
    *bytes_read = 0U;
    if (address == 0U || decoder->memory.read == NULL) {
        return false;
    }
    return decoder->memory.read(decoder->memory.context, tid,
                                (uintptr_t)address, destination, length,
                                bytes_read);
}

static bool append_escaped(struct sg_buffer *output,
                           const unsigned char *data, size_t length)
{
    size_t index;

    if (!sg_buffer_append_cstr(output, "\"")) {
        return false;
    }
    for (index = 0U; index < length; ++index) {
        unsigned char byte = data[index];

        switch (byte) {
        case '\\':
            if (!sg_buffer_append_cstr(output, "\\\\")) {
                return false;
            }
            break;
        case '"':
            if (!sg_buffer_append_cstr(output, "\\\"")) {
                return false;
            }
            break;
        case '\n':
            if (!sg_buffer_append_cstr(output, "\\n")) {
                return false;
            }
            break;
        case '\r':
            if (!sg_buffer_append_cstr(output, "\\r")) {
                return false;
            }
            break;
        case '\t':
            if (!sg_buffer_append_cstr(output, "\\t")) {
                return false;
            }
            break;
        case '\0':
            if (!sg_buffer_append_cstr(output, "\\0")) {
                return false;
            }
            break;
        default:
            if (isprint((int)byte) != 0) {
                if (!sg_buffer_append(output, &byte, 1U)) {
                    return false;
                }
            } else if (!sg_buffer_append_format(output, "\\x%02x",
                                                (unsigned int)byte)) {
                return false;
            }
            break;
        }
    }
    return sg_buffer_append_cstr(output, "\"");
}

static bool append_remote_bytes(const struct sg_decoder *decoder, pid_t tid,
                                uint64_t address, size_t requested,
                                bool stop_at_nul, struct sg_buffer *output)
{
    size_t limit = decoder->string_limit;
    size_t amount = requested < limit ? requested : limit;
    unsigned char *data;
    size_t bytes_read;
    size_t shown;
    bool readable;
    bool truncated;

    if (address == 0U) {
        return sg_buffer_append_cstr(output, "NULL");
    }
    if (amount == 0U) {
        return sg_buffer_append_cstr(output,
                                     requested == 0U ? "\"\"" : "\"\"...");
    }
    data = malloc(amount);
    if (data == NULL) {
        return false;
    }
    readable = read_memory(decoder, tid, address, data, amount, &bytes_read);
    if (!readable || bytes_read == 0U) {
        free(data);
        return append_pointer(output, address);
    }

    shown = bytes_read;
    truncated = bytes_read < requested;
    if (stop_at_nul) {
        unsigned char *terminator = memchr(data, '\0', bytes_read);

        if (terminator != NULL) {
            shown = (size_t)(terminator - data);
            truncated = false;
        } else {
            truncated = true;
        }
    } else if (requested > amount) {
        truncated = true;
    }
    readable = append_escaped(output, data, shown);
    free(data);
    if (!readable) {
        return false;
    }
    return !truncated || sg_buffer_append_cstr(output, "...");
}

static bool append_string(const struct sg_decoder *decoder, pid_t tid,
                          uint64_t address, struct sg_buffer *output)
{
    size_t requested = decoder->string_limit == SIZE_MAX
                           ? SIZE_MAX
                           : decoder->string_limit + 1U;

    return append_remote_bytes(decoder, tid, address, requested, true, output);
}

static bool append_flags(struct sg_buffer *output, uint64_t value,
                         const struct flag_name *names, size_t name_count,
                         const char *zero_name)
{
    uint64_t remaining = value;
    bool wrote = false;
    size_t index;

    if (value == 0U && zero_name != NULL) {
        return sg_buffer_append_cstr(output, zero_name);
    }
    for (index = 0U; index < name_count; ++index) {
        if (names[index].value != 0U &&
            (remaining & names[index].value) == names[index].value) {
            if (wrote && !sg_buffer_append_cstr(output, "|")) {
                return false;
            }
            if (!sg_buffer_append_cstr(output, names[index].name)) {
                return false;
            }
            remaining &= ~names[index].value;
            wrote = true;
        }
    }
    if (remaining != 0U || !wrote) {
        if (wrote && !sg_buffer_append_cstr(output, "|")) {
            return false;
        }
        return sg_buffer_append_format(output, "0x%" PRIx64, remaining);
    }
    return true;
}

static bool append_open_flags(struct sg_buffer *output, uint64_t value)
{
    uint64_t access_mode = value & (uint64_t)O_ACCMODE;
    const char *access_name = access_mode == (uint64_t)O_WRONLY
                                  ? "O_WRONLY"
                              : access_mode == (uint64_t)O_RDWR
                                  ? "O_RDWR"
                                  : "O_RDONLY";
    uint64_t remaining = value & ~(uint64_t)O_ACCMODE;

    if (!sg_buffer_append_cstr(output, access_name)) {
        return false;
    }
    if (remaining == 0U) {
        return true;
    }
    if (!sg_buffer_append_cstr(output, "|")) {
        return false;
    }
    return append_flags(output, remaining, open_flag_names,
                        sizeof(open_flag_names) / sizeof(open_flag_names[0]),
                        NULL);
}

static bool append_signal(struct sg_buffer *output, uint64_t value)
{
    int signal_number = (int)(uint32_t)value;
    const char *abbreviation = sigabbrev_np(signal_number);

    return abbreviation == NULL
               ? sg_buffer_append_format(output, "%d", signal_number)
               : sg_buffer_append_format(output, "SIG%s", abbreviation);
}

static bool append_clone_flags(struct sg_buffer *output, uint64_t value)
{
    uint64_t flags = value & ~(uint64_t)CSIGNAL;
    unsigned int signal_number = (unsigned int)(value & (uint64_t)CSIGNAL);

    if (!append_flags(output, flags, clone_flag_names,
                      sizeof(clone_flag_names) / sizeof(clone_flag_names[0]),
                      "0")) {
        return false;
    }
    if (signal_number == 0U) {
        return true;
    }
    return sg_buffer_append_cstr(output, "|") &&
           append_signal(output, signal_number);
}

static bool append_named_integer(struct sg_buffer *output, int value,
                                 const int *values, const char *const *names,
                                 size_t count)
{
    size_t index;

    for (index = 0U; index < count; ++index) {
        if (values[index] == value) {
            return sg_buffer_append_cstr(output, names[index]);
        }
    }
    return sg_buffer_append_format(output, "%d", value);
}

static bool append_socket_domain(struct sg_buffer *output, uint64_t value)
{
    static const struct {
        int value;
        const char *name;
    } domains[] = {
        {AF_UNSPEC, "AF_UNSPEC"}, {AF_UNIX, "AF_UNIX"},
        {AF_INET, "AF_INET"}, {AF_INET6, "AF_INET6"},
        {AF_NETLINK, "AF_NETLINK"}, {AF_PACKET, "AF_PACKET"}
    };
    size_t index;
    int domain = (int)(uint32_t)value;

    for (index = 0U; index < sizeof(domains) / sizeof(domains[0]); ++index) {
        if (domains[index].value == domain) {
            return sg_buffer_append_cstr(output, domains[index].name);
        }
    }
    return sg_buffer_append_format(output, "%d", domain);
}

static bool append_socket_type(struct sg_buffer *output, uint64_t value)
{
    int base = (int)((uint32_t)value & SG_SOCK_TYPE_MASK);
    uint64_t flags = value & ~(uint64_t)SG_SOCK_TYPE_MASK;
    const char *name = base == SOCK_STREAM   ? "SOCK_STREAM"
                       : base == SOCK_DGRAM  ? "SOCK_DGRAM"
                       : base == SOCK_RAW    ? "SOCK_RAW"
                       : base == SOCK_SEQPACKET ? "SOCK_SEQPACKET"
                                                : NULL;

    if (name == NULL) {
        if (!sg_buffer_append_format(output, "%d", base)) {
            return false;
        }
    } else if (!sg_buffer_append_cstr(output, name)) {
        return false;
    }
    if ((flags & (uint64_t)SOCK_NONBLOCK) != 0U) {
        if (!sg_buffer_append_cstr(output, "|SOCK_NONBLOCK")) {
            return false;
        }
        flags &= ~(uint64_t)SOCK_NONBLOCK;
    }
    if ((flags & (uint64_t)SOCK_CLOEXEC) != 0U) {
        if (!sg_buffer_append_cstr(output, "|SOCK_CLOEXEC")) {
            return false;
        }
        flags &= ~(uint64_t)SOCK_CLOEXEC;
    }
    return flags == 0U || sg_buffer_append_format(output, "|0x%" PRIx64, flags);
}

static bool append_sockaddr(const struct sg_decoder *decoder, pid_t tid,
                            uint64_t address, size_t length,
                            struct sg_buffer *output)
{
    struct sockaddr_storage storage = {0};
    size_t amount = length < sizeof(storage) ? length : sizeof(storage);
    size_t bytes_read;

    if (address == 0U) {
        return sg_buffer_append_cstr(output, "NULL");
    }
    if (amount < sizeof(sa_family_t) ||
        !read_memory(decoder, tid, address, &storage, amount, &bytes_read) ||
        bytes_read < sizeof(sa_family_t)) {
        return append_pointer(output, address);
    }
    if (storage.ss_family == AF_INET &&
        bytes_read >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *address4 = (const struct sockaddr_in *)&storage;
        char text[INET_ADDRSTRLEN];

        if (inet_ntop(AF_INET, &address4->sin_addr, text, sizeof(text)) == NULL) {
            return append_pointer(output, address);
        }
        return sg_buffer_append_format(output,
                                       "{sa_family=AF_INET, sin_port=htons(%u), "
                                       "sin_addr=inet_addr(\"%s\")}",
                                       (unsigned int)ntohs(address4->sin_port), text);
    }
    if (storage.ss_family == AF_INET6 &&
        bytes_read >= sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *address6 =
            (const struct sockaddr_in6 *)&storage;
        char text[INET6_ADDRSTRLEN];

        if (inet_ntop(AF_INET6, &address6->sin6_addr, text, sizeof(text)) == NULL) {
            return append_pointer(output, address);
        }
        return sg_buffer_append_format(output,
                                       "{sa_family=AF_INET6, sin6_port=htons(%u), "
                                       "sin6_addr=inet_pton(\"%s\")}",
                                       (unsigned int)ntohs(address6->sin6_port), text);
    }
    if (storage.ss_family == AF_UNIX && bytes_read >= sizeof(sa_family_t)) {
        const struct sockaddr_un *address_unix =
            (const struct sockaddr_un *)&storage;
        size_t path_offset = offsetof(struct sockaddr_un, sun_path);
        size_t path_length = bytes_read > path_offset ? bytes_read - path_offset : 0U;
        const unsigned char *path = (const unsigned char *)address_unix->sun_path;

        if (!sg_buffer_append_cstr(output, "{sa_family=AF_UNIX, sun_path=")) {
            return false;
        }
        if (path_length > 0U && path[0] == '\0') {
            if (!sg_buffer_append_cstr(output, "@") ||
                !append_escaped(output, path + 1U, path_length - 1U)) {
                return false;
            }
        } else {
            size_t shown = 0U;

            while (shown < path_length && path[shown] != '\0') {
                ++shown;
            }
            if (!append_escaped(output, path, shown)) {
                return false;
            }
        }
        return sg_buffer_append_cstr(output, "}");
    }
    return sg_buffer_append_format(output, "{sa_family=%u}",
                                   (unsigned int)storage.ss_family);
}

static bool append_argv(const struct sg_decoder *decoder, pid_t tid,
                        uint64_t address, struct sg_buffer *output)
{
    size_t index;

    if (address == 0U) {
        return sg_buffer_append_cstr(output, "NULL");
    }
    if (!sg_buffer_append_cstr(output, "[")) {
        return false;
    }
    for (index = 0U; index < 32U; ++index) {
        uint64_t pointer = 0U;
        size_t bytes_read;
        uint64_t offset = (uint64_t)index * sizeof(pointer);

        if (address > UINT64_MAX - offset ||
            !read_memory(decoder, tid, address + offset,
                         &pointer, sizeof(pointer), &bytes_read) ||
            bytes_read != sizeof(pointer)) {
            if (index != 0U && !sg_buffer_append_cstr(output, ", ")) {
                return false;
            }
            if (!sg_buffer_append_cstr(output, "?")) {
                return false;
            }
            break;
        }
        if (pointer == 0U) {
            return sg_buffer_append_cstr(output, "]");
        }
        if (index != 0U && !sg_buffer_append_cstr(output, ", ")) {
            return false;
        }
        if (!append_string(decoder, tid, pointer, output)) {
            return false;
        }
    }
    return sg_buffer_append_cstr(output, ", ...]");
}

static bool append_timespec(const struct sg_decoder *decoder, pid_t tid,
                            uint64_t address, struct sg_buffer *output)
{
    struct timespec value;
    size_t bytes_read;

    if (address == 0U) {
        return sg_buffer_append_cstr(output, "NULL");
    }
    if (!read_memory(decoder, tid, address, &value, sizeof(value), &bytes_read) ||
        bytes_read != sizeof(value)) {
        return append_pointer(output, address);
    }
    return sg_buffer_append_format(output, "{tv_sec=%lld, tv_nsec=%ld}",
                                   (long long)value.tv_sec, value.tv_nsec);
}

static bool append_pipe(const struct sg_decoder *decoder, pid_t tid,
                        const struct sg_syscall_event *event, uint64_t address,
                        struct sg_buffer *output)
{
    int descriptors[2];
    size_t bytes_read;

    if (event->error_number != 0 ||
        !read_memory(decoder, tid, address, descriptors, sizeof(descriptors),
                     &bytes_read) ||
        bytes_read != sizeof(descriptors)) {
        return append_pointer(output, address);
    }
    return sg_buffer_append_format(output, "[%d, %d]", descriptors[0],
                                   descriptors[1]);
}

static bool append_uts(const struct sg_decoder *decoder, pid_t tid,
                       const struct sg_syscall_event *event, uint64_t address,
                       struct sg_buffer *output)
{
    struct utsname value;
    size_t bytes_read;

    if (event->error_number != 0 ||
        !read_memory(decoder, tid, address, &value, sizeof(value), &bytes_read) ||
        bytes_read != sizeof(value)) {
        return append_pointer(output, address);
    }
    return sg_buffer_append_format(output,
                                   "{sysname=\"%.*s\", nodename=\"%.*s\", "
                                   "release=\"%.*s\", machine=\"%.*s\"}",
                                   (int)sizeof(value.sysname), value.sysname,
                                   (int)sizeof(value.nodename), value.nodename,
                                   (int)sizeof(value.release), value.release,
                                   (int)sizeof(value.machine), value.machine);
}

static bool is_output_argument(enum argument_kind kind)
{
    return kind == ARG_STRING_OUT || kind == ARG_BUFFER_OUT ||
           kind == ARG_PIPE_OUT || kind == ARG_UTS_OUT;
}

static bool render_argument(const struct sg_decoder *decoder, pid_t tid,
                            const struct sg_syscall_event *event,
                            const struct argument_spec *spec, size_t index,
                            struct sg_buffer *output)
{
    uint64_t value = event->arguments[index];
    size_t length;

    switch (spec->kind) {
    case ARG_HEX:
        return sg_buffer_append_format(output, "0x%" PRIx64, value);
    case ARG_S32:
        return sg_buffer_append_format(output, "%" PRId32,
                                       (int32_t)(uint32_t)value);
    case ARG_U64:
    case ARG_SIZE:
        return sg_buffer_append_format(output, "%" PRIu64, value);
    case ARG_FD:
        return sg_buffer_append_format(output, "%" PRId32,
                                       (int32_t)(uint32_t)value);
    case ARG_DIRFD:
        return (int32_t)(uint32_t)value == AT_FDCWD
                   ? sg_buffer_append_cstr(output, "AT_FDCWD")
                   : sg_buffer_append_format(output, "%" PRId32,
                                             (int32_t)(uint32_t)value);
    case ARG_POINTER:
        return append_pointer(output, value);
    case ARG_STRING:
        return append_string(decoder, tid, value, output);
    case ARG_STRING_OUT:
        if (event->error_number != 0) {
            return append_pointer(output, value);
        }
        length = event->result > 0 ? (size_t)event->result
                                   : (size_t)event->arguments[spec->auxiliary];
        return append_remote_bytes(decoder, tid, value, length, true, output);
    case ARG_BUFFER_IN:
        length = (size_t)event->arguments[spec->auxiliary];
        return append_remote_bytes(decoder, tid, value, length, false, output);
    case ARG_BUFFER_OUT:
        if (event->error_number != 0) {
            return append_pointer(output, value);
        }
        if (event->result == 0) {
            return sg_buffer_append_cstr(output, "\"\"");
        }
        if (event->result < 0) {
            return append_pointer(output, value);
        }
        length = (size_t)event->result;
        if (length > (size_t)event->arguments[spec->auxiliary]) {
            length = (size_t)event->arguments[spec->auxiliary];
        }
        return append_remote_bytes(decoder, tid, value, length, false, output);
    case ARG_ARGV:
        return append_argv(decoder, tid, value, output);
    case ARG_MODE:
        return sg_buffer_append_format(output, "0%" PRIo64, value);
    case ARG_OPEN_FLAGS:
        return append_open_flags(output, value);
    case ARG_FD_FLAGS: {
        static const struct flag_name names[] = {
            {O_NONBLOCK, "O_NONBLOCK"}, {O_CLOEXEC, "O_CLOEXEC"}
        };
        return append_flags(output, value, names,
                            sizeof(names) / sizeof(names[0]), "0");
    }
    case ARG_PROT_FLAGS:
        return append_flags(output, value, prot_flag_names,
                            sizeof(prot_flag_names) / sizeof(prot_flag_names[0]),
                            "PROT_NONE");
    case ARG_MAP_FLAGS:
        return append_flags(output, value, map_flag_names,
                            sizeof(map_flag_names) / sizeof(map_flag_names[0]),
                            "0");
    case ARG_CLONE_FLAGS:
        return append_clone_flags(output, value);
    case ARG_ACCESS_FLAGS: {
        static const struct flag_name names[] = {
            {R_OK, "R_OK"}, {W_OK, "W_OK"}, {X_OK, "X_OK"}
        };
        return append_flags(output, value, names,
                            sizeof(names) / sizeof(names[0]), "F_OK");
    }
    case ARG_AT_FLAGS: {
        static const struct flag_name names[] = {
            {AT_SYMLINK_NOFOLLOW, "AT_SYMLINK_NOFOLLOW"},
            {AT_REMOVEDIR, "AT_REMOVEDIR"},
            {AT_SYMLINK_FOLLOW, "AT_SYMLINK_FOLLOW"},
            {AT_EMPTY_PATH, "AT_EMPTY_PATH"}
        };
        return append_flags(output, value, names,
                            sizeof(names) / sizeof(names[0]), "0");
    }
    case ARG_SOCKET_DOMAIN:
        return append_socket_domain(output, value);
    case ARG_SOCKET_TYPE:
        return append_socket_type(output, value);
    case ARG_SIGNAL:
        return append_signal(output, value);
    case ARG_SIGMASK_HOW: {
        static const int values[] = {SIG_BLOCK, SIG_UNBLOCK, SIG_SETMASK};
        static const char *const names[] = {
            "SIG_BLOCK", "SIG_UNBLOCK", "SIG_SETMASK"
        };
        return append_named_integer(output, (int)(uint32_t)value, values, names,
                                    sizeof(values) / sizeof(values[0]));
    }
    case ARG_SHUTDOWN_HOW: {
        static const int values[] = {SHUT_RD, SHUT_WR, SHUT_RDWR};
        static const char *const names[] = {"SHUT_RD", "SHUT_WR", "SHUT_RDWR"};
        return append_named_integer(output, (int)(uint32_t)value, values, names,
                                    sizeof(values) / sizeof(values[0]));
    }
    case ARG_FCNTL_COMMAND: {
        static const int values[] = {
            F_DUPFD, F_GETFD, F_SETFD, F_GETFL, F_SETFL, F_GETLK, F_SETLK,
            F_SETLKW, F_DUPFD_CLOEXEC
        };
        static const char *const names[] = {
            "F_DUPFD", "F_GETFD", "F_SETFD", "F_GETFL", "F_SETFL",
            "F_GETLK", "F_SETLK", "F_SETLKW", "F_DUPFD_CLOEXEC"
        };
        return append_named_integer(output, (int)(uint32_t)value, values, names,
                                    sizeof(values) / sizeof(values[0]));
    }
    case ARG_EPOLL_OPERATION: {
        static const int values[] = {EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD};
        static const char *const names[] = {
            "EPOLL_CTL_ADD", "EPOLL_CTL_DEL", "EPOLL_CTL_MOD"
        };
        return append_named_integer(output, (int)(uint32_t)value, values, names,
                                    sizeof(values) / sizeof(values[0]));
    }
    case ARG_WHENCE:
        return (int32_t)(uint32_t)value == SEEK_SET
                   ? sg_buffer_append_cstr(output, "SEEK_SET")
               : (int32_t)(uint32_t)value == SEEK_CUR
                   ? sg_buffer_append_cstr(output, "SEEK_CUR")
               : (int32_t)(uint32_t)value == SEEK_END
                   ? sg_buffer_append_cstr(output, "SEEK_END")
                   : sg_buffer_append_format(output, "%" PRId32,
                                             (int32_t)(uint32_t)value);
    case ARG_SOCKADDR_IN:
        return append_sockaddr(decoder, tid, value,
                               (size_t)event->arguments[spec->auxiliary], output);
    case ARG_TIMESPEC_IN:
        return append_timespec(decoder, tid, value, output);
    case ARG_PIPE_OUT:
        return append_pipe(decoder, tid, event, value, output);
    case ARG_UTS_OUT:
        return append_uts(decoder, tid, event, value, output);
    }
    return false;
}

bool sg_decoder_capture_entry(const struct sg_decoder *decoder, pid_t tid,
                              struct sg_syscall_event *event)
{
    const struct syscall_signature *signature = find_signature(event->number);
    size_t index;

    if (signature == NULL) {
        event->argument_count =
            (uint8_t)sg_syscall_argument_count(event->number);
        return true;
    }
    event->argument_count = effective_argument_count(signature, event);
    for (index = 0U; index < event->argument_count; ++index) {
        struct sg_buffer rendered;
        char *saved;

        if (is_output_argument(signature->arguments[index].kind)) {
            continue;
        }
        sg_buffer_init(&rendered);
        if (!render_argument(decoder, tid, event, &signature->arguments[index],
                             index, &rendered)) {
            sg_buffer_destroy(&rendered);
            sg_decoder_release_event(event);
            return false;
        }
        saved = malloc(rendered.length + 1U);
        if (saved == NULL) {
            sg_buffer_destroy(&rendered);
            sg_decoder_release_event(event);
            return false;
        }
        memcpy(saved, rendered.data, rendered.length + 1U);
        event->decoded_arguments[index] = saved;
        sg_buffer_destroy(&rendered);
    }
    return true;
}

void sg_decoder_release_event(struct sg_syscall_event *event)
{
    size_t index;

    for (index = 0U; index < 6U; ++index) {
        free(event->decoded_arguments[index]);
        event->decoded_arguments[index] = NULL;
    }
}

static bool append_result(const struct syscall_signature *signature,
                          const struct sg_syscall_event *event,
                          struct sg_buffer *output)
{
    if (event->error_number != 0) {
        const char *name = strerrorname_np(event->error_number);
        const char *description = strerror(event->error_number);

        if (name == NULL) {
            return sg_buffer_append_format(output, " = -1 errno(%d)",
                                           event->error_number);
        }
        return sg_buffer_append_format(output, " = -1 %s (%s)", name,
                                       description);
    }
    if (signature != NULL && signature->result_kind == RESULT_POINTER) {
        return sg_buffer_append_format(output, " = 0x%" PRIx64,
                                       (uint64_t)event->result);
    }
    return sg_buffer_append_format(output, " = %" PRId64, event->result);
}

bool sg_decode_syscall(const struct sg_decoder *decoder, pid_t tid,
                       const struct sg_syscall_event *event,
                       struct sg_buffer *output)
{
    const struct syscall_signature *signature = find_signature(event->number);
    const struct sg_syscall_descriptor *descriptor =
        sg_syscall_by_number(event->number);
    uint8_t argument_count = signature == NULL
                                 ? event->argument_count
                                 : effective_argument_count(signature, event);
    size_t index;

    if (descriptor == NULL) {
        if (!sg_buffer_append_format(output, "syscall_%ld(", event->number)) {
            return false;
        }
    } else if (!sg_buffer_append_format(output, "%s(", descriptor->name)) {
        return false;
    }
    for (index = 0U; index < argument_count; ++index) {
        if (index != 0U && !sg_buffer_append_cstr(output, ", ")) {
            return false;
        }
        if (event->decoded_arguments[index] != NULL) {
            if (!sg_buffer_append_cstr(output, event->decoded_arguments[index])) {
                return false;
            }
        } else if (signature != NULL) {
            if (!render_argument(decoder, tid, event,
                                 &signature->arguments[index], index, output)) {
                return false;
            }
        } else if (!sg_buffer_append_format(output, "0x%" PRIx64,
                                            event->arguments[index])) {
            return false;
        }
    }
    return sg_buffer_append_cstr(output, ")") &&
           append_result(signature, event, output);
}
