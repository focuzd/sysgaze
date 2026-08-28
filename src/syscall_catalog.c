#include "sysgaze/syscall_catalog.h"

#include <string.h>
#include <sys/syscall.h>

#define DESC(syscall_name, class_mask) \
    { SYS_##syscall_name, #syscall_name, (class_mask) }

#define SYSCALL(number, syscall_name) [number] = {number, #syscall_name, 0U},
static const struct sg_syscall_descriptor syscall_names[SG_SYSCALL_LIMIT] = {
#include "syscall_names.inc"
};
#undef SYSCALL

#define ARITY(number, count, syscall_name) [number] = (uint8_t)((count) + 1U),
static const uint8_t syscall_arities[SG_SYSCALL_LIMIT] = {
#include "syscall_arities.inc"
};
#undef ARITY

/* Classification is deliberately separate from the complete name table.
 * Stage 3 grows this metadata as decoders are added; an unclassified syscall
 * still has a correct name and remains available to explicit-name filters. */
static const struct sg_syscall_descriptor classified_descriptors[] = {
    DESC(read, SG_CLASS_FILE),
    DESC(write, SG_CLASS_FILE),
    DESC(close, SG_CLASS_FILE),
    DESC(lseek, SG_CLASS_FILE),
    DESC(mmap, SG_CLASS_MEMORY),
    DESC(mprotect, SG_CLASS_MEMORY),
    DESC(munmap, SG_CLASS_MEMORY),
    DESC(brk, SG_CLASS_MEMORY),
    DESC(rt_sigaction, SG_CLASS_SIGNAL),
    DESC(rt_sigprocmask, SG_CLASS_SIGNAL),
    DESC(rt_sigreturn, SG_CLASS_SIGNAL),
    DESC(ioctl, SG_CLASS_FILE),
    DESC(pread64, SG_CLASS_FILE),
    DESC(pwrite64, SG_CLASS_FILE),
    DESC(readv, SG_CLASS_FILE),
    DESC(writev, SG_CLASS_FILE),
    DESC(access, SG_CLASS_FILE),
    DESC(pipe, SG_CLASS_FILE | SG_CLASS_IPC),
    DESC(select, SG_CLASS_FILE),
    DESC(sched_yield, SG_CLASS_PROCESS),
    DESC(mremap, SG_CLASS_MEMORY),
    DESC(msync, SG_CLASS_MEMORY),
    DESC(mincore, SG_CLASS_MEMORY),
    DESC(madvise, SG_CLASS_MEMORY),
    DESC(shmget, SG_CLASS_MEMORY | SG_CLASS_IPC),
    DESC(shmat, SG_CLASS_MEMORY | SG_CLASS_IPC),
    DESC(shmctl, SG_CLASS_MEMORY | SG_CLASS_IPC),
    DESC(dup, SG_CLASS_FILE),
    DESC(dup2, SG_CLASS_FILE),
    DESC(nanosleep, SG_CLASS_PROCESS),
    DESC(getpid, SG_CLASS_PROCESS),
    DESC(socket, SG_CLASS_NETWORK),
    DESC(connect, SG_CLASS_NETWORK),
    DESC(accept, SG_CLASS_NETWORK),
    DESC(sendto, SG_CLASS_NETWORK),
    DESC(recvfrom, SG_CLASS_NETWORK),
    DESC(sendmsg, SG_CLASS_NETWORK),
    DESC(recvmsg, SG_CLASS_NETWORK),
    DESC(shutdown, SG_CLASS_NETWORK),
    DESC(bind, SG_CLASS_NETWORK),
    DESC(listen, SG_CLASS_NETWORK),
    DESC(getsockname, SG_CLASS_NETWORK),
    DESC(getpeername, SG_CLASS_NETWORK),
    DESC(socketpair, SG_CLASS_NETWORK | SG_CLASS_IPC),
    DESC(setsockopt, SG_CLASS_NETWORK),
    DESC(getsockopt, SG_CLASS_NETWORK),
    DESC(clone, SG_CLASS_PROCESS),
    DESC(fork, SG_CLASS_PROCESS),
    DESC(vfork, SG_CLASS_PROCESS),
    DESC(execve, SG_CLASS_PROCESS | SG_CLASS_FILE),
    DESC(exit, SG_CLASS_PROCESS),
    DESC(wait4, SG_CLASS_PROCESS),
    DESC(kill, SG_CLASS_SIGNAL | SG_CLASS_PROCESS),
    DESC(uname, SG_CLASS_PROCESS),
    DESC(fcntl, SG_CLASS_FILE),
    DESC(fsync, SG_CLASS_FILE),
    DESC(fdatasync, SG_CLASS_FILE),
    DESC(truncate, SG_CLASS_FILE),
    DESC(ftruncate, SG_CLASS_FILE),
    DESC(getdents, SG_CLASS_FILE),
    DESC(getcwd, SG_CLASS_FILE),
    DESC(chdir, SG_CLASS_FILE),
    DESC(rename, SG_CLASS_FILE),
    DESC(mkdir, SG_CLASS_FILE),
    DESC(rmdir, SG_CLASS_FILE),
    DESC(creat, SG_CLASS_FILE),
    DESC(link, SG_CLASS_FILE),
    DESC(unlink, SG_CLASS_FILE),
    DESC(symlink, SG_CLASS_FILE),
    DESC(readlink, SG_CLASS_FILE),
    DESC(chmod, SG_CLASS_FILE),
    DESC(fchmod, SG_CLASS_FILE),
    DESC(chown, SG_CLASS_FILE),
    DESC(fchown, SG_CLASS_FILE),
    DESC(gettimeofday, SG_CLASS_PROCESS),
    DESC(getuid, SG_CLASS_PROCESS),
    DESC(getgid, SG_CLASS_PROCESS),
    DESC(geteuid, SG_CLASS_PROCESS),
    DESC(getegid, SG_CLASS_PROCESS),
    DESC(getppid, SG_CLASS_PROCESS),
    DESC(setsid, SG_CLASS_PROCESS),
    DESC(sigaltstack, SG_CLASS_SIGNAL),
    DESC(arch_prctl, SG_CLASS_PROCESS),
    DESC(futex, SG_CLASS_PROCESS | SG_CLASS_IPC),
    DESC(exit_group, SG_CLASS_PROCESS),
    DESC(epoll_wait, SG_CLASS_FILE),
    DESC(epoll_ctl, SG_CLASS_FILE),
    DESC(openat, SG_CLASS_FILE),
    DESC(newfstatat, SG_CLASS_FILE),
    DESC(unlinkat, SG_CLASS_FILE),
    DESC(renameat, SG_CLASS_FILE),
    DESC(linkat, SG_CLASS_FILE),
    DESC(symlinkat, SG_CLASS_FILE),
    DESC(readlinkat, SG_CLASS_FILE),
    DESC(pselect6, SG_CLASS_FILE | SG_CLASS_SIGNAL),
    DESC(ppoll, SG_CLASS_FILE | SG_CLASS_SIGNAL),
    DESC(unshare, SG_CLASS_PROCESS),
    DESC(splice, SG_CLASS_FILE),
    DESC(tee, SG_CLASS_FILE),
    DESC(vmsplice, SG_CLASS_FILE),
    DESC(accept4, SG_CLASS_NETWORK),
    DESC(dup3, SG_CLASS_FILE),
    DESC(pipe2, SG_CLASS_FILE | SG_CLASS_IPC),
    DESC(preadv, SG_CLASS_FILE),
    DESC(pwritev, SG_CLASS_FILE),
    DESC(process_vm_readv, SG_CLASS_PROCESS | SG_CLASS_MEMORY),
    DESC(process_vm_writev, SG_CLASS_PROCESS | SG_CLASS_MEMORY),
    DESC(execveat, SG_CLASS_PROCESS | SG_CLASS_FILE),
    DESC(preadv2, SG_CLASS_FILE),
    DESC(pwritev2, SG_CLASS_FILE),
    DESC(clone3, SG_CLASS_PROCESS),
    DESC(close_range, SG_CLASS_FILE),
    DESC(openat2, SG_CLASS_FILE)
};

const struct sg_syscall_descriptor *sg_syscall_catalog(size_t *count)
{
    if (count != NULL) {
        *count = sizeof(classified_descriptors) /
                 sizeof(classified_descriptors[0]);
    }
    return classified_descriptors;
}

const struct sg_syscall_descriptor *sg_syscall_by_name(const char *name)
{
    long number;

    if (name == NULL) {
        return NULL;
    }
    for (number = 0; (unsigned long)number < SG_SYSCALL_LIMIT; ++number) {
        const struct sg_syscall_descriptor *descriptor =
            &syscall_names[(size_t)number];

        if (descriptor->name != NULL && strcmp(descriptor->name, name) == 0) {
            return descriptor;
        }
    }
    return NULL;
}

const struct sg_syscall_descriptor *sg_syscall_by_number(long number)
{
    const struct sg_syscall_descriptor *descriptor;

    if (number < 0 || (unsigned long)number >= SG_SYSCALL_LIMIT) {
        return NULL;
    }
    descriptor = &syscall_names[(size_t)number];
    return descriptor->name == NULL ? NULL : descriptor;
}

size_t sg_syscall_name_count(void)
{
    size_t count = 0U;
    size_t number;

    for (number = 0U; number < SG_SYSCALL_LIMIT; ++number) {
        if (syscall_names[number].name != NULL) {
            ++count;
        }
    }
    return count;
}

long sg_syscall_name_max_number(void)
{
    size_t number = SG_SYSCALL_LIMIT;

    while (number != 0U) {
        --number;
        if (syscall_names[number].name != NULL) {
            return (long)number;
        }
    }
    return -1;
}

unsigned int sg_syscall_argument_count(long number)
{
    uint8_t encoded;

    if (number < 0 || (unsigned long)number >= SG_SYSCALL_LIMIT) {
        return 6U;
    }
    encoded = syscall_arities[(size_t)number];
    if (encoded != 0U) {
        return (unsigned int)encoded - 1U;
    }

    /* Native x86-64 entries whose implementations are arch-specific or have
     * been removed from current generic kernel sources. */
    switch (number) {
    case 9: return 6U;   /* mmap */
    case 15: return 0U;  /* rt_sigreturn */
    case 154: return 3U; /* modify_ldt */
    case 156: return 1U; /* _sysctl */
    case 158: return 2U; /* arch_prctl */
    case 166: return 2U; /* umount2 */
    case 172: return 1U; /* iopl */
    case 174: return 2U; /* create_module */
    case 177: return 1U; /* get_kernel_syms */
    case 178: return 5U; /* query_module */
    case 180: return 3U; /* nfsservctl */
    case 181: return 5U; /* getpmsg */
    case 182: return 5U; /* putpmsg */
    case 183: return 5U; /* afs_syscall */
    case 184: return 1U; /* tuxcall */
    case 185: return 3U; /* security */
    case 205: return 1U; /* set_thread_area */
    case 211: return 1U; /* get_thread_area */
    case 212: return 3U; /* lookup_dcookie */
    case 214: return 4U; /* epoll_ctl_old */
    case 215: return 4U; /* epoll_wait_old */
    case 236: return 0U; /* vserver */
    default: return 6U;
    }
}

const char *sg_syscall_class_name(unsigned int class_bit)
{
    static const char *const names[] = {
        "file", "process", "memory", "network", "signal", "ipc"
    };

    return class_bit < sizeof(names) / sizeof(names[0]) ? names[class_bit]
                                                        : NULL;
}

bool sg_syscall_class_by_name(const char *name, uint32_t *class_mask)
{
    unsigned int bit;

    if (name == NULL || class_mask == NULL) {
        return false;
    }
    for (bit = 0U; bit < 6U; ++bit) {
        if (strcmp(name, sg_syscall_class_name(bit)) == 0) {
            *class_mask = UINT32_C(1) << bit;
            return true;
        }
    }
    return false;
}
