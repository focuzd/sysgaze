#include "sysgaze/syscall_catalog.h"

#include <string.h>

#define ARG(kind_value) { (kind_value), 0U }
#define ARG_AUX(kind_value, auxiliary_value) \
    { (kind_value), (auxiliary_value) }
#define SYSCALL(syscall_number, syscall_name, abi_arity, class_mask, result, \
                ...) \
    { \
        .number = (syscall_number), \
        .name = #syscall_name, \
        .arity = (abi_arity), \
        .classes = (class_mask), \
        .result_kind = (result), \
        .arguments = {__VA_ARGS__} \
    },
static const struct sg_syscall_descriptor syscalls[] = {
#include "syscall_catalog.inc"
};
#undef SYSCALL
#undef ARG_AUX
#undef ARG

const struct sg_syscall_descriptor *sg_syscall_catalog(size_t *count)
{
    if (count != NULL) {
        *count = sizeof(syscalls) / sizeof(syscalls[0]);
    }
    return syscalls;
}

const struct sg_syscall_descriptor *sg_syscall_by_name(const char *name)
{
    size_t number;

    if (name == NULL) {
        return NULL;
    }
    for (number = 0U; number < sizeof(syscalls) / sizeof(syscalls[0]);
         ++number) {
        const struct sg_syscall_descriptor *descriptor = &syscalls[number];

        if (descriptor->name != NULL && strcmp(descriptor->name, name) == 0) {
            return descriptor;
        }
    }
    return NULL;
}

const struct sg_syscall_descriptor *sg_syscall_by_number(long number)
{
    size_t left = 0U;
    size_t right = sizeof(syscalls) / sizeof(syscalls[0]);

    if (number < 0 || (unsigned long)number >= SG_SYSCALL_LIMIT) {
        return NULL;
    }
    while (left < right) {
        size_t middle = left + (right - left) / 2U;

        if (syscalls[middle].number < number) {
            left = middle + 1U;
        } else {
            right = middle;
        }
    }
    return left < sizeof(syscalls) / sizeof(syscalls[0]) &&
                   syscalls[left].number == number
               ? &syscalls[left]
               : NULL;
}

size_t sg_syscall_name_count(void)
{
    return sizeof(syscalls) / sizeof(syscalls[0]);
}

long sg_syscall_name_max_number(void)
{
    return sizeof(syscalls) / sizeof(syscalls[0]) == 0U
               ? -1
               : syscalls[sizeof(syscalls) / sizeof(syscalls[0]) - 1U].number;
}

unsigned int sg_syscall_argument_count(long number)
{
    const struct sg_syscall_descriptor *descriptor =
        sg_syscall_by_number(number);

    return descriptor == NULL ? 6U : descriptor->arity;
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
