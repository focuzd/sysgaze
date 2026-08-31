#ifndef SYSGAZE_FILTER_H
#define SYSGAZE_FILTER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SG_SYSCALL_LIMIT 512U
#define SG_FILTER_WORD_BITS 64U
#define SG_FILTER_WORDS (SG_SYSCALL_LIMIT / SG_FILTER_WORD_BITS)

static_assert(SG_SYSCALL_LIMIT % SG_FILTER_WORD_BITS == 0U,
              "syscall filter must contain whole words");

enum sg_syscall_class {
    SG_CLASS_FILE = UINT32_C(1) << 0,
    SG_CLASS_PROCESS = UINT32_C(1) << 1,
    SG_CLASS_MEMORY = UINT32_C(1) << 2,
    SG_CLASS_NETWORK = UINT32_C(1) << 3,
    SG_CLASS_SIGNAL = UINT32_C(1) << 4,
    SG_CLASS_IPC = UINT32_C(1) << 5
};

struct sg_filter {
    uint64_t words[SG_FILTER_WORDS];
    bool active;
};

void sg_filter_clear(struct sg_filter *filter);
void sg_filter_fill(struct sg_filter *filter);
bool sg_filter_contains(const struct sg_filter *filter, long syscall_number);
size_t sg_filter_count(const struct sg_filter *filter);
bool sg_filter_parse(struct sg_filter *filter, const char *spec,
                     char *error, size_t error_size);

#endif
