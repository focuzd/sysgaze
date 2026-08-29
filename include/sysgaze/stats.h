#ifndef SYSGAZE_STATS_H
#define SYSGAZE_STATS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sysgaze/event.h"

struct sg_syscall_stat {
    long number;
    uint64_t calls;
    uint64_t errors;
    uint64_t nanoseconds;
};

struct sg_stats {
    struct sg_syscall_stat *rows;
    size_t count;
    size_t capacity;
    uint64_t total_calls;
    uint64_t total_errors;
    uint64_t total_nanoseconds;
};

void sg_stats_init(struct sg_stats *stats);
void sg_stats_destroy(struct sg_stats *stats);
bool sg_stats_record(struct sg_stats *stats,
                     const struct sg_syscall_event *event);
bool sg_stats_sorted_copy(const struct sg_stats *stats,
                          struct sg_syscall_stat **rows, size_t *count);

#endif
