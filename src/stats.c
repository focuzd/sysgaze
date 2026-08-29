#include "sysgaze/stats.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "sysgaze/syscall_catalog.h"

static bool elapsed_nanoseconds(const struct sg_syscall_event *event,
                                uint64_t *result)
{
    int64_t seconds = (int64_t)event->exited_at.tv_sec -
                      (int64_t)event->entered_at.tv_sec;
    int64_t nanoseconds = (int64_t)event->exited_at.tv_nsec -
                          (int64_t)event->entered_at.tv_nsec;

    *result = 0U;
    if (seconds < 0 || (seconds == 0 && nanoseconds < 0)) {
        return true;
    }
    if (nanoseconds < 0) {
        --seconds;
        nanoseconds += INT64_C(1000000000);
    }
    if ((uint64_t)seconds > UINT64_MAX / UINT64_C(1000000000)) {
        return false;
    }
    *result = (uint64_t)seconds * UINT64_C(1000000000) +
              (uint64_t)nanoseconds;
    return true;
}

void sg_stats_init(struct sg_stats *stats)
{
    memset(stats, 0, sizeof(*stats));
}

void sg_stats_destroy(struct sg_stats *stats)
{
    free(stats->rows);
    sg_stats_init(stats);
}

static struct sg_syscall_stat *find_row(struct sg_stats *stats, long number)
{
    size_t index;

    for (index = 0U; index < stats->count; ++index) {
        if (stats->rows[index].number == number) {
            return &stats->rows[index];
        }
    }
    return NULL;
}

static struct sg_syscall_stat *add_row(struct sg_stats *stats, long number)
{
    struct sg_syscall_stat *resized;
    size_t capacity;

    if (stats->count == stats->capacity) {
        capacity = stats->capacity == 0U ? 16U : stats->capacity * 2U;
        if (capacity < stats->capacity ||
            capacity > SIZE_MAX / sizeof(*stats->rows)) {
            return NULL;
        }
        resized = realloc(stats->rows, capacity * sizeof(*stats->rows));
        if (resized == NULL) {
            return NULL;
        }
        stats->rows = resized;
        stats->capacity = capacity;
    }
    memset(&stats->rows[stats->count], 0, sizeof(stats->rows[stats->count]));
    stats->rows[stats->count].number = number;
    return &stats->rows[stats->count++];
}

bool sg_stats_record(struct sg_stats *stats,
                     const struct sg_syscall_event *event)
{
    struct sg_syscall_stat *row;
    uint64_t nanoseconds;
    bool error;

    if (!event->completed ||
        !elapsed_nanoseconds(event, &nanoseconds) ||
        stats->total_calls == UINT64_MAX ||
        stats->total_nanoseconds > UINT64_MAX - nanoseconds) {
        return false;
    }
    error = event->error_number != 0;
    if (error && stats->total_errors == UINT64_MAX) {
        return false;
    }
    row = find_row(stats, event->number);
    if (row == NULL) {
        row = add_row(stats, event->number);
        if (row == NULL) {
            return false;
        }
    }
    if (row->calls == UINT64_MAX ||
        row->nanoseconds > UINT64_MAX - nanoseconds ||
        (error && row->errors == UINT64_MAX)) {
        return false;
    }
    ++row->calls;
    row->errors += error ? 1U : 0U;
    row->nanoseconds += nanoseconds;
    ++stats->total_calls;
    stats->total_errors += error ? 1U : 0U;
    stats->total_nanoseconds += nanoseconds;
    return true;
}

static int compare_rows(const void *left_pointer, const void *right_pointer)
{
    const struct sg_syscall_stat *left = left_pointer;
    const struct sg_syscall_stat *right = right_pointer;
    const struct sg_syscall_descriptor *left_descriptor;
    const struct sg_syscall_descriptor *right_descriptor;
    int names;

    if (left->nanoseconds != right->nanoseconds) {
        return left->nanoseconds > right->nanoseconds ? -1 : 1;
    }
    left_descriptor = sg_syscall_by_number(left->number);
    right_descriptor = sg_syscall_by_number(right->number);
    if (left_descriptor != NULL && right_descriptor != NULL) {
        names = strcmp(left_descriptor->name, right_descriptor->name);
        if (names != 0) {
            return names;
        }
    } else if (left_descriptor != NULL) {
        return -1;
    } else if (right_descriptor != NULL) {
        return 1;
    }
    if (left->number == right->number) {
        return 0;
    }
    return left->number < right->number ? -1 : 1;
}

bool sg_stats_sorted_copy(const struct sg_stats *stats,
                          struct sg_syscall_stat **rows, size_t *count)
{
    *rows = NULL;
    *count = stats->count;
    if (stats->count == 0U) {
        return true;
    }
    if (stats->count > SIZE_MAX / sizeof(**rows)) {
        return false;
    }
    *rows = malloc(stats->count * sizeof(**rows));
    if (*rows == NULL) {
        return false;
    }
    memcpy(*rows, stats->rows, stats->count * sizeof(**rows));
    qsort(*rows, stats->count, sizeof(**rows), compare_rows);
    return true;
}
