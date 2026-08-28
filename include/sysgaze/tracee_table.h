#ifndef SYSGAZE_TRACEE_TABLE_H
#define SYSGAZE_TRACEE_TABLE_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include "sysgaze/tracee.h"

enum sg_tracee_slot_state {
    SG_TRACEE_SLOT_EMPTY,
    SG_TRACEE_SLOT_OCCUPIED,
    SG_TRACEE_SLOT_TOMBSTONE
};

struct sg_tracee_slot {
    enum sg_tracee_slot_state state;
    struct sg_tracee tracee;
};

struct sg_tracee_table {
    struct sg_tracee_slot *slots;
    size_t capacity;
    size_t count;
    size_t tombstones;
};

void sg_tracee_table_init(struct sg_tracee_table *table);
void sg_tracee_table_destroy(struct sg_tracee_table *table);
struct sg_tracee *sg_tracee_table_get(struct sg_tracee_table *table, pid_t tid);
bool sg_tracee_table_insert(struct sg_tracee_table *table, pid_t tid, pid_t tgid,
                            bool attached, bool *inserted);
bool sg_tracee_table_remove(struct sg_tracee_table *table, pid_t tid,
                            struct sg_tracee *removed);

#endif
