#include "sysgaze/tracee_table.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define SG_TRACEE_INITIAL_CAPACITY 16U

static size_t hash_tid(pid_t tid)
{
    uint64_t value = (uint64_t)(unsigned long)tid;

    value ^= value >> 33;
    value *= UINT64_C(0xff51afd7ed558ccd);
    value ^= value >> 33;
    return (size_t)value;
}

void sg_tracee_table_init(struct sg_tracee_table *table)
{
    memset(table, 0, sizeof(*table));
}

void sg_tracee_table_destroy(struct sg_tracee_table *table)
{
    free(table->slots);
    sg_tracee_table_init(table);
}

static size_t find_slot(const struct sg_tracee_table *table, pid_t tid,
                        bool *found)
{
    size_t mask = table->capacity - 1U;
    size_t index = hash_tid(tid) & mask;
    size_t first_tombstone = SIZE_MAX;

    for (;;) {
        const struct sg_tracee_slot *slot = &table->slots[index];

        if (slot->state == SG_TRACEE_SLOT_EMPTY) {
            *found = false;
            return first_tombstone == SIZE_MAX ? index : first_tombstone;
        }
        if (slot->state == SG_TRACEE_SLOT_OCCUPIED &&
            slot->tracee.tid == tid) {
            *found = true;
            return index;
        }
        if (slot->state == SG_TRACEE_SLOT_TOMBSTONE &&
            first_tombstone == SIZE_MAX) {
            first_tombstone = index;
        }
        index = (index + 1U) & mask;
    }
}

static bool resize_table(struct sg_tracee_table *table, size_t capacity)
{
    struct sg_tracee_slot *old_slots = table->slots;
    size_t old_capacity = table->capacity;
    struct sg_tracee_slot *new_slots;
    size_t index;

    new_slots = calloc(capacity, sizeof(*new_slots));
    if (new_slots == NULL) {
        return false;
    }
    table->slots = new_slots;
    table->capacity = capacity;
    table->count = 0U;
    table->tombstones = 0U;

    for (index = 0U; index < old_capacity; ++index) {
        if (old_slots[index].state == SG_TRACEE_SLOT_OCCUPIED) {
            bool found;
            size_t destination = find_slot(table, old_slots[index].tracee.tid,
                                           &found);

            table->slots[destination] = old_slots[index];
            table->slots[destination].state = SG_TRACEE_SLOT_OCCUPIED;
            ++table->count;
        }
    }
    free(old_slots);
    return true;
}

static bool ensure_capacity(struct sg_tracee_table *table)
{
    if (table->capacity == 0U) {
        return resize_table(table, SG_TRACEE_INITIAL_CAPACITY);
    }
    if ((table->count + table->tombstones + 1U) * 10U <
        table->capacity * 7U) {
        return true;
    }
    if (table->capacity > SIZE_MAX / 2U) {
        return false;
    }
    return resize_table(table, table->capacity * 2U);
}

struct sg_tracee *sg_tracee_table_get(struct sg_tracee_table *table, pid_t tid)
{
    bool found;
    size_t index;

    if (table->capacity == 0U || tid <= 0) {
        return NULL;
    }
    index = find_slot(table, tid, &found);
    return found ? &table->slots[index].tracee : NULL;
}

bool sg_tracee_table_insert(struct sg_tracee_table *table, pid_t tid, pid_t tgid,
                            bool attached, bool *inserted)
{
    bool found;
    size_t index;

    if (tid <= 0 || tgid <= 0 || !ensure_capacity(table)) {
        return false;
    }
    index = find_slot(table, tid, &found);
    if (found) {
        if (inserted != NULL) {
            *inserted = false;
        }
        return true;
    }
    if (table->slots[index].state == SG_TRACEE_SLOT_TOMBSTONE) {
        --table->tombstones;
    }
    memset(&table->slots[index].tracee, 0, sizeof(table->slots[index].tracee));
    table->slots[index].state = SG_TRACEE_SLOT_OCCUPIED;
    table->slots[index].tracee.tid = tid;
    table->slots[index].tracee.tgid = tgid;
    table->slots[index].tracee.attached = attached;
    table->slots[index].tracee.phase = SG_TRACEE_NEW;
    ++table->count;
    if (inserted != NULL) {
        *inserted = true;
    }
    return true;
}

bool sg_tracee_table_remove(struct sg_tracee_table *table, pid_t tid,
                            struct sg_tracee *removed)
{
    bool found;
    size_t index;

    if (table->capacity == 0U || tid <= 0) {
        return false;
    }
    index = find_slot(table, tid, &found);
    if (!found) {
        return false;
    }
    if (removed != NULL) {
        *removed = table->slots[index].tracee;
    }
    memset(&table->slots[index].tracee, 0, sizeof(table->slots[index].tracee));
    table->slots[index].state = SG_TRACEE_SLOT_TOMBSTONE;
    --table->count;
    ++table->tombstones;
    return true;
}
