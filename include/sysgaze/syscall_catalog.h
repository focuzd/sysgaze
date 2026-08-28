#ifndef SYSGAZE_SYSCALL_CATALOG_H
#define SYSGAZE_SYSCALL_CATALOG_H

#include <stddef.h>

#include "sysgaze/filter.h"

const struct sg_syscall_descriptor *sg_syscall_catalog(size_t *count);
const struct sg_syscall_descriptor *sg_syscall_by_name(const char *name);
const struct sg_syscall_descriptor *sg_syscall_by_number(long number);
size_t sg_syscall_name_count(void);
long sg_syscall_name_max_number(void);
unsigned int sg_syscall_argument_count(long number);
const char *sg_syscall_class_name(unsigned int class_bit);
bool sg_syscall_class_by_name(const char *name, uint32_t *class_mask);

#endif
