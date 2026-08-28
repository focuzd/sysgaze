#ifndef SYSGAZE_TRACE_H
#define SYSGAZE_TRACE_H

#include <stdbool.h>
#include <stddef.h>

#include "sysgaze/config.h"

bool sg_trace_run(const struct sg_config *config, int *command_status,
                  char *error, size_t error_size);

#endif
