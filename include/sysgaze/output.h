#ifndef SYSGAZE_OUTPUT_H
#define SYSGAZE_OUTPUT_H

#include <stdbool.h>

#include "sysgaze/event.h"

struct sg_output_sink {
    void *context;
    bool (*write_event)(void *context, const struct sg_event *event);
    bool (*finish)(void *context);
};

#endif
