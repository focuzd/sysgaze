#ifndef SYSGAZE_OUTPUT_H
#define SYSGAZE_OUTPUT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "sysgaze/config.h"
#include "sysgaze/decoder.h"
#include "sysgaze/event.h"
#include "sysgaze/stats.h"

struct sg_output {
    FILE *stream;
    const struct sg_decoder *decoder;
    enum sg_output_format format;
    pid_t *unfinished_tids;
    size_t unfinished_count;
    size_t unfinished_capacity;
    bool show_tids;
    bool summary;
};

bool sg_output_init(struct sg_output *output, FILE *stream,
                    enum sg_output_format format,
                    const struct sg_decoder *decoder, bool show_tids,
                    bool summary,
                    char *error, size_t error_size);
bool sg_output_write_event(struct sg_output *output,
                           const struct sg_event *event,
                           char *error, size_t error_size);
void sg_output_migrate_tid(struct sg_output *output, pid_t former_tid,
                           pid_t current_tid);
bool sg_output_write_summary(struct sg_output *output,
                             const struct sg_stats *stats,
                             char *error, size_t error_size);
bool sg_output_finish(struct sg_output *output, char *error,
                      size_t error_size);
void sg_output_destroy(struct sg_output *output);

#endif
