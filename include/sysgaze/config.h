#ifndef SYSGAZE_CONFIG_H
#define SYSGAZE_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include "sysgaze/filter.h"

enum sg_run_mode {
    SG_RUN_LAUNCH,
    SG_RUN_ATTACH
};

enum sg_output_format {
    SG_FORMAT_TEXT,
    SG_FORMAT_NDJSON,
    SG_FORMAT_JSON
};

struct sg_config {
    enum sg_run_mode mode;
    enum sg_output_format format;
    pid_t attach_pid;
    char **command_argv;
    const char *output_path;
    size_t string_limit;
    bool follow;
    bool summary;
    bool seccomp_bpf;
    struct sg_filter filter;
};

#endif
