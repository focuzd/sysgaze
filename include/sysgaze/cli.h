#ifndef SYSGAZE_CLI_H
#define SYSGAZE_CLI_H

#include <stddef.h>
#include <stdio.h>

#include "sysgaze/config.h"

enum sg_cli_action {
    SG_CLI_RUN,
    SG_CLI_HELP,
    SG_CLI_VERSION,
    SG_CLI_ERROR
};

enum sg_cli_action sg_cli_parse(int argc, char **argv, struct sg_config *config,
                                char *error, size_t error_size);
void sg_cli_print_usage(FILE *stream, const char *program_name);
void sg_cli_print_version(FILE *stream);

#endif
