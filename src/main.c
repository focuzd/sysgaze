#include <stdio.h>

#include "sysgaze/cli.h"
#include "sysgaze/trace.h"

int main(int argc, char **argv)
{
    struct sg_config config;
    char error[256];
    enum sg_cli_action action;
    int command_status;

    action = sg_cli_parse(argc, argv, &config, error, sizeof(error));
    switch (action) {
    case SG_CLI_HELP:
        sg_cli_print_usage(stdout, argv[0]);
        return 0;
    case SG_CLI_VERSION:
        sg_cli_print_version(stdout);
        return 0;
    case SG_CLI_ERROR:
        (void)fprintf(stderr, "%s: %s\nTry '%s --help' for more information.\n",
                      argv[0], error, argv[0]);
        return 2;
    case SG_CLI_RUN:
        if (!sg_trace_run(&config, &command_status, error, sizeof(error))) {
            (void)fprintf(stderr, "%s: %s\n", argv[0], error);
            return 1;
        }
        return command_status;
    }
    return 1;
}
