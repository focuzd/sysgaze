#include "sysgaze/cli.h"

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define SG_DEFAULT_STRING_LIMIT 32U
#define SG_MAX_STRING_LIMIT (1024U * 1024U)
#define SG_VERSION "1.0.0"

enum {
    OPT_FORMAT = 1000,
    OPT_SECCOMP_BPF,
    OPT_VERSION
};

static const struct option long_options[] = {
    {"follow", no_argument, NULL, 'f'},
    {"format", required_argument, NULL, OPT_FORMAT},
    {"help", no_argument, NULL, 'h'},
    {"seccomp-bpf", no_argument, NULL, OPT_SECCOMP_BPF},
    {"version", no_argument, NULL, OPT_VERSION},
    {NULL, 0, NULL, 0}
};

static void set_error(char *error, size_t error_size, const char *format, ...)
{
    va_list arguments;

    if (error == NULL || error_size == 0U) {
        return;
    }
    va_start(arguments, format);
    (void)vsnprintf(error, error_size, format, arguments);
    va_end(arguments);
}

static bool parse_pid(const char *text, pid_t *pid)
{
    char *end = NULL;
    long value;

    if (text == NULL || *text == '\0') {
        return false;
    }
    errno = 0;
    value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value <= 0 ||
        value > INT_MAX) {
        return false;
    }
    *pid = (pid_t)value;
    return true;
}

static bool parse_size_limit(const char *text, size_t *limit)
{
    char *end = NULL;
    uintmax_t value;

    if (text == NULL || *text == '\0' || *text == '-') {
        return false;
    }
    errno = 0;
    value = strtoumax(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' ||
        value > SG_MAX_STRING_LIMIT) {
        return false;
    }
    *limit = (size_t)value;
    return true;
}

static bool parse_format(const char *text, enum sg_output_format *format)
{
    if (strcmp(text, "text") == 0) {
        *format = SG_FORMAT_TEXT;
    } else if (strcmp(text, "ndjson") == 0) {
        *format = SG_FORMAT_NDJSON;
    } else if (strcmp(text, "json") == 0) {
        *format = SG_FORMAT_JSON;
    } else {
        return false;
    }
    return true;
}

static int separator_index(int argc, char **argv)
{
    int index;

    for (index = 1; index < argc; ++index) {
        if (strcmp(argv[index], "--") == 0) {
            return index;
        }
        if (argv[index][0] != '-') {
            return -1;
        }
        if (strcmp(argv[index], "-p") == 0 ||
            strcmp(argv[index], "-e") == 0 ||
            strcmp(argv[index], "-s") == 0 ||
            strcmp(argv[index], "-o") == 0 ||
            strcmp(argv[index], "--format") == 0) {
            ++index;
        }
    }
    return -1;
}

static void config_init(struct sg_config *config)
{
    memset(config, 0, sizeof(*config));
    config->mode = SG_RUN_LAUNCH;
    config->format = SG_FORMAT_TEXT;
    config->string_limit = SG_DEFAULT_STRING_LIMIT;
    sg_filter_clear(&config->filter);
}

static enum sg_cli_action validate_config(int argc, char **argv,
                                          struct sg_config *config,
                                          bool saw_attach,
                                          int separator,
                                          char *error, size_t error_size)
{
    if (saw_attach) {
        config->mode = SG_RUN_ATTACH;
        if (separator >= 0) {
            set_error(error, error_size,
                      "'-- COMMAND' cannot be supplied with -p");
            return SG_CLI_ERROR;
        }
        if (optind != argc) {
            set_error(error, error_size,
                      "a command cannot be supplied with -p");
            return SG_CLI_ERROR;
        }
    } else {
        if (separator < 0 || separator != optind - 1) {
            set_error(error, error_size,
                      "launch mode requires '-- COMMAND [ARG...]'");
            return SG_CLI_ERROR;
        }
        if (optind >= argc) {
            set_error(error, error_size, "no command supplied after '--'");
            return SG_CLI_ERROR;
        }
        config->command_argv = &argv[optind];
    }

    if (config->format == SG_FORMAT_JSON && !config->summary) {
        set_error(error, error_size,
                  "--format=json is only valid with -c");
        return SG_CLI_ERROR;
    }
    if (config->format == SG_FORMAT_NDJSON && config->summary) {
        set_error(error, error_size,
                  "--format=ndjson cannot be used with -c; use text or json");
        return SG_CLI_ERROR;
    }
    if (config->seccomp_bpf) {
        if (config->mode == SG_RUN_ATTACH) {
            set_error(error, error_size,
                      "--seccomp-bpf is not available in attach mode");
            return SG_CLI_ERROR;
        }
        if (!config->filter.active || sg_filter_count(&config->filter) == 0U) {
            set_error(error, error_size,
                      "--seccomp-bpf requires a non-empty syscall filter");
            return SG_CLI_ERROR;
        }
    }
    return SG_CLI_RUN;
}

enum sg_cli_action sg_cli_parse(int argc, char **argv, struct sg_config *config,
                                char *error, size_t error_size)
{
    bool saw_attach = false;
    bool saw_filter = false;
    int separator;
    int option;

    if (config == NULL || argc < 1 || argv == NULL) {
        set_error(error, error_size, "invalid CLI parser arguments");
        return SG_CLI_ERROR;
    }
    config_init(config);
    separator = separator_index(argc, argv);
    if (error != NULL && error_size != 0U) {
        error[0] = '\0';
    }

    optind = 1;
    opterr = 0;
    optopt = 0;
    while ((option = getopt_long(argc, argv, "+p:fe:s:o:ch", long_options,
                                 NULL)) != -1) {
        switch (option) {
        case 'p':
            if (saw_attach) {
                set_error(error, error_size, "-p may only be supplied once");
                return SG_CLI_ERROR;
            }
            if (!parse_pid(optarg, &config->attach_pid)) {
                set_error(error, error_size, "invalid PID '%s'", optarg);
                return SG_CLI_ERROR;
            }
            saw_attach = true;
            break;
        case 'f':
            config->follow = true;
            break;
        case 'e':
            if (saw_filter) {
                set_error(error, error_size,
                          "-e trace=EXPR may only be supplied once");
                return SG_CLI_ERROR;
            }
            if (!sg_filter_parse(&config->filter, optarg, error, error_size)) {
                return SG_CLI_ERROR;
            }
            saw_filter = true;
            break;
        case 's':
            if (!parse_size_limit(optarg, &config->string_limit)) {
                set_error(error, error_size,
                          "invalid string limit '%s' (maximum %u)", optarg,
                          SG_MAX_STRING_LIMIT);
                return SG_CLI_ERROR;
            }
            break;
        case 'o':
            if (*optarg == '\0') {
                set_error(error, error_size, "output path cannot be empty");
                return SG_CLI_ERROR;
            }
            config->output_path = optarg;
            break;
        case 'c':
            config->summary = true;
            break;
        case 'h':
            return SG_CLI_HELP;
        case OPT_FORMAT:
            if (!parse_format(optarg, &config->format)) {
                set_error(error, error_size, "unknown output format '%s'",
                          optarg);
                return SG_CLI_ERROR;
            }
            break;
        case OPT_SECCOMP_BPF:
            config->seccomp_bpf = true;
            break;
        case OPT_VERSION:
            return SG_CLI_VERSION;
        case '?':
        default:
            if (optopt != 0) {
                set_error(error, error_size, "invalid option or missing value '-%c'",
                          optopt);
            } else {
                set_error(error, error_size, "unknown option '%s'",
                          argv[optind - 1]);
            }
            return SG_CLI_ERROR;
        }
    }

    return validate_config(argc, argv, config, saw_attach, separator, error,
                           error_size);
}

void sg_cli_print_usage(FILE *stream, const char *program_name)
{
    (void)fprintf(stream,
                  "Usage:\n"
                  "  %s [OPTIONS] -- COMMAND [ARG...]\n"
                  "  %s [OPTIONS] -p PID\n\n"
                  "Options:\n"
                  "  -p PID             attach to a running process\n"
                  "  -f, --follow       follow fork, vfork, clone, and exec\n"
                  "  -e trace=EXPR      select syscalls by name or %%class\n"
                  "  -s N               maximum displayed string bytes (default 32)\n"
                  "  -o FILE            write tracer output to FILE\n"
                  "  -c                 print aggregate syscall statistics\n"
                  "      --format=FMT    text, ndjson stream, or json summary\n"
                  "      --seccomp-bpf   filtered launch-mode acceleration\n"
                  "  -h, --help         show this help\n"
                  "      --version      show version\n",
                  program_name, program_name);
}

void sg_cli_print_version(FILE *stream)
{
    (void)fprintf(stream, "sysgaze %s\n", SG_VERSION);
}
