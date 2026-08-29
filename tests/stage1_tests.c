#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>

#include "sysgaze/buffer.h"
#include "sysgaze/cli.h"
#include "sysgaze/decoder.h"
#include "sysgaze/filter.h"
#include "sysgaze/stats.h"
#include "sysgaze/syscall_catalog.h"
#include "sysgaze/tracee_table.h"

static unsigned int tests_run;
static unsigned int tests_failed;

struct fake_memory {
    unsigned char *base;
    size_t length;
};

#define CHECK(condition)                                                        \
    do {                                                                        \
        if (!(condition)) {                                                     \
            (void)fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__,       \
                          __LINE__, #condition);                                 \
            return false;                                                       \
        }                                                                       \
    } while (false)

static bool fake_memory_read(void *opaque, pid_t tid, uintptr_t address,
                             void *destination, size_t length,
                             size_t *bytes_read)
{
    struct fake_memory *memory = opaque;
    uintptr_t base = (uintptr_t)memory->base;
    size_t offset;

    (void)tid;
    *bytes_read = 0U;
    if (address < base) {
        return false;
    }
    offset = (size_t)(address - base);
    if (offset >= memory->length) {
        return false;
    }
    if (length > memory->length - offset) {
        length = memory->length - offset;
    }
    memcpy(destination, memory->base + offset, length);
    *bytes_read = length;
    return true;
}

static bool decode_event(struct sg_decoder *decoder,
                         struct sg_syscall_event *event,
                         const char *expected)
{
    struct sg_buffer output;
    bool result;

    sg_buffer_init(&output);
    result = sg_decode_syscall(decoder, 1, event, &output);
    if (result && strcmp(output.data, expected) != 0) {
        (void)fprintf(stderr, "expected: %s\nactual:   %s\n", expected,
                      output.data);
        result = false;
    }
    sg_buffer_destroy(&output);
    return result;
}

static bool test_decoder_input_snapshot_and_escaping(void)
{
    unsigned char bytes[] = {'a', '"', '\n', '\0', 0xffU};
    struct fake_memory memory = {.base = bytes, .length = sizeof(bytes)};
    struct sg_decoder decoder = {
        .string_limit = 32U,
        .memory = {.context = &memory, .read = fake_memory_read}
    };
    struct sg_syscall_event event = {
        .number = SYS_write,
        .arguments = {1U, (uint64_t)(uintptr_t)bytes, sizeof(bytes)},
        .result = (int64_t)sizeof(bytes),
        .completed = true
    };

    CHECK(sg_decoder_capture_entry(&decoder, 1, &event));
    memset(bytes, 'z', sizeof(bytes));
    CHECK(decode_event(&decoder, &event,
                       "write(1, \"a\\\"\\n\\0\\xff\", 5) = 5"));
    sg_decoder_release_event(&event);
    return true;
}

static bool test_decoder_output_buffer_and_zero_length(void)
{
    unsigned char bytes[8] = {0};
    struct fake_memory memory = {.base = bytes, .length = sizeof(bytes)};
    struct sg_decoder decoder = {
        .string_limit = 32U,
        .memory = {.context = &memory, .read = fake_memory_read}
    };
    struct sg_syscall_event event = {
        .number = SYS_read,
        .arguments = {3U, (uint64_t)(uintptr_t)bytes, sizeof(bytes)}
    };

    CHECK(sg_decoder_capture_entry(&decoder, 1, &event));
    memcpy(bytes, "ok\n", 3U);
    bytes[3] = '\0';
    event.result = 4;
    event.completed = true;
    CHECK(decode_event(&decoder, &event,
                       "read(3, \"ok\\n\\0\", 8) = 4"));
    sg_decoder_release_event(&event);

    memset(&event, 0, sizeof(event));
    event.number = SYS_read;
    event.arguments[0] = 3U;
    event.arguments[1] = (uint64_t)(uintptr_t)bytes;
    event.arguments[2] = sizeof(bytes);
    CHECK(sg_decoder_capture_entry(&decoder, 1, &event));
    CHECK(decode_event(&decoder, &event, "read(3, \"\", 8) = 0"));
    sg_decoder_release_event(&event);
    return true;
}

static bool test_decoder_strings_flags_and_errno(void)
{
    unsigned char path[] = "abcdef";
    struct fake_memory memory = {.base = path, .length = sizeof(path)};
    struct sg_decoder decoder = {
        .string_limit = 4U,
        .memory = {.context = &memory, .read = fake_memory_read}
    };
    struct sg_syscall_event event = {
        .number = SYS_openat,
        .arguments = {
            (uint32_t)AT_FDCWD,
            (uint64_t)(uintptr_t)path,
            O_WRONLY | O_CREAT,
            0644U
        },
        .result = -ENOENT,
        .error_number = ENOENT,
        .completed = true
    };

    CHECK(sg_decoder_capture_entry(&decoder, 1, &event));
    CHECK(decode_event(
        &decoder, &event,
        "openat(AT_FDCWD, \"abcd\"..., O_WRONLY|O_CREAT, 0644) = -1 "
        "ENOENT (No such file or directory)"));
    sg_decoder_release_event(&event);

    memset(&event, 0, sizeof(event));
    event.number = SYS_open;
    event.arguments[0] = 1U;
    event.arguments[1] = UINT64_C(0x40000000);
    CHECK(sg_decoder_capture_entry(&decoder, 1, &event));
    CHECK(decode_event(&decoder, &event,
                       "open(0x1, O_RDONLY|0x40000000) = 0"));
    sg_decoder_release_event(&event);
    return true;
}

static bool test_decoder_argv(void)
{
    struct argv_memory {
        char first[8];
        char second[8];
        uint64_t pointers[3];
    } storage = {.first = "one", .second = "two"};
    struct fake_memory memory = {
        .base = (unsigned char *)&storage,
        .length = sizeof(storage)
    };
    struct sg_decoder decoder = {
        .string_limit = 32U,
        .memory = {.context = &memory, .read = fake_memory_read}
    };
    struct sg_syscall_event event = {
        .number = SYS_execve,
        .result = -ENOENT,
        .error_number = ENOENT
    };

    storage.pointers[0] = (uint64_t)(uintptr_t)storage.first;
    storage.pointers[1] = (uint64_t)(uintptr_t)storage.second;
    storage.pointers[2] = 0U;
    event.arguments[0] = (uint64_t)(uintptr_t)storage.first;
    event.arguments[1] = (uint64_t)(uintptr_t)storage.pointers;
    event.arguments[2] = 0U;
    CHECK(sg_decoder_capture_entry(&decoder, 1, &event));
    CHECK(decode_event(
        &decoder, &event,
        "execve(\"one\", [\"one\", \"two\"], NULL) = -1 ENOENT "
        "(No such file or directory)"));
    sg_decoder_release_event(&event);
    return true;
}

static bool test_tracee_table_growth_and_deletion(void)
{
    struct sg_tracee_table table;
    int tid;

    sg_tracee_table_init(&table);
    for (tid = 1; tid <= 100; ++tid) {
        bool inserted = false;

        CHECK(sg_tracee_table_insert(&table, (pid_t)tid, (pid_t)(tid / 4 + 1),
                                     false, &inserted));
        CHECK(inserted);
        CHECK(sg_tracee_table_get(&table, (pid_t)tid) != NULL);
    }
    CHECK(table.count == 100U);
    for (tid = 2; tid <= 100; tid += 2) {
        struct sg_tracee removed;

        CHECK(sg_tracee_table_remove(&table, (pid_t)tid, &removed));
        CHECK(removed.tid == (pid_t)tid);
        CHECK(sg_tracee_table_get(&table, (pid_t)tid) == NULL);
    }
    CHECK(table.count == 50U);
    for (tid = 1; tid <= 99; tid += 2) {
        CHECK(sg_tracee_table_get(&table, (pid_t)tid)->tid == (pid_t)tid);
    }
    for (tid = 102; tid <= 200; tid += 2) {
        CHECK(sg_tracee_table_insert(&table, (pid_t)tid, (pid_t)tid, true,
                                     NULL));
    }
    CHECK(table.count == 100U);
    CHECK(sg_tracee_table_insert(&table, 1, 1, false, NULL));
    CHECK(table.count == 100U);
    CHECK(!sg_tracee_table_remove(&table, 999, NULL));
    sg_tracee_table_destroy(&table);
    CHECK(table.slots == NULL);
    return true;
}

static bool test_buffer_lifecycle(void)
{
    struct sg_buffer buffer;

    sg_buffer_init(&buffer);
    CHECK(buffer.data == NULL);
    CHECK(sg_buffer_append_cstr(&buffer, "hello"));
    CHECK(sg_buffer_append(&buffer, "\0x", 2U));
    CHECK(buffer.length == 7U);
    CHECK(memcmp(buffer.data, "hello\0x", 7U) == 0);
    CHECK(buffer.data[7] == '\0');
    CHECK(sg_buffer_append_format(&buffer, "-%d-%s", 42, "done"));
    CHECK(buffer.length == 15U);
    CHECK(memcmp(buffer.data + 7U, "-42-done", 8U) == 0);

    sg_buffer_reset(&buffer);
    CHECK(buffer.length == 0U);
    CHECK(buffer.data[0] == '\0');
    CHECK(sg_buffer_append(&buffer, NULL, 0U));
    CHECK(!sg_buffer_append(&buffer, NULL, 1U));
    sg_buffer_destroy(&buffer);
    CHECK(buffer.data == NULL);
    CHECK(buffer.capacity == 0U);
    return true;
}

static bool test_buffer_overflow_is_non_destructive(void)
{
    struct sg_buffer buffer;
    char *old_data;
    size_t old_capacity;

    sg_buffer_init(&buffer);
    CHECK(sg_buffer_append_cstr(&buffer, "stable"));
    old_data = buffer.data;
    old_capacity = buffer.capacity;
    CHECK(!sg_buffer_reserve(&buffer, SIZE_MAX));
    CHECK(buffer.data == old_data);
    CHECK(buffer.capacity == old_capacity);
    CHECK(strcmp(buffer.data, "stable") == 0);
    sg_buffer_destroy(&buffer);
    return true;
}

static bool test_filter_names_and_exclusions(void)
{
    struct sg_filter filter;
    char error[128];

    CHECK(sg_filter_parse(&filter, "trace=read,write", error, sizeof(error)));
    CHECK(filter.active);
    CHECK(sg_filter_count(&filter) == 2U);
    CHECK(sg_filter_contains(&filter, SYS_read));
    CHECK(sg_filter_contains(&filter, SYS_write));
    CHECK(!sg_filter_contains(&filter, SYS_close));

    CHECK(sg_filter_parse(&filter, "trace=!read", error, sizeof(error)));
    CHECK(sg_filter_count(&filter) == SG_SYSCALL_LIMIT - 1U);
    CHECK(!sg_filter_contains(&filter, SYS_read));
    CHECK(sg_filter_contains(&filter, SYS_write));
    CHECK(sg_filter_contains(&filter, 999L));
    return true;
}

static bool test_filter_classes_and_algebra(void)
{
    struct sg_filter filter;
    char error[128];

    CHECK(sg_filter_parse(&filter, "trace=%network,!socket,read", error,
                          sizeof(error)));
    CHECK(!sg_filter_contains(&filter, SYS_socket));
    CHECK(sg_filter_contains(&filter, SYS_connect));
    CHECK(sg_filter_contains(&filter, SYS_read));
    CHECK(!sg_filter_contains(&filter, SYS_mmap));

    CHECK(sg_filter_parse(&filter, "trace=!%network", error, sizeof(error)));
    CHECK(!sg_filter_contains(&filter, SYS_connect));
    CHECK(sg_filter_contains(&filter, SYS_read));
    return true;
}

static bool test_filter_rejects_malformed_input(void)
{
    static const char *const invalid[] = {
        "", "read", "trace=", "trace=read,", "trace=,read",
        "trace=read,,write", "trace=no_such_call", "trace=%no_such_class",
        "trace=!"
    };
    size_t index;
    struct sg_filter filter;
    struct sg_filter before;
    char error[128];

    for (index = 0U; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
        sg_filter_fill(&filter);
        before = filter;
        error[0] = '\0';
        CHECK(!sg_filter_parse(&filter, invalid[index], error, sizeof(error)));
        CHECK(error[0] != '\0');
        CHECK(memcmp(&filter, &before, sizeof(filter)) == 0);
    }
    return true;
}

static bool test_catalog_is_well_formed(void)
{
    const struct sg_syscall_descriptor *catalog;
    size_t count;
    size_t left;
    size_t right;

    catalog = sg_syscall_catalog(&count);
    CHECK(catalog != NULL);
    CHECK(count > 50U);
    for (left = 0U; left < count; ++left) {
        CHECK(catalog[left].number >= 0);
        CHECK((unsigned long)catalog[left].number < SG_SYSCALL_LIMIT);
        CHECK(catalog[left].name != NULL);
        CHECK(catalog[left].name[0] != '\0');
        CHECK(catalog[left].classes != 0U);
        for (right = left + 1U; right < count; ++right) {
            CHECK(catalog[left].number != catalog[right].number);
            CHECK(strcmp(catalog[left].name, catalog[right].name) != 0);
        }
    }
    return true;
}

static bool test_complete_syscall_name_table(void)
{
    size_t count = 0U;
    long number;

    CHECK(sg_syscall_name_count() == 385U);
    CHECK(sg_syscall_name_max_number() == 471L);
    for (number = 0; (unsigned long)number < SG_SYSCALL_LIMIT; ++number) {
        const struct sg_syscall_descriptor *descriptor =
            sg_syscall_by_number(number);

        if (descriptor == NULL) {
            continue;
        }
        ++count;
        CHECK(descriptor->number == number);
        CHECK(descriptor->name != NULL);
        CHECK(sg_syscall_by_name(descriptor->name) == descriptor);
        CHECK(sg_syscall_argument_count(number) <= 6U);
    }
    CHECK(count == sg_syscall_name_count());
    CHECK(strcmp(sg_syscall_by_number(SYS_open)->name, "open") == 0);
    CHECK(strcmp(sg_syscall_by_number(451L)->name, "cachestat") == 0);
    CHECK(strcmp(sg_syscall_by_number(471L)->name, "rseq_slice_yield") == 0);
    CHECK(sg_syscall_by_number(337L) == NULL);
    CHECK(sg_syscall_by_number(900L) == NULL);
    CHECK(sg_syscall_by_name("not_a_linux_syscall") == NULL);
    CHECK(sg_syscall_argument_count(SYS_read) == 3U);
    CHECK(sg_syscall_argument_count(SYS_mmap) == 6U);
    CHECK(sg_syscall_argument_count(SYS_rt_sigreturn) == 0U);
    CHECK(sg_syscall_argument_count(425L) == 2U);
    CHECK(sg_syscall_argument_count(471L) == 0U);
    return true;
}

static bool test_filter_accepts_complete_name_table(void)
{
    struct sg_filter filter;
    char error[128];

    CHECK(sg_filter_parse(&filter, "trace=open,cachestat,rseq_slice_yield",
                          error, sizeof(error)));
    CHECK(sg_filter_count(&filter) == 3U);
    CHECK(sg_filter_contains(&filter, SYS_open));
    CHECK(sg_filter_contains(&filter, 451L));
    CHECK(sg_filter_contains(&filter, 471L));
    return true;
}

static enum sg_cli_action parse_cli(size_t count, const char *const values[],
                                    struct sg_config *config, char *error,
                                    size_t error_size)
{
    if (count > (size_t)INT_MAX) {
        return SG_CLI_ERROR;
    }
    return sg_cli_parse((int)count, (char **)values, config, error, error_size);
}

static bool test_cli_launch_configuration(void)
{
    const char *const argv[] = {
        "sysgaze", "-f", "-s", "128", "-e", "trace=read,!write",
        "--format=ndjson", "-o", "events.jsonl", "--", "echo", "hello"
    };
    struct sg_config config;
    char error[256];

    CHECK(parse_cli(sizeof(argv) / sizeof(argv[0]), argv, &config, error,
                    sizeof(error)) == SG_CLI_RUN);
    CHECK(config.mode == SG_RUN_LAUNCH);
    CHECK(config.follow);
    CHECK(config.string_limit == 128U);
    CHECK(config.format == SG_FORMAT_NDJSON);
    CHECK(strcmp(config.output_path, "events.jsonl") == 0);
    CHECK(strcmp(config.command_argv[0], "echo") == 0);
    CHECK(strcmp(config.command_argv[1], "hello") == 0);
    CHECK(sg_filter_contains(&config.filter, SYS_read));
    CHECK(!sg_filter_contains(&config.filter, SYS_write));
    return true;
}

static bool test_cli_attach_configuration(void)
{
    const char *const argv[] = {
        "sysgaze", "-p", "12345", "-f", "-c", "--format=json"
    };
    struct sg_config config;
    char error[256];

    CHECK(parse_cli(sizeof(argv) / sizeof(argv[0]), argv, &config, error,
                    sizeof(error)) == SG_CLI_RUN);
    CHECK(config.mode == SG_RUN_ATTACH);
    CHECK(config.attach_pid == (pid_t)12345);
    CHECK(config.follow);
    CHECK(config.summary);
    CHECK(config.format == SG_FORMAT_JSON);
    CHECK(config.command_argv == NULL);
    return true;
}

static bool cli_is_error(size_t count, const char *const argv[])
{
    struct sg_config config;
    char error[256];

    return parse_cli(count, argv, &config, error, sizeof(error)) == SG_CLI_ERROR &&
           error[0] != '\0';
}

static bool test_cli_rejects_invalid_combinations(void)
{
    const char *const no_command[] = {"sysgaze"};
    const char *const no_separator[] = {"sysgaze", "echo"};
    const char *const late_separator[] = {"sysgaze", "echo", "--", "hello"};
    const char *const attach_command[] = {"sysgaze", "-p", "1", "--", "echo"};
    const char *const bad_pid[] = {"sysgaze", "-p", "-1"};
    const char *const json_stream[] = {"sysgaze", "--format=json", "--", "echo"};
    const char *const ndjson_summary[] = {
        "sysgaze", "-c", "--format=ndjson", "--", "echo"
    };
    const char *const seccomp_no_filter[] = {"sysgaze", "--seccomp-bpf", "--", "echo"};
    const char *const seccomp_attach[] = {
        "sysgaze", "--seccomp-bpf", "-e", "trace=read", "-p", "1"
    };
    const char *const duplicate_filter[] = {
        "sysgaze", "-e", "trace=read", "-e", "trace=write", "--", "echo"
    };
    const char *const huge_string[] = {
        "sysgaze", "-s", "1048577", "--", "echo"
    };

    CHECK(cli_is_error(sizeof(no_command) / sizeof(no_command[0]), no_command));
    CHECK(cli_is_error(sizeof(no_separator) / sizeof(no_separator[0]),
                       no_separator));
    CHECK(cli_is_error(sizeof(late_separator) / sizeof(late_separator[0]),
                       late_separator));
    CHECK(cli_is_error(sizeof(attach_command) / sizeof(attach_command[0]),
                       attach_command));
    CHECK(cli_is_error(sizeof(bad_pid) / sizeof(bad_pid[0]), bad_pid));
    CHECK(cli_is_error(sizeof(json_stream) / sizeof(json_stream[0]), json_stream));
    CHECK(cli_is_error(sizeof(ndjson_summary) / sizeof(ndjson_summary[0]),
                       ndjson_summary));
    CHECK(cli_is_error(sizeof(seccomp_no_filter) / sizeof(seccomp_no_filter[0]),
                       seccomp_no_filter));
    CHECK(cli_is_error(sizeof(seccomp_attach) / sizeof(seccomp_attach[0]),
                       seccomp_attach));
    CHECK(cli_is_error(sizeof(duplicate_filter) / sizeof(duplicate_filter[0]),
                       duplicate_filter));
    CHECK(cli_is_error(sizeof(huge_string) / sizeof(huge_string[0]), huge_string));
    return true;
}

static bool test_cli_actions(void)
{
    const char *const help[] = {"sysgaze", "--help"};
    const char *const version[] = {"sysgaze", "--version"};
    struct sg_config config;
    char error[256];

    CHECK(parse_cli(sizeof(help) / sizeof(help[0]), help, &config, error,
                    sizeof(error)) == SG_CLI_HELP);
    CHECK(parse_cli(sizeof(version) / sizeof(version[0]), version, &config, error,
                    sizeof(error)) == SG_CLI_VERSION);
    return true;
}

static bool test_statistics_aggregation_and_ordering(void)
{
    struct sg_stats stats;
    struct sg_syscall_stat *rows = NULL;
    size_t count = 0U;
    struct sg_syscall_event read_event = {
        .number = SYS_read,
        .error_number = 0,
        .entered_at = {.tv_sec = 1, .tv_nsec = 100},
        .exited_at = {.tv_sec = 1, .tv_nsec = 400},
        .completed = true
    };
    struct sg_syscall_event write_event = {
        .number = SYS_write,
        .error_number = EBADF,
        .entered_at = {.tv_sec = 2, .tv_nsec = 0},
        .exited_at = {.tv_sec = 2, .tv_nsec = 200},
        .completed = true
    };
    struct sg_syscall_event getpid_event = {
        .number = SYS_getpid,
        .entered_at = {.tv_sec = 3, .tv_nsec = 10},
        .exited_at = {.tv_sec = 3, .tv_nsec = 210},
        .completed = true
    };

    sg_stats_init(&stats);
    CHECK(sg_stats_record(&stats, &read_event));
    CHECK(sg_stats_record(&stats, &write_event));
    CHECK(sg_stats_record(&stats, &getpid_event));
    CHECK(stats.total_calls == 3U);
    CHECK(stats.total_errors == 1U);
    CHECK(stats.total_nanoseconds == 700U);
    CHECK(sg_stats_sorted_copy(&stats, &rows, &count));
    CHECK(count == 3U);
    CHECK(rows[0].number == SYS_read);
    CHECK(rows[1].number == SYS_getpid);
    CHECK(rows[2].number == SYS_write);
    CHECK(rows[2].errors == 1U);
    free(rows);
    sg_stats_destroy(&stats);
    return true;
}

static void run_test(const char *name, bool (*test)(void))
{
    bool passed;

    ++tests_run;
    passed = test();
    (void)fprintf(stderr, "%s %s\n", passed ? "ok" : "not ok", name);
    if (!passed) {
        ++tests_failed;
    }
}

int main(void)
{
    run_test("tracee table", test_tracee_table_growth_and_deletion);
    run_test("decoder input snapshots", test_decoder_input_snapshot_and_escaping);
    run_test("decoder output buffers", test_decoder_output_buffer_and_zero_length);
    run_test("decoder flags and errno", test_decoder_strings_flags_and_errno);
    run_test("decoder argv", test_decoder_argv);
    run_test("buffer lifecycle", test_buffer_lifecycle);
    run_test("buffer overflow", test_buffer_overflow_is_non_destructive);
    run_test("filter names", test_filter_names_and_exclusions);
    run_test("filter classes", test_filter_classes_and_algebra);
    run_test("filter malformed input", test_filter_rejects_malformed_input);
    run_test("syscall catalog", test_catalog_is_well_formed);
    run_test("complete syscall names", test_complete_syscall_name_table);
    run_test("complete-name filters", test_filter_accepts_complete_name_table);
    run_test("CLI launch", test_cli_launch_configuration);
    run_test("CLI attach", test_cli_attach_configuration);
    run_test("CLI validation", test_cli_rejects_invalid_combinations);
    run_test("CLI actions", test_cli_actions);
    run_test("statistics", test_statistics_aggregation_and_ordering);

    (void)fprintf(stderr, "%u tests, %u failures\n", tests_run, tests_failed);
    return tests_failed == 0U ? EXIT_SUCCESS : EXIT_FAILURE;
}
