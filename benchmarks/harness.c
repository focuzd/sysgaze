#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

enum { DEFAULT_WARMUPS = 5, DEFAULT_ITERATIONS = 30, MAX_ITERATIONS = 1000 };

struct workload {
    const char *name;
    const char *argument;
    const char *workers;
    bool follow;
    uint64_t filtered_events;
};

enum runner_kind { RUN_NATIVE, RUN_SYSGAZE, RUN_STRACE };

struct runner {
    const char *name;
    enum runner_kind kind;
    bool filtered;
    bool seccomp;
};

struct sample {
    double wall_ms;
    double cpu_ms;
    uint64_t events;
    uint64_t ptrace_calls;
};

static const struct workload workloads[] = {
    {"syscall", "syscall", NULL, false, 2000U},
    {"file", "file", NULL, false, 200U},
    {"process", "process", NULL, true, 800U},
    {"thread", "thread", NULL, true, 800U}
};

static int configured_count(const char *name, int fallback)
{
    const char *text = getenv(name);
    char *end = NULL;
    long value;

    if (text == NULL || *text == '\0') {
        return fallback;
    }
    errno = 0;
    value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value < 1 ||
        value > MAX_ITERATIONS) {
        (void)fprintf(stderr, "%s must be between 1 and %d\n", name,
                      MAX_ITERATIONS);
        exit(2);
    }
    return (int)value;
}

static uint64_t timespec_nanoseconds(const struct timespec *value)
{
    return (uint64_t)value->tv_sec * UINT64_C(1000000000) +
           (uint64_t)value->tv_nsec;
}

static int64_t timeval_microseconds(const struct timeval *value)
{
    return (int64_t)value->tv_sec * INT64_C(1000000) + value->tv_usec;
}

static double usage_cpu_ms(const struct rusage *before,
                           const struct rusage *after)
{
    int64_t user = timeval_microseconds(&after->ru_utime) -
                   timeval_microseconds(&before->ru_utime);
    int64_t system = timeval_microseconds(&after->ru_stime) -
                     timeval_microseconds(&before->ru_stime);

    return (double)(user + system) / 1000.0;
}

static bool parse_metrics(int descriptor, uint64_t *events,
                          uint64_t *ptrace_calls)
{
    char buffer[128];
    size_t used = 0U;

    for (;;) {
        ssize_t amount = read(descriptor, buffer + used,
                              sizeof(buffer) - used - 1U);

        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount < 0) {
            return false;
        }
        if (amount == 0) {
            break;
        }
        used += (size_t)amount;
        if (used == sizeof(buffer) - 1U) {
            break;
        }
    }
    buffer[used] = '\0';
    return sscanf(buffer, "events=%" SCNu64 " ptrace_calls=%" SCNu64,
                  events, ptrace_calls) == 2;
}

static uint64_t count_strace_events(const char *path)
{
    char line[4096];
    FILE *stream = fopen(path, "r");
    uint64_t count = 0U;

    if (stream == NULL) {
        return UINT64_MAX;
    }
    while (fgets(line, sizeof(line), stream) != NULL) {
        char *cursor = line;

        if (strncmp(cursor, "[pid ", 5U) == 0) {
            char *closing = strchr(cursor, ']');
            if (closing != NULL) {
                cursor = closing + 1;
                while (*cursor == ' ') {
                    ++cursor;
                }
            }
        }
        if (strncmp(cursor, "<...", 4U) != 0 && strchr(cursor, '(') != NULL) {
            ++count;
        }
    }
    if (ferror(stream) != 0) {
        count = UINT64_MAX;
    }
    (void)fclose(stream);
    return count;
}

static void redirect_to_null(int descriptor, int flags)
{
    int null = open("/dev/null", flags | O_CLOEXEC);

    if (null < 0 || dup2(null, descriptor) < 0) {
        _exit(126);
    }
    if (null != descriptor) {
        (void)close(null);
    }
}

static void execute_runner(const struct runner *runner,
                           const struct workload *workload,
                           const char *sysgaze, const char *workload_program,
                           const char *strace, const char *output_path,
                           int metrics_descriptor)
{
    char descriptor_text[32];
    char *arguments[16];
    size_t used = 0U;

    redirect_to_null(STDOUT_FILENO, O_WRONLY);
    redirect_to_null(STDERR_FILENO, O_WRONLY);
    if (runner->kind == RUN_NATIVE) {
        char *native_arguments[] = {
            (char *)workload_program, (char *)workload->argument,
            (char *)workload->workers, NULL
        };
        execve(workload_program, native_arguments, environ);
        _exit(127);
    }

    arguments[used++] = (char *)(runner->kind == RUN_SYSGAZE ? sysgaze : strace);
    if (workload->follow) {
        arguments[used++] = (char *)"-f";
    }
    if (runner->seccomp) {
        arguments[used++] = (char *)"--seccomp-bpf";
    }
    if (runner->kind == RUN_STRACE) {
        arguments[used++] = (char *)"-qq";
    }
    arguments[used++] = (char *)"-o";
    arguments[used++] = (char *)output_path;
    if (runner->filtered) {
        arguments[used++] = (char *)"-e";
        arguments[used++] = (char *)"trace=getpid";
    }
    arguments[used++] = (char *)"--";
    arguments[used++] = (char *)workload_program;
    arguments[used++] = (char *)workload->argument;
    if (workload->workers != NULL) {
        arguments[used++] = (char *)workload->workers;
    }
    arguments[used] = NULL;

    if (runner->kind == RUN_SYSGAZE) {
        (void)snprintf(descriptor_text, sizeof(descriptor_text), "%d",
                       metrics_descriptor);
        if (setenv("SYSGAZE_BENCHMARK_FD", descriptor_text, 1) < 0) {
            _exit(126);
        }
    }
    execve(arguments[0], arguments, environ);
    _exit(127);
}

static bool run_once(const struct runner *runner,
                     const struct workload *workload, const char *sysgaze,
                     const char *workload_program, const char *strace,
                     const char *output_path, struct sample *sample)
{
    struct timespec started;
    struct timespec finished;
    struct rusage usage_before;
    struct rusage usage_after;
    struct rusage child_usage;
    int metrics[2] = {-1, -1};
    int status;
    pid_t child;

    if (truncate(output_path, 0) < 0 ||
        (runner->kind == RUN_SYSGAZE && pipe(metrics) < 0) ||
        getrusage(RUSAGE_CHILDREN, &usage_before) < 0 ||
        clock_gettime(CLOCK_MONOTONIC, &started) < 0) {
        return false;
    }
    child = fork();
    if (child < 0) {
        return false;
    }
    if (child == 0) {
        if (metrics[0] >= 0) {
            (void)close(metrics[0]);
        }
        execute_runner(runner, workload, sysgaze, workload_program, strace,
                       output_path, metrics[1]);
    }
    if (metrics[1] >= 0) {
        (void)close(metrics[1]);
    }
    while (wait4(child, &status, 0, &child_usage) < 0) {
        if (errno != EINTR) {
            return false;
        }
    }
    if (clock_gettime(CLOCK_MONOTONIC, &finished) < 0 ||
        getrusage(RUSAGE_CHILDREN, &usage_after) < 0 ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return false;
    }
    sample->wall_ms = (double)(timespec_nanoseconds(&finished) -
                               timespec_nanoseconds(&started)) / 1000000.0;
    sample->cpu_ms = usage_cpu_ms(&usage_before, &usage_after);
    sample->events = 0U;
    sample->ptrace_calls = 0U;
    if (runner->kind == RUN_SYSGAZE) {
        bool valid = parse_metrics(metrics[0], &sample->events,
                                   &sample->ptrace_calls);
        (void)close(metrics[0]);
        if (!valid) {
            sample->events = count_strace_events(output_path);
            sample->ptrace_calls = 0U;
            if (sample->events == UINT64_MAX) {
                return false;
            }
        }
    } else if (runner->kind == RUN_STRACE) {
        sample->events = count_strace_events(output_path);
        if (sample->events == UINT64_MAX) {
            return false;
        }
    }
    return true;
}

static int compare_double(const void *left, const void *right)
{
    double first = *(const double *)left;
    double second = *(const double *)right;

    return first < second ? -1 : first > second ? 1 : 0;
}

static int compare_u64(const void *left, const void *right)
{
    uint64_t first = *(const uint64_t *)left;
    uint64_t second = *(const uint64_t *)right;

    return first < second ? -1 : first > second ? 1 : 0;
}

static double median_double(const struct sample *samples, size_t count,
                            bool cpu)
{
    double *values = malloc(count * sizeof(*values));
    double result;
    size_t index;

    if (values == NULL) {
        return -1.0;
    }
    for (index = 0U; index < count; ++index) {
        values[index] = cpu ? samples[index].cpu_ms : samples[index].wall_ms;
    }
    qsort(values, count, sizeof(*values), compare_double);
    result = count % 2U != 0U ? values[count / 2U]
                              : (values[count / 2U - 1U] + values[count / 2U]) /
                                    2.0;
    free(values);
    return result;
}

static uint64_t median_u64(const struct sample *samples, size_t count,
                           bool ptrace_count)
{
    uint64_t *values = malloc(count * sizeof(*values));
    uint64_t result;
    size_t index;

    if (values == NULL) {
        return UINT64_MAX;
    }
    for (index = 0U; index < count; ++index) {
        values[index] = ptrace_count ? samples[index].ptrace_calls
                                     : samples[index].events;
    }
    qsort(values, count, sizeof(*values), compare_u64);
    result = values[count / 2U];
    free(values);
    return result;
}

static bool benchmark_runner(const struct runner *runner,
                             const struct workload *workload,
                             const char *sysgaze, const char *workload_program,
                             const char *strace, const char *output_path,
                             int warmups, int iterations, double native_median,
                             double *reported_median,
                             uint64_t *reported_ptrace_calls)
{
    struct sample *samples;
    double minimum;
    double maximum;
    double wall_median;
    double cpu_median;
    uint64_t events;
    uint64_t ptrace_calls;
    int index;

    for (index = 0; index < warmups; ++index) {
        struct sample ignored;
        if (!run_once(runner, workload, sysgaze, workload_program, strace,
                      output_path, &ignored)) {
            return false;
        }
    }
    samples = calloc((size_t)iterations, sizeof(*samples));
    if (samples == NULL) {
        return false;
    }
    for (index = 0; index < iterations; ++index) {
        if (!run_once(runner, workload, sysgaze, workload_program, strace,
                      output_path, &samples[index])) {
            free(samples);
            return false;
        }
        if (runner->filtered &&
            samples[index].events != workload->filtered_events) {
            (void)fprintf(stderr,
                          "%s/%s event mismatch: got %" PRIu64
                          ", expected %" PRIu64 "\n",
                          workload->name, runner->name, samples[index].events,
                          workload->filtered_events);
            free(samples);
            return false;
        }
    }
    minimum = samples[0].wall_ms;
    maximum = samples[0].wall_ms;
    for (index = 1; index < iterations; ++index) {
        if (samples[index].wall_ms < minimum) {
            minimum = samples[index].wall_ms;
        }
        if (samples[index].wall_ms > maximum) {
            maximum = samples[index].wall_ms;
        }
    }
    wall_median = median_double(samples, (size_t)iterations, false);
    cpu_median = median_double(samples, (size_t)iterations, true);
    events = median_u64(samples, (size_t)iterations, false);
    ptrace_calls = median_u64(samples, (size_t)iterations, true);
    free(samples);
    if (wall_median < 0.0 || cpu_median < 0.0 || events == UINT64_MAX ||
        ptrace_calls == UINT64_MAX) {
        return false;
    }
    (void)printf("%-8s %-18s %9.3f %9.3f %9.3f %9.3f %9.2f %10" PRIu64,
                 workload->name, runner->name, wall_median, minimum, maximum,
                 cpu_median,
                 native_median > 0.0 ? wall_median / native_median : 1.0,
                 events);
    if (runner->kind == RUN_SYSGAZE && ptrace_calls != 0U) {
        (void)printf(" %12" PRIu64 "\n", ptrace_calls);
    } else {
        (void)printf(" %12s\n", "-");
    }
    *reported_median = wall_median;
    *reported_ptrace_calls = ptrace_calls;
    return true;
}

static void print_header(int warmups, int iterations)
{
    (void)printf("warmups=%d iterations=%d filter=trace=getpid\n", warmups,
                 iterations);
    (void)printf("%-8s %-18s %9s %9s %9s %9s %9s %10s %12s\n",
                 "workload", "mode", "median", "min", "max", "cpu-ms",
                 "overhead", "events", "ptrace-calls");
}

static bool run_workload(const struct workload *workload,
                         const struct runner *runners, size_t runner_count,
                         const char *sysgaze, const char *workload_program,
                         const char *strace, const char *output_path,
                         int warmups, int iterations)
{
    double native_median = 0.0;
    uint64_t filtered_ptrace_calls = 0U;
    size_t runner_index;

    for (runner_index = 0U; runner_index < runner_count; ++runner_index) {
        double median;
        uint64_t ptrace_calls;

        if (!benchmark_runner(&runners[runner_index], workload, sysgaze,
                              workload_program, strace, output_path, warmups,
                              iterations, native_median, &median,
                              &ptrace_calls)) {
            (void)fprintf(stderr, "benchmark failed for %s/%s\n",
                          workload->name, runners[runner_index].name);
            return false;
        }
        if (runner_index == 0U) {
            native_median = median;
        }
        if (runners[runner_index].kind == RUN_SYSGAZE &&
            runners[runner_index].filtered && !runners[runner_index].seccomp) {
            filtered_ptrace_calls = ptrace_calls;
        }
        if (runners[runner_index].seccomp && filtered_ptrace_calls != 0U &&
            ptrace_calls >= filtered_ptrace_calls) {
            (void)fprintf(stderr,
                          "%s seccomp path did not reduce ptrace calls "
                          "(%" PRIu64 " >= %" PRIu64 ")\n",
                          workload->name, ptrace_calls,
                          filtered_ptrace_calls);
            return false;
        }
    }
    return true;
}

int main(int argc, char **argv)
{
    static const struct runner runners[] = {
        {"native", RUN_NATIVE, false, false},
        {"sysgaze", RUN_SYSGAZE, false, false},
        {"sysgaze-filtered", RUN_SYSGAZE, true, false},
        {"sysgaze-seccomp", RUN_SYSGAZE, true, true},
        {"strace", RUN_STRACE, false, false},
        {"strace-filtered", RUN_STRACE, true, false}
    };
    static const int scaling_workers[] = {1, 2, 4, 8, 16};
    static const char *const scaling_types[] = {"process", "thread"};
    char output_path[] = "/tmp/sysgaze-bench-XXXXXX";
    int warmups = configured_count("SYSGAZE_BENCH_WARMUPS", DEFAULT_WARMUPS);
    int iterations = configured_count("SYSGAZE_BENCH_ITERATIONS",
                                      DEFAULT_ITERATIONS);
    bool scaling = getenv("SYSGAZE_BENCH_SCALING") != NULL;
    size_t runner_count;
    int descriptor;

    if (argc != 3 && argc != 4) {
        (void)fprintf(stderr, "usage: %s SYSGAZE WORKLOAD [STRACE]\n", argv[0]);
        return 2;
    }
    runner_count = scaling ? 4U : argc == 4 ? 6U : 4U;
    descriptor = mkstemp(output_path);
    if (descriptor < 0 || close(descriptor) < 0) {
        (void)fprintf(stderr, "cannot create benchmark output: %s\n",
                      strerror(errno));
        return 1;
    }

    print_header(warmups, iterations);
    if (scaling) {
        size_t type_index;

        for (type_index = 0U;
             type_index < sizeof(scaling_types) / sizeof(scaling_types[0]);
             ++type_index) {
            size_t worker_index;

            for (worker_index = 0U;
                 worker_index < sizeof(scaling_workers) /
                                    sizeof(scaling_workers[0]);
                 ++worker_index) {
                char label[32];
                char worker_text[8];
                int workers = scaling_workers[worker_index];
                struct workload scaled;

                (void)snprintf(label, sizeof(label), "%s-%d",
                               scaling_types[type_index], workers);
                (void)snprintf(worker_text, sizeof(worker_text), "%d", workers);
                scaled.name = label;
                scaled.argument = scaling_types[type_index];
                scaled.workers = worker_text;
                scaled.follow = true;
                scaled.filtered_events = (uint64_t)(unsigned int)workers * 100U;
                if (!run_workload(&scaled, runners, runner_count, argv[1],
                                  argv[2], NULL, output_path, warmups,
                                  iterations)) {
                    (void)unlink(output_path);
                    return 1;
                }
            }
        }
    } else {
        size_t workload_index;

        for (workload_index = 0U;
             workload_index < sizeof(workloads) / sizeof(workloads[0]);
             ++workload_index) {
            if (!run_workload(&workloads[workload_index], runners,
                              runner_count, argv[1], argv[2],
                              argc == 4 ? argv[3] : NULL, output_path, warmups,
                              iterations)) {
                (void)unlink(output_path);
                return 1;
            }
        }
    }
    (void)unlink(output_path);
    return 0;
}
