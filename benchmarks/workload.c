#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

enum {
    SYSCALL_ITERATIONS = 2000,
    FILE_ITERATIONS = 200,
    DEFAULT_FANOUT_WORKERS = 8,
    MAX_FANOUT_WORKERS = 16,
    FANOUT_ITERATIONS = 100
};

static int syscall_workload(void)
{
    int index;

    for (index = 0; index < SYSCALL_ITERATIONS; ++index) {
        (void)syscall(SYS_getpid);
    }
    return 0;
}

static int file_workload(void)
{
    static const char byte = 'x';
    char input;
    int index;

    for (index = 0; index < FILE_ITERATIONS; ++index) {
        int zero = open("/dev/zero", O_RDONLY | O_CLOEXEC);
        int null = open("/dev/null", O_WRONLY | O_CLOEXEC);

        if (zero < 0 || null < 0 || read(zero, &input, 1U) != 1 ||
            write(null, &byte, 1U) != 1 || close(zero) < 0 || close(null) < 0) {
            if (zero >= 0) {
                (void)close(zero);
            }
            if (null >= 0) {
                (void)close(null);
            }
            return 1;
        }
        (void)syscall(SYS_getpid);
    }
    return 0;
}

static int process_workload(int workers)
{
    pid_t children[MAX_FANOUT_WORKERS];
    int worker;

    for (worker = 0; worker < workers; ++worker) {
        pid_t child = fork();

        if (child < 0) {
            return 1;
        }
        if (child == 0) {
            int index;

            for (index = 0; index < FANOUT_ITERATIONS; ++index) {
                (void)syscall(SYS_getpid);
            }
            _exit(0);
        }
        children[worker] = child;
    }
    for (worker = 0; worker < workers; ++worker) {
        int status;

        if (waitpid(children[worker], &status, 0) != children[worker] ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            return 1;
        }
    }
    return 0;
}

static void *thread_worker(void *opaque)
{
    int index;

    (void)opaque;
    for (index = 0; index < FANOUT_ITERATIONS; ++index) {
        (void)syscall(SYS_getpid);
    }
    return NULL;
}

static int thread_workload(int workers)
{
    pthread_t threads[MAX_FANOUT_WORKERS];
    int worker;

    for (worker = 0; worker < workers; ++worker) {
        int result = pthread_create(&threads[worker], NULL, thread_worker, NULL);

        if (result != 0) {
            (void)fprintf(stderr, "pthread_create: %s\n", strerror(result));
            return 1;
        }
    }
    for (worker = 0; worker < workers; ++worker) {
        int result = pthread_join(threads[worker], NULL);

        if (result != 0) {
            (void)fprintf(stderr, "pthread_join: %s\n", strerror(result));
            return 1;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    int workers = DEFAULT_FANOUT_WORKERS;

    if (argc != 2 && argc != 3) {
        (void)fprintf(stderr,
                      "usage: %s syscall|file|process|thread [workers]\n",
                      argv[0]);
        return 2;
    }
    if (argc == 3) {
        char *end = NULL;
        long value;

        errno = 0;
        value = strtol(argv[2], &end, 10);
        if (errno != 0 || end == argv[2] || *end != '\0' || value < 1 ||
            value > MAX_FANOUT_WORKERS) {
            (void)fprintf(stderr, "workers must be between 1 and %d\n",
                          MAX_FANOUT_WORKERS);
            return 2;
        }
        workers = (int)value;
    }
    if (strcmp(argv[1], "syscall") == 0) {
        return syscall_workload();
    }
    if (strcmp(argv[1], "file") == 0) {
        return file_workload();
    }
    if (strcmp(argv[1], "process") == 0) {
        return process_workload(workers);
    }
    if (strcmp(argv[1], "thread") == 0) {
        return thread_workload(workers);
    }
    (void)fprintf(stderr, "unknown workload '%s'\n", argv[1]);
    return 2;
}
