#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static atomic_bool running = true;

static void stop_running(int signal_number)
{
    (void)signal_number;
    atomic_store_explicit(&running, false, memory_order_relaxed);
}

static void exercise_syscalls(void)
{
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 5000000L};

    while (atomic_load_explicit(&running, memory_order_relaxed)) {
        (void)syscall(SYS_getpid);
        (void)nanosleep(&delay, NULL);
    }
}

static void *worker_main(void *opaque)
{
    (void)opaque;
    exercise_syscalls();
    return NULL;
}

int main(void)
{
    struct sigaction action = {0};
    pthread_t first;
    pthread_t second;

    action.sa_handler = stop_running;
    if (sigemptyset(&action.sa_mask) < 0 ||
        sigaction(SIGTERM, &action, NULL) < 0 ||
        prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0UL, 0UL, 0UL) < 0 ||
        pthread_create(&first, NULL, worker_main, NULL) != 0 ||
        pthread_create(&second, NULL, worker_main, NULL) != 0) {
        return 40;
    }
    (void)puts("ready");
    (void)fflush(stdout);
    exercise_syscalls();
    if (pthread_join(first, NULL) != 0 || pthread_join(second, NULL) != 0) {
        return 41;
    }
    return 0;
}
