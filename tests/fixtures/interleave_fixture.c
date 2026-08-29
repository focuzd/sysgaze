#include <pthread.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static int descriptors[2];

static void *worker_main(void *opaque)
{
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 30000000L};
    char byte = 'x';
    volatile long process_id;

    (void)opaque;
    (void)nanosleep(&delay, NULL);
    process_id = syscall(SYS_getpid);
    (void)process_id;
    if (write(descriptors[1], &byte, 1U) != 1) {
        return (void *)(uintptr_t)1U;
    }
    return NULL;
}

int main(void)
{
    pthread_t worker;
    void *result = NULL;
    char byte;

    if (pipe(descriptors) < 0 ||
        pthread_create(&worker, NULL, worker_main, NULL) != 0 ||
        read(descriptors[0], &byte, 1U) != 1 || byte != 'x' ||
        pthread_join(worker, &result) != 0 || result != NULL) {
        return 60;
    }
    return 0;
}
