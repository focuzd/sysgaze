#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void *thread_main(void *opaque)
{
    volatile pid_t process_id;

    (void)opaque;
    process_id = getpid();
    (void)process_id;
    return NULL;
}

int main(int argc, char **argv)
{
    pthread_t thread;
    pid_t child;
    int status;

    if (argc == 2 && strcmp(argv[1], "--child") == 0) {
        volatile pid_t process_id = getpid();

        (void)process_id;
        return 3;
    }
    if (pthread_create(&thread, NULL, thread_main, NULL) != 0) {
        return 30;
    }
    child = fork();
    if (child < 0) {
        return 31;
    }
    if (child == 0) {
        execl(argv[0], argv[0], "--child", (char *)NULL);
        _exit(32);
    }
    if (pthread_join(thread, NULL) != 0) {
        return 33;
    }
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 3) {
        return 34;
    }
    return 5;
}
