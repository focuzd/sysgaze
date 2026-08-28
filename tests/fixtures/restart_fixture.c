#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void handle_signal(int signal_number)
{
    (void)signal_number;
}

static void delay_milliseconds(long milliseconds)
{
    struct timespec delay = {
        .tv_sec = milliseconds / 1000L,
        .tv_nsec = (milliseconds % 1000L) * 1000000L
    };

    while (nanosleep(&delay, &delay) < 0 && errno == EINTR) {
    }
}

int main(void)
{
    int descriptors[2];
    struct sigaction action = {0};
    pid_t parent = getpid();
    pid_t helper;
    char byte = '\0';
    ssize_t amount;
    int status;

    action.sa_handler = handle_signal;
    action.sa_flags = SA_RESTART;
    if (sigemptyset(&action.sa_mask) < 0 ||
        sigaction(SIGUSR1, &action, NULL) < 0 || pipe(descriptors) < 0) {
        return 10;
    }

    helper = fork();
    if (helper < 0) {
        return 11;
    }
    if (helper == 0) {
        (void)close(descriptors[0]);
        delay_milliseconds(30L);
        if (kill(parent, SIGUSR1) < 0) {
            _exit(12);
        }
        delay_milliseconds(30L);
        if (write(descriptors[1], "x", 1U) != 1) {
            _exit(13);
        }
        _exit(0);
    }

    (void)close(descriptors[1]);
    amount = read(descriptors[0], &byte, 1U);
    if (amount != 1 || byte != 'x') {
        return 14;
    }
    if (waitpid(helper, &status, 0) != helper || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
        return 15;
    }
    return 0;
}
