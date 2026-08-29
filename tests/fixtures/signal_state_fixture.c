#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t handled;

static void handle_user_signal(int signal_number)
{
    (void)signal_number;
    handled = 1;
}

int main(void)
{
    struct sigaction action = {0};
    struct sigaction ignored = {0};
    sigset_t blocked;
    pid_t helper;
    int status;

    action.sa_handler = handle_user_signal;
    ignored.sa_handler = SIG_IGN;
    if (sigemptyset(&action.sa_mask) < 0 ||
        sigemptyset(&ignored.sa_mask) < 0 ||
        sigaction(SIGUSR1, &action, NULL) < 0 ||
        sigaction(SIGUSR2, &ignored, NULL) < 0 ||
        sigemptyset(&blocked) < 0 || sigaddset(&blocked, SIGUSR1) < 0 ||
        sigprocmask(SIG_BLOCK, &blocked, NULL) < 0 || raise(SIGUSR1) != 0 ||
        handled != 0 || sigprocmask(SIG_UNBLOCK, &blocked, NULL) < 0 ||
        handled != 1 || raise(SIGUSR2) != 0) {
        return 50;
    }
    handled = 0;
    if (sigaction(SIGTRAP, &action, NULL) < 0 || raise(SIGTRAP) != 0 ||
        handled != 1) {
        return 55;
    }

    helper = fork();
    if (helper < 0) {
        return 51;
    }
    if (helper == 0) {
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 30000000L};

        (void)nanosleep(&delay, NULL);
        _exit(kill(getppid(), SIGCONT) == 0 ? 0 : 52);
    }
    if (raise(SIGSTOP) != 0 || waitpid(helper, &status, 0) != helper ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return 53;
    }
    (void)raise(SIGTERM);
    return 54;
}
