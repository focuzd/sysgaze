#include <stddef.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void)
{
    static const char empty[] = "";
    volatile long first = syscall(SYS_getpid);
    volatile long second = syscall(SYS_getpid);
    volatile long third = syscall(SYS_getpid);

    (void)first;
    (void)second;
    (void)third;
    if (syscall(SYS_write, STDOUT_FILENO, empty, (size_t)0U) != 0 ||
        syscall(SYS_write, -1, empty, (size_t)1U) != -1) {
        return 80;
    }
    return 0;
}
