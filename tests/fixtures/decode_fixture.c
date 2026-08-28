#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

int main(void)
{
    const unsigned char payload[] = {'a', 'b', 'c', 'd', 'e', '\n', '\0', 0xffU};
    unsigned char received[sizeof(payload)] = {0};
    const char missing[] = "/sysgaze/this-path-does-not-exist";
    int descriptors[2];
    struct utsname identity;
    int descriptor;

    if (pipe2(descriptors, O_CLOEXEC) < 0) {
        return 20;
    }
    if (write(descriptors[1], payload, sizeof(payload)) !=
        (ssize_t)sizeof(payload)) {
        return 21;
    }
    if (read(descriptors[0], received, sizeof(received)) !=
        (ssize_t)sizeof(received)) {
        return 22;
    }
    descriptor = openat(AT_FDCWD, missing, O_RDONLY);
    if (descriptor >= 0) {
        (void)close(descriptor);
        return 23;
    }
    if (uname(&identity) < 0) {
        return 24;
    }
    if (syscall(SYS_write, -1, (void *)(uintptr_t)1U, (size_t)4U) != -1) {
        return 25;
    }
    return 0;
}
