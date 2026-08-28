#include <signal.h>
#include <stdlib.h>

int main(void)
{
    if (raise(SIGTERM) != 0) {
        return EXIT_FAILURE;
    }
    return EXIT_FAILURE;
}
