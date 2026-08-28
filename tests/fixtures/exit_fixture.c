#include <sys/types.h>
#include <unistd.h>

int main(void)
{
    volatile pid_t process_id = getpid();

    (void)process_id;
    return 7;
}
