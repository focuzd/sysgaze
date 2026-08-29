#include <stddef.h>
#include <sys/mman.h>

int main(void)
{
    void *page = mmap(NULL, 4096U, PROT_NONE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    volatile unsigned char value;

    if (page == MAP_FAILED) {
        return 70;
    }
    value = *(volatile unsigned char *)page;
    (void)value;
    return 71;
}
