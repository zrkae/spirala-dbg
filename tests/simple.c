#include <stdio.h>
#include <unistd.h>

int main()
{
    puts("hi");
    fflush(stdout);
    sleep(3);
    puts("hi again");
}
