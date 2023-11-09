#include <stdio.h>
#include <unistd.h>

int main()
{
    int i = 0;
    for (;; i++) {
        printf("%d\n", i);
        sleep(1);
    }
}
