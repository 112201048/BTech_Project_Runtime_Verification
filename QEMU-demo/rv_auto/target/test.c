#include <stdio.h>
#include <unistd.h>

int x = 0;
int y = 0;

int main() {
    printf("Program started\n");
    printf("Address of x: %p\n", (void*)&x);
    printf("Address of y: %p\n", (void*)&y);

    for (int i = 0; i < 5; i++) {
        x = i;
        y = i * 10;

        printf("Program: x=%d, y=%d\n", x, y);
        sleep(1);
    }

    return 0;
}