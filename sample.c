#include <stdio.h>
#include <stdbool.h>

//Global variables whose address should be known by the Tool
int a = 1;
int b = 50;
bool c = false;

void init_system() {
    a = 0;
}

int main() {
    int abc = 0;
    init_system();
    printf("Address of a: %p\n", (void*)&a);
    printf("Address of b: %p\n", (void*)&b);
    printf("Address of c: %p\n", (void*)&c);
    int abcd = 0;


    printf("Started sampling ...\n");

    for (int i = 0; i < 5; i++) {
        b += i * 10;
        if (b > 150) {
            c = true;
        }
    }

    return 0;
}
