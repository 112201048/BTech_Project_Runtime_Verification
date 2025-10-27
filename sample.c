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
    init_system();

    printf("Started sampling ...\n");

    for (int i = 0; i < 5; i++) {
        b += i * 10;
        if (b > 150) {
            c = true;
        }
    }

    while(1);
    return 0;
}
