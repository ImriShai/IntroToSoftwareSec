#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    srand(time(NULL));
    for (int i = 0; i < 5; i++) {
        printf("Random number %d: %d\n", i + 1, rand());
    }
    return 0;
}