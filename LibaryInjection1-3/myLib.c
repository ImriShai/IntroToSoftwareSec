#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <dlfcn.h>

// Array of predictable numbers to return from rand()
static int known_numbers[] = {42, 1337, 123, 999, 777};
// Index to keep track of the current position in known_numbers
static int index = 0;

typedef void (*orig_srand_t)(unsigned int);
typedef time_t (*orig_time_t)(time_t *);
typedef int (*orig_rand_t)(void);

// Custom implementation of srand() that always sets a fixed seed value
void srand(unsigned int seed) {
    orig_srand_t original_srand = (orig_srand_t)dlsym(RTLD_NEXT, "srand");
    original_srand(12345); // Fixed seed value
}

// Custom implementation of time() that always returns a fixed time value, doesn't need a handler because it doesn't call the original function
time_t time(time_t *t) {
    time_t fake_time = 1678900000; // Fixed time value
    if (t) *t = fake_time; // if t is not NULL, set the value to fake_time
    return fake_time;
}

// Custom implementation of rand() that returns predictable values from known_numbers
int rand(void) {
    return known_numbers[index++ % 5]; // Return predictable values
}