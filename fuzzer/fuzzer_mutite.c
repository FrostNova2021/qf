
#include <stdlib.h>
#include <time.h>

#include <inttypes.h>
#include <stdint.h>

#ifdef __x86_64__
typedef uint64_t uint_t;
typedef float    ufloat;
#else
typedef uint32_t uint_t;
typedef float    ufloat;
#endif

#include "fuzzer_mutite.h"


void init_random(void) {
    srand((unsigned)time(NULL));
}

fuzz_data* fuzz_random_data_maker(void) {
    fuzz_data* result = (fuzz_data*)malloc(sizeof(fuzz_data));

    if (NULL == result)
        return NULL;

    result->random_fuzzing_method = rand() % RANDOM_FUZZING_RANDOM_RANGE;
    result->random_fuzzing_size = rand() % RANDOM_FUZZING_SIZE_RANGE;
    result->random_fuzzing_r1 = rand() % RANDOM_FUZZING_RANDOM_RANGE;
    result->random_fuzzing_r2 = rand() % RANDOM_FUZZING_RANDOM_RANGE;

    return result;
}

char* data_maker_block(int data_size,int data_random1,int data_random2) {

    return NULL;
}

uint_t data_maker_number(int data_size,int data_random1,int data_random2) {
    uint_t result = data_random1 * data_random2;

    if (1 == data_size) {
        result = result & 0xFF;
    } else if (2 == data_size) {
        result = result & 0xFFFF;
    } else if (4 == data_size) {
        result = result & 0xFFFFFFFF;
    } else if (8 == data_size) {
        result = result & 0xFFFFFFFFFFFFFFFF;
    } else {
        result = 0;
    }

    return result;
}




