
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

fuzz_data* fuzz_random_data_maker(int data_size) {
    fuzz_data* result = (fuzz_data*)malloc(sizeof(fuzz_data));

    if (NULL == result)
        return NULL;

    memset(result,0,sizeof(fuzz_data));

    int fuzz_entry = rand() % RANDOM_FUZZING_ENTRY_RANGE;
    int fuzz_io = rand() % RANDOM_FUZZING_READ_WRITE_RANGE;
    int fuzz_offset = rand() % data_size;

    SET_FUZZ_ENTRY(result->random_fuzzing_method,fuzz_entry);
    SET_FUZZ_IO(result->random_fuzzing_method,fuzz_io);
    SET_FUZZ_OFFSET(result->random_fuzzing_method,fuzz_offset);

    if (fuzz_offset + RANDOM_FUZZING_SIZE_RANGE >= data_size) {  //  MMIO Buffer Write Check 
        int make_range = data_size - fuzz_offset;

        result->random_fuzzing_size = rand() % make_range;
    } else {
        result->random_fuzzing_size = rand() % RANDOM_FUZZING_SIZE_RANGE;
    }

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




