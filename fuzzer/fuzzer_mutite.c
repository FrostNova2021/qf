

#include "fuzzer_mutite.h"
#include "kernel_bridge.h"


const char* data_maker_block(int data_size,int data_random1,int data_random2) {

    return NULL;
}

const uint_t data_maker_number(int data_size,int data_random1,int data_random2) {
    uint_t result = data_random1 * data_random2;

    if (1 == data_size) {
        result = result & 0xFF;
    } else if (2 == data_size) {
        result = result & 0xFFFF;
    } else if (4 == data_size) {
        result = result & 0xFFFFFFFF;
    } else if (8 == data_size) {
        result = result & 0xFFFFFFFFFFFFFFFF;
    }

    return result;
}




