
#include <stdio.h>

#define MAX_SIZE (0x100)


typedef struct {
    char buffer[MAX_SIZE];
    int a;
    int b;
    int c;
    int d;
} data;


int main() {
    data test = {0};

    printf("no crash!\n");

    test.buffer[0x1001] = 0xFF;

    printf("try crash!\n");

    test.buffer[sizeof(data)] = 0xFF;

    return 0;
}



