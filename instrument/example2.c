

#include <stdio.h>


void try_write(void) {
    printf("try write !!!\n");
}


int try_read(void) {
    printf("try read !!!\n");

    return 0;
}


int main(int argc,char** argv) {
    printf("main running !!!\n");

    try_write();
    try_read();

    printf("main exit !!\n");

    return 1;
}



