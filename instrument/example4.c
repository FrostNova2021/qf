

#include <stdio.h>



int foo1(int b) {
    printf("foo1 !!\n");

    if (b==1) {
        ;
    } else {
        foo2(b);
    }

    return 0;
}

int foo2(int b) {
    printf("foo1 !!\n");

    if (b==1) {
        ;
    } else {
        foo3(b);
    }

    return 0;
}

int foo3(int b) {
    printf("foo1 !!\n");

    if (b==1) {
        ;
    } else {
        foo4(b);
    }

    return 0;
}

int foo4(int b) {
    printf("foo1 !!\n");

    if (b==1) {
        ;
    } else {
        ;
    }

    return 0;
}


int main(int argc,char** argv) {
    __sanitizer_enter();

    printf("main running !!!\n");

    foo1(2);

    printf("main exit !!\n");

    __sanitizer_exit();
    return 1;
}



