#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/io.h>

#define MM_INDEX 0x00
#define MM_DATA  0x04
#define MM_SIZE  1024 * 4

unsigned char* mmio_mem;

void mmio_write(uint32_t addr,uint32_t data) {
    *((uint32_t*)(mmio_mem + addr)) = data;
}


int main(int argc, char *argv[]) {
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);

    mmio_mem = mmap(0, MM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);

    printf("mmio_mem @ %p\n", mmio_mem);

    mmio_write(MM_INDEX,4);  //  s->regs.mm_index = 4;
    mmio_write(MM_DATA,0xABCDABCD);  //  =>  trigger ..

    return 0;
}