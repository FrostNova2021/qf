
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

#include "fuzzer_mutite.h"
#include "kernel_bridge.h"


#define MM_INDEX 0x00
#define MM_DATA  0x04
#define MM_SIZE  1024 * 4

#define KVM_HYPERCALL "vmcall"

static inline long kvm_hypercall0(unsigned int nr) {
    long ret;
    asm volatile(KVM_HYPERCALL
             : "=a"(ret)
             : "a"(nr));
    return ret;
}

static inline long kvm_hypercall1(unsigned int nr, unsigned long p1) {
    long ret;
    asm volatile(KVM_HYPERCALL
             : "=a"(ret)
             : "a"(nr), "b"(p1));
    return ret;
}

static inline long kvm_hypercall2(unsigned int nr, unsigned long p1,
                  unsigned long p2) {
    long ret;
    asm volatile(KVM_HYPERCALL
             : "=a"(ret)
             : "a"(nr), "b"(p1), "c"(p2));
    return ret;
}

static inline long kvm_hypercall3(unsigned int nr, unsigned long p1,
                  unsigned long p2, unsigned long p3) {
    long ret;
    asm volatile(KVM_HYPERCALL
             : "=a"(ret)
             : "a"(nr), "b"(p1), "c"(p2), "d"(p3));
    return ret;
}

static inline long kvm_hypercall4(unsigned int nr, unsigned long p1,
                  unsigned long p2, unsigned long p3,
                  unsigned long p4) {
    long ret;
    asm volatile(KVM_HYPERCALL
             : "=a"(ret)
             : "a"(nr), "b"(p1), "c"(p2), "d"(p3), "S"(p4));
    return ret;
}


unsigned char* mmio_mem;

void mmio_write(uint32_t addr,uint32_t data) {
    *((uint32_t*)(mmio_mem + addr)) = data;
}

void trigger_mmio(void) {
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);

    mmio_mem = mmap(0, MM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);

    printf("mmio_mem @ %p\n", mmio_mem);

    mmio_write(MM_INDEX,4);  //  s->regs.mm_index = 4;
    mmio_write(MM_DATA,0xABCDABCD);  //  =>  trigger ..

}

int is_qemu_fuzzer_kvm_envirement(void) {
    unsigned long result = kvm_hypercall0(HYPERCALL_CHECK_FUZZER);

    printf("result = %d \n",result);

    if (HYPERCALL_FLAG_CHECK_FUZZER == HYPERCALL_LOW_32BIT(result))
        return 1;
    
    return 0;
}

int is_qemu_fuzzer_ready_state(void) {
    unsigned long result = HYPERCALL_LOW_32BIT(kvm_hypercall0(HYPERCALL_CHECK_READY));

    if (HYPERCALL_FLAG_SUCCESS == result)
        return 1;
    
    return 0;
}

int push_fuzzing_record(int random_fuzzing_entry,int random_fuzzing_size,int random_fuzzing_r1,int random_fuzzing_r2) {
    unsigned long result = HYPERCALL_LOW_32BIT(kvm_hypercall4(HYPERCALL_PUSH_RECORD,
        random_fuzzing_entry,
        random_fuzzing_size,
        random_fuzzing_r1,
        random_fuzzing_r2));

    if (HYPERCALL_FLAG_SUCCESS == result)
        return 1;
    else if (HYPERCALL_FLAG_FAIL_FUZZER_OUTLINE == result)
        printf("Check fuzzer like outline\n");
    
    return 0;
}


int main(int argc, char *argv[]) {
    if (!is_qemu_fuzzer_kvm_envirement()) {
        printf("QEMU Fuzzer kvm envirement check running fail ! \n");

        return 1;
    }

    printf("QEMU Fuzzer kvm envirement check success\n");

    while (1) {
        while (is_qemu_fuzzer_ready_state()) {  //  fuzzer online
            int random_fuzzing_entry = 0;
            int random_fuzzing_size = 0;
            int random_fuzzing_r1 = 0;
            int random_fuzzing_r2 = 0;

            push_fuzzing_record();
            data_maker_number();

        }

        while (!is_qemu_fuzzer_ready_state()) {  //  ffuzer outline
            printf("QEMU Fuzzer.cc no ready -- Check Fuzzer.cc on hostOS \n");
            sleep(3);
        }
    }


    return 0;
}