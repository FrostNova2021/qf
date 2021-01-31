
#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/dir.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/io.h>

#include "kernel_bridge.h"
#include "fuzzer_mutite.h"


#define MM_INDEX (0x00)
#define MM_DATA  (0x04)
#define MM_SIZE  (1024 * 4)

#define KVM_HYPERCALL "vmcall"

#define LINUX_SYS_DEVICE_PATH "/sys/devices/pci0000:00/"


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

int get_qemu_fuzzer_target_device(void) {
    unsigned long result = HYPERCALL_LOW_32BIT(kvm_hypercall0(HYPERCALL_GET_DEVICE));

    if (HYPERCALL_FLAG_FAIL_ERROR_ID == result)
        return -1;
    
    return result;
}

int get_qemu_fuzzer_target_class(void) {
    unsigned long result = HYPERCALL_LOW_32BIT(kvm_hypercall0(HYPERCALL_GET_CLASS));

    if (HYPERCALL_FLAG_FAIL_ERROR_ID == result)
        return -1;
    
    return result;
}

int get_qemu_fuzzer_target_vendor(void) {
    unsigned long result = HYPERCALL_LOW_32BIT(kvm_hypercall0(HYPERCALL_GET_VENDOR));

    if (HYPERCALL_FLAG_FAIL_ERROR_ID == result)
        return -1;
    
    return result;
}

int get_qemu_fuzzer_target_revision(void) {
    unsigned long result = HYPERCALL_LOW_32BIT(kvm_hypercall0(HYPERCALL_GET_REVISION));

    if (HYPERCALL_FLAG_FAIL_ERROR_ID == result)
        return -1;
    
    return result;
}

int get_qemu_fuzzer_target_mmio_resource(void) {
    unsigned long result = HYPERCALL_LOW_32BIT(kvm_hypercall0(HYPERCALL_GET_MMIO_RESOURCE));

    if (HYPERCALL_FLAG_FAIL_ERROR_ID == result)
        return -1;
    
    return result;
}

int get_qemu_fuzzer_target_portio_resource(void) {
    unsigned long result = HYPERCALL_LOW_32BIT(kvm_hypercall0(HYPERCALL_GET_PORTIO_RESOURCE));

    if (HYPERCALL_FLAG_FAIL_ERROR_ID == result)
        return -1;
    
    return result;
}

void mmio_write_by_1byte(memory_address mmio_address,uint8_t data) {
    *((uint8_t*)mmio_address) = data;
}

void mmio_write_by_2byte(memory_address mmio_address,uint16_t data) {
    *((uint16_t*)mmio_address) = data;
}

void mmio_write_by_4byte(memory_address mmio_address,uint32_t data) {
    *((uint32_t*)mmio_address) = data;
}

void mmio_write_by_8byte(memory_address mmio_address,uint64_t data) {
    *((uint64_t*)mmio_address) = data;
}

void mmio_write(memory_address mmio_address,void* data,int data_size) {
    if (1 == data_size) {
        mmio_write_by_1byte(mmio_address,*(uint8_t*)data);
    } else if (2 == data_size) {
        mmio_write_by_2byte(mmio_address,*(uint16_t*)data);
    } else if (4 == data_size) {
        mmio_write_by_4byte(mmio_address,*(uint32_t*)data);
    } else if (8 == data_size) {
        mmio_write_by_8byte(mmio_address,*(uint64_t*)data);
    } else {
        // ......
    }
}

uint8_t mmio_read_by_1byte(memory_address mmio_address) {
    return *((uint8_t*)mmio_address);
}

uint16_t mmio_read_by_2byte(memory_address mmio_address) {
    return *((uint16_t*)mmio_address);
}

uint32_t mmio_read_by_4byte(memory_address mmio_address) {
    return *((uint32_t*)mmio_address);
}

uint64_t mmio_read_by_8byte(memory_address mmio_address) {
    return *((uint64_t*)mmio_address);
}

void mmio_read(memory_address mmio_address,int data_size) {
    if (1 == data_size) {
        *((uint8_t*)mmio_address) = mmio_read_by_1byte(mmio_address);
    } else if (2 == data_size) {
        *((uint16_t*)mmio_address) = mmio_read_by_2byte(mmio_address);
    } else if (4 == data_size) {
        *((uint32_t*)mmio_address) = mmio_read_by_4byte(mmio_address);
    } else if (8 == data_size) {
        *((uint64_t*)mmio_address) = mmio_read_by_8byte(mmio_address);
    } else {
        // ......
    }
}

int read_file_data(char* path,int* output_data) {
    int file_handle = open(path,O_RDONLY);

    if (-1 == file_handle)
        return 0;

    char temp_string[16] = {0};

    read(file_handle,temp_string,sizeof(temp_string));
    close(file_handle);
  
    char* no_use_string;
    *output_data = strtol(&temp_string,&no_use_string,16);

    return 1;
}

char* search_target_device(int device_id,int class_id,int vendor_id,int revision_id) {
    struct dirent* dirent_info = NULL;
    DIR* dir_info = opendir(LINUX_SYS_DEVICE_PATH);
    char* temp_read_device_path[1024];
    char* temp_read_class_path[1024];
    char* temp_read_vendor_path[1024];
    char* temp_read_revision_path[1024];

    while ((NULL != (dirent_info = readdir(dir_info)))) {
        if (dirent_info->d_type & DT_DIR) {
            int temp_device_id = 0;
            int temp_class_id = 0;
            int temp_vendor_id = 0;
            int temp_revision_id = 0;

            memset(temp_read_device_path,0,sizeof(temp_read_device_path));
            sprintf(temp_read_device_path,"%s/%s/device",LINUX_SYS_DEVICE_PATH,&dirent_info->d_name);
            memset(temp_read_class_path,0,sizeof(temp_read_class_path));
            sprintf(temp_read_class_path,"%s/%s/class",LINUX_SYS_DEVICE_PATH,&dirent_info->d_name);
            memset(temp_read_vendor_path,0,sizeof(temp_read_vendor_path));
            sprintf(temp_read_vendor_path,"%s/%s/vendor",LINUX_SYS_DEVICE_PATH,&dirent_info->d_name);
            memset(temp_read_revision_path,0,sizeof(temp_read_revision_path));
            sprintf(temp_read_revision_path,"%s/%s/revision",LINUX_SYS_DEVICE_PATH,&dirent_info->d_name);
            
            if (!read_file_data(temp_read_device_path,&temp_device_id) ||
                !read_file_data(temp_read_class_path,&temp_class_id) ||
                !read_file_data(temp_read_vendor_path,&temp_vendor_id) ||
                !read_file_data(temp_read_revision_path,&temp_revision_id))
                continue;

            if (device_id == temp_device_id &&
                class_id == temp_class_id &&
                vendor_id == temp_vendor_id &&
                revision_id == temp_revision_id) {
                char* result = (char*)malloc(1024);
                memset(result,0,1024);
                sprintf(result,"%s/%s/",LINUX_SYS_DEVICE_PATH,&dirent_info->d_name);

                return result;
            }
        }
    }
    
    return NULL;
}

int main(int argc, char *argv[]) {
    if (!is_qemu_fuzzer_kvm_envirement()) {
        printf("QEMU Fuzzer kvm envirement check running fail ! \n");

        return 1;
    }

    printf("QEMU Fuzzer kvm envirement check success\n");

    int target_device_id = get_qemu_fuzzer_target_device();
    int target_class_id = get_qemu_fuzzer_target_class();
    int target_vendor_id = get_qemu_fuzzer_target_vendor();
    int target_revision_id = get_qemu_fuzzer_target_revision();
    int target_mmio_resource_id = get_qemu_fuzzer_target_mmio_resource();

    if (-1 == target_device_id ||
        -1 == target_class_id ||
        -1 == target_vendor_id ||
        -1 == target_revision_id ||
        -1 == target_mmio_resource_id) {
        printf("QEMU Fuzzer Get Device Information fail ! \n");

        return 1;
    }

    printf("QEMU Fuzzer Target => DeviceID:%X ClassID:%X VendorID:%X RevisionID:%X \n",
        target_device_id,target_class_id,target_vendor_id,target_revision_id);
    printf("  => MMIO Resource Id = %d\n",target_mmio_resource_id);

    char* target_device_path = search_target_device(target_device_id,target_class_id,target_vendor_id,target_revision_id);

    if (NULL == target_device_path) {
        printf("QEMU Fuzzer Search Device fail ! \n");

        return 1;
    }

    int mmio_handle = open(target_device_path,O_RDWR|O_SYNC);
    struct stat file_state = {0};

    fstat(mmio_handle, &file_state);

    unsigned char* mmio_mem = mmap(0,file_state.st_size,PROT_READ|PROT_WRITE,MAP_SHARED,mmio_handle,0);

    init_random();

    while (1) {
        while (is_qemu_fuzzer_ready_state()) {  //  fuzzer online
            fuzz_data* random_data = fuzz_random_data_maker();
            uint_t fuzz_value = data_maker_number(
                random_data->random_fuzzing_size,
                random_data->random_fuzzing_r1,
                random_data->random_fuzzing_r2
            );

            if (HYPERCALL_FLAG_SUCCESS != push_fuzzing_record(
                random_data->random_fuzzing_method,
                random_data->random_fuzzing_size,
                random_data->random_fuzzing_r1,
                random_data->random_fuzzing_r2)) {
                printf("Push Fuzzing Record with VMCALL Error!\n");

                continue;
            }

            int fuzz_entry = GET_FUZZ_ENTRY(random_data->random_fuzzing_method);
            int fuzz_io = GET_FUZZ_IO(random_data->random_fuzzing_method);
            int fuzz_offset = GET_FUZZ_OFFSET(random_data->random_fuzzing_method);

            printf("Fuzzing Data:%d %d %d %d %d %d\n",
                fuzz_entry,
                fuzz_io,
                fuzz_offset,
                random_data->random_fuzzing_size,
                random_data->random_fuzzing_r1,
                random_data->random_fuzzing_r2);

            switch (fuzz_entry) {
                case RANDOM_FUZZING_ENTRY_MMIO:
                    if (RANDOM_FUZZING_READ == fuzz_io)
                        mmio_read((memory_address)&mmio_mem[fuzz_offset],
                                  random_data->random_fuzzing_size);
                    else
                        mmio_write((memory_address)&mmio_mem[fuzz_offset],
                                   &fuzz_value,
                                   random_data->random_fuzzing_size);

                    break;
                case RANDOM_FUZZING_ENTRY_PORTIO:
                    if (RANDOM_FUZZING_READ == fuzz_io) {

                    } else {

                    }
                    
                    break;
                default:
                    break;
            }
        }

        while (!is_qemu_fuzzer_ready_state()) {  //  fuzzer outline
            printf("QEMU Fuzzer.cc no ready -- Check Fuzzer.cc on hostOS \n");
            sleep(3);
        }
    }


    return 0;
}