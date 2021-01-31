
#ifndef __FUZZER_DEVICE_TABLE_H__
#define __FUZZER_DEVICE_TABLE_H__

#define MAX_DEVICE_NAME 256


typedef struct {
    char device_name[MAX_DEVICE_NAME];
    bind_target_data device_data;
} fuzzer_device;

fuzzer_device fuzzer_device_table[] = {
    {"vuln-device",{0x00,0x6666,0xFF,0x1234,0x00,0x00,HYPERCALL_FLAG_FAIL_UNSUPPORT}} ,
};

#endif
