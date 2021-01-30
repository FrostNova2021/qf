
#ifndef __KERNEL_H__
#define __KERNEL_H__

#define NETLINK_CHANNEL_ID 31

#define MSG_MAX_LENGTH 1024

#define MSG_ECHO "KVM Bridge Echo"

#define HYPERCALL_CHECK_FUZZER  (0xABCDEF)
#define HYPERCALL_CHECK_READY   (HYPERCALL_CHECK_FUZZER + 1)
#define HYPERCALL_PUSH_RECORD   (HYPERCALL_CHECK_FUZZER + 2)

#define HYPERCALL_FLAG_SUCCESS              (0x0)
#define HYPERCALL_FLAG_FAIL                 (0x1)
#define HYPERCALL_FLAG_FAIL_FUZZER_OUTLINE  (0x2)
#define HYPERCALL_FLAG_CHECK_FUZZER         (0x51464B4D)  //  string:'QFKM'

#define HYPERCALL_LOW_32BIT(HYPERCALL_RETURN_VALUE)  (HYPERCALL_RETURN_VALUE & 0xFFFFFFFF)
#define HYPERCALL_HIGH_32BIT(HYPERCALL_RETURN_VALUE) ((HYPERCALL_RETURN_VALUE >> 32) & 0xFFFFFFFF)


#ifndef __SANITIZE_CONVERAGE_H__
#ifdef __x86_64__
typedef uint64_t uint_t;
typedef float    ufloat;
#else
typedef uint32_t uint_t;
typedef float    ufloat;
#endif
#endif

#define KERNEL_BRIDGE_MESSAGE_ERROR    (0x00)
#define KERNEL_BRIDGE_MESSAGE_SUCCESS  (0x01)
#define KERNEL_BRIDGE_MESSAGE_ECHO     (0x10)
#define KERNEL_BRIDGE_MESSAGE_REGISTER (KERNEL_BRIDGE_MESSAGE_ECHO + 1)
#define KERNEL_BRIDGE_MESSAGE_EXIT     (KERNEL_BRIDGE_MESSAGE_ECHO + 2)


//  send to fuzzer.cc
typedef struct {
    int operation_id;
} kernel_message_header;

typedef struct {
    kernel_message_header header;
    int echo_buffer_length;
    char echo_buffer[MSG_MAX_LENGTH];
} kernel_message_echo;

typedef struct {
    kernel_message_header header;
} kernel_message_check_online;

typedef struct {
    kernel_message_header header;
    int fuzzing_entry;
    int fuzzing_size;
    int fuzzing_r1;
    int fuzzing_r2;
} kernel_message_record;


//  send to kvm_hypercall
typedef struct {
    int operation_id;
} user_message_header;

typedef struct {
    user_message_header header;
} user_message_echo;

typedef struct {
    user_message_header header;
    int pid;
} user_message_register_fuzzer;

typedef struct {
    user_message_header header;
    int pid;
} user_message_check_online;




#endif
