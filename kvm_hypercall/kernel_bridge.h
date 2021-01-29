
#ifndef __KERNEL_H__
#define __KERNEL_H__

#define NETLINK_CHANNEL_ID 31

#define MSG_MAX_LENGTH 512
#define MSG_ECHO "KVM Bridge Echo"

#define HYPERCALL_CHECK_FUZZER 0xABCDEF

#ifndef __SANITIZE_CONVERAGE_H__
#ifdef __x86_64__
typedef uint64_t uint_t;
typedef float    ufloat;
#else
typedef uint32_t uint_t;
typedef float    ufloat;
#endif
#endif


#define KERNEL_BRIDGE_MESSAGE_ECHO 0x01




typedef struct {
    int operation_id;
} kernel_message_header;

typedef struct {
    int operation_id;
    int echo_buffer_length;
    char echo_buffer[MSG_MAX_LENGTH];
} kernel_message_echo;

typedef struct {
    int operation_id;
} user_message_header;

typedef struct {
    user_message_header header;

} user_message_xxx;




#endif
