

#include <asm/cacheflush.h>
#include <asm/vmx.h>
#include <asm/kvm_host.h>
#include <linux/kernel.h>
#include <linux/kvm_host.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <net/sock.h>


#if LINUX_VERSION_CODE > KERNEL_VERSION(5,0,0)
#include <linux/kprobes.h>
#else
#include <linux/kallsyms.h>
#endif

#include "kernel_bridge.h"


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Access non-exported symbols");
MODULE_AUTHOR("Ben Bancroft");

static int (*buffervm_set_memory_rw)(unsigned long addr, int numpages);
static int (*buffervm_set_memory_ro)(unsigned long addr, int numpages);

static int (*vmcall_handle_func)(struct kvm_vcpu *vcpu);


#if LINUX_VERSION_CODE > KERNEL_VERSION(5,0,0)
static int handler_pre(struct kprobe *p, struct pt_regs *regs){
    return 0;
}
static struct kprobe kp = {  
    .symbol_name = "kallsyms_lookup_name",  
};  

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t fn_kallsyms_lookup_name = 0;

int __get_kallsyms_lookup_name(void)
{
    int ret = -1;
    kp.pre_handler = handler_pre;
    ret = register_kprobe(&kp);

    if (ret < 0) {
        printk(KERN_INFO "register_kprobe failed, returned %d\n", ret);

        return ret;
    }

    printk(KERN_INFO "Planted kprobe at %p\n", kp.addr);
    fn_kallsyms_lookup_name = (kallsyms_lookup_name_t)(void*)kp.addr;
    unregister_kprobe(&kp);
    return ret;
}
#endif


struct sock* netlink_handle = NULL;

static void netlink_receive_recall(struct sk_buff* buffer) {
    struct nlmsghdr* message = (struct nlmsghdr*)buffer->data;
    int pid = message->nlmsg_pid;
    user_message_header* recv_message_header = nlmsg_data(message);
    int operation_id = recv_message_header->operation_id;

    printk(KERN_INFO "netlink_receive_recall() ! => %d\n",operation_id);

    struct sk_buff* output_buffer = NULL;
    int output_buffer_size = 0;

    switch (operation_id) {
        case KERNEL_BRIDGE_MESSAGE_ECHO: {
            output_buffer_size = sizeof(kernel_message_echo);
            output_buffer = nlmsg_new(output_buffer_size,0);
            
            if(!output_buffer) {
                printk(KERN_ERR "Failed to allocate new skb\n");

                return;
            }

            kernel_message_echo* message_echo = (kernel_message_echo*)output_buffer;

            message_echo->operation_id = operation_id;
            message_echo->echo_buffer_length = strlen(MSG_ECHO);
            memcpy(&message_echo->echo_buffer,MSG_ECHO,message_echo->echo_buffer_length);

            printk(KERN_INFO "message_echo->echo_buffer_length = %d %d\n",message_echo->echo_buffer_length,output_buffer_size);
            struct nlmsghdr* message_header = nlmsg_put(output_buffer,0,0,NLMSG_DONE,output_buffer_size,0);
            NETLINK_CB(output_buffer).dst_group = 0;
            memcpy(nlmsg_data(message_header),output_buffer,output_buffer_size);

            break;
        } default: {}
    }

    if (NULL != output_buffer) {
        nlmsg_unicast(netlink_handle,output_buffer,pid);
        printk(KERN_INFO "Netlink send back data to %d\n",pid);
    } else {
        printk(KERN_ERR "Receive Error operation_id = %d\n",operation_id);
    }
}


static int buffervm_handle_vmcall(struct kvm_vcpu *vcpu) {
    unsigned long vmcall_number = vcpu->arch.regs[VCPU_REGS_RAX];

    printk("[%s] vmcall: 0x%lx\n", __this_module.name, vmcall_number);

    int result = (*vmcall_handle_func)(vcpu);

    switch (vmcall_number) {
        case HYPERCALL_CHECK_FUZZER :
            printk(KERN_INFO "vmcall => HYPERCALL_CHECK_FUZZER \n");
        default :
            break;
    }

    return result;
}

static int __init buffervm_init(void)
{
    unsigned long addr;
    struct netlink_kernel_cfg init_config = {
        .input = netlink_receive_recall
    };

    netlink_handle = netlink_kernel_create(&init_net,NETLINK_CHANNEL_ID,&init_config);

    if (!netlink_handle) {
        pr_err("Create netlink Error no=%d\n",netlink_handle);
        
        return -ENXIO;
    }

    #if LINUX_VERSION_CODE > KERNEL_VERSION(5,0,0)
        __get_kallsyms_lookup_name();

        buffervm_set_memory_rw = (void *)fn_kallsyms_lookup_name("set_memory_rw");
    #else
        buffervm_set_memory_rw = (void *)kallsyms_lookup_name("set_memory_rw");
    #endif


    if (!buffervm_set_memory_rw) {
        pr_err("can't find set_memory_rw symbol\n");

        return -ENXIO;
    }

    #if LINUX_VERSION_CODE > KERNEL_VERSION(5,0,0)
        buffervm_set_memory_ro = (void *)fn_kallsyms_lookup_name("set_memory_ro");
    #else
        buffervm_set_memory_ro = (void *)kallsyms_lookup_name("set_memory_ro");
    #endif

    if (!buffervm_set_memory_ro) {
        pr_err("can't find set_memory_ro symbol\n");

        return -ENXIO;
    }

    #if LINUX_VERSION_CODE > KERNEL_VERSION(5,0,0)
        unsigned long handler_base_addr = fn_kallsyms_lookup_name("kvm_vmx_exit_handlers");
        uintptr_t vmcall_handle_func_symbol = fn_kallsyms_lookup_name("handle_vmcall");
    #else
        unsigned long handler_base_addr = kallsyms_lookup_name("kvm_vmx_exit_handlers");
        uintptr_t vmcall_handle_func_symbol = kallsyms_lookup_name("handle_vmcall");
    #endif

    uintptr_t *kvm_vmcall_exit_handler = (uintptr_t *)(handler_base_addr + sizeof (uintptr_t) * EXIT_REASON_VMCALL);


    if (*kvm_vmcall_exit_handler != vmcall_handle_func_symbol) {
        pr_err("Cannot patch vmcall handler - original function is wrong. Is kernel newer?\n");

        return -ENXIO;
    }

    vmcall_handle_func = vmcall_handle_func_symbol;

    printk(KERN_INFO "[%s] (0x%lx): 0x%lx actual 0x%lx\n", __this_module.name, handler_base_addr, *kvm_vmcall_exit_handler, vmcall_handle_func_symbol);

    addr = PAGE_ALIGN((uintptr_t) kvm_vmcall_exit_handler) - PAGE_SIZE;

    buffervm_set_memory_rw(addr, 1);
    *kvm_vmcall_exit_handler = &buffervm_handle_vmcall;
    buffervm_set_memory_ro(addr, 1);

    return 0;
}

static void __exit buffervm_exit(void)
{
    unsigned long addr;
    unsigned long handler_base_addr;
    uintptr_t *kvm_vmcall_exit_handler;

    #if LINUX_VERSION_CODE > KERNEL_VERSION(5,0,0)
        handler_base_addr = (void *)fn_kallsyms_lookup_name("kvm_vmx_exit_handlers");
    #else
        handler_base_addr = (void *)kallsyms_lookup_name("kvm_vmx_exit_handlers");
    #endif
        
    kvm_vmcall_exit_handler = (uintptr_t *)(handler_base_addr + sizeof (uintptr_t) * EXIT_REASON_VMCALL);
    addr = PAGE_ALIGN((uintptr_t) kvm_vmcall_exit_handler) - PAGE_SIZE;

    buffervm_set_memory_rw(addr, 1);
    *kvm_vmcall_exit_handler = vmcall_handle_func;
    buffervm_set_memory_ro(addr, 1);

    netlink_kernel_release(netlink_handle);

    printk(KERN_INFO "Goodbye world 1.\n");
}

module_init(buffervm_init);
module_exit(buffervm_exit);
