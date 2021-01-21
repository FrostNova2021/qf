

#include <memory.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <linux/shm.h>

#include <sanitizer/coverage_interface.h>

#include "sanitize_converage.h"
#include "signal_number.h"

/// -fsanitize-coverage-whitelist=


static int __sancov_trace_pc_switch = 1;
static const size_t __sancov_trace_pc_map_max = 1 << 16;
static const size_t __sancov_trace_pc_map_size = __sancov_trace_pc_map_max * sizeof(unsigned long);
static unsigned long  __sancov_trace_pc_table[__sancov_trace_pc_map_max] = {0};
static unsigned long __sancov_trace_pc_index = 0;
static unsigned long __sancov_current_all_guard_count = 0;
static pid_t __sancov_father_pid = 0;
static int __sancov_share_memory_id = 0;
static int __sancov_pipe_write = 0;
static int __sancov_pipe_read = 0;


ATTRIBUTE_NO_SANITIZE_ALL
void __sanitizer_cov_trace_pc_guard_init(uint32_t *start,uint32_t *stop) {
    static uint64_t N;

    if (start == stop || *start)
        return;

    __sancov_father_pid = getppid();

    if (__sancov_father_pid > 1) {
        int file_handle[2] = {0};

        if (-1 == pipe(file_handle)) {
            perror("Create PIPE Error!");
            exit(-1);
        }

        __sancov_pipe_read = file_handle[0];
        __sancov_pipe_write = file_handle[1];

        union sigval send_sigval;
        send_sigval.sival_int = __sancov_pipe_read << 16 | __sancov_pipe_write;
        printf("sival_int=%d\n",__sancov_pipe_write);

        //printf("fuzzer pid = %d \n",__sancov_father_pid);

        sigqueue(__sancov_father_pid,SIGNAL_CREATE_FUZZER_TARGET,send_sigval);
    } else {
        //memset(__sancov_trace_pc_table,0,__sancov_trace_pc_map_size);
    }

    __sancov_current_all_guard_count = (stop - start);

    printf("Sanitizer All Coverage edges: 0x%X \n",__sancov_current_all_guard_count);

    for (uint32_t *x = start; x < stop; x++)
        *x = ++N;
}

ATTRIBUTE_NO_SANITIZE_ALL
void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    uint32_t edge_address = (uint32_t)guard;
    uint32_t edge_id = *guard;

    if (!edge_id || !__sancov_trace_pc_switch)
        return;

    void *PC = __builtin_return_address(0);
    char symbolize_data[1024];
    char current_function_name[512];

    __sanitizer_symbolize_pc(PC, "%p %F %L", symbolize_data, sizeof(symbolize_data));
    __sanitizer_symbolize_pc(PC, "%F", current_function_name, sizeof(current_function_name));

    printf("Sanitizer Trace PC Guard : %p %x PC %s\n", edge_address, edge_id, symbolize_data);

    __sancov_trace_pc_table[__sancov_trace_pc_index++] = PC;
}

void dev_enter(void) {
    memset(&__sancov_trace_pc_table,0,sizeof(__sancov_trace_pc_table));
}

void dev_exit(void) {
    printf("Sanitizer All Execute Edges : %d \n",__sancov_trace_pc_index);

    if (__sancov_father_pid > 1) {
        unsigned long pipe_write_size = __sancov_trace_pc_index * sizeof(unsigned long);
        write(__sancov_pipe_write,__sancov_trace_pc_table,pipe_write_size);

        union sigval send_sigval;
        send_sigval.sival_int = pipe_write_size;
        printf("dev_exit %d %d \n",pipe_write_size,sizeof(unsigned long));

        sigqueue(__sancov_father_pid,SIGNAL_FUZZ_ONCE,send_sigval);
    } else {
    }

    memset(__sancov_trace_pc_table,0,__sancov_trace_pc_map_size);
    __sancov_trace_pc_index = 0;
}





