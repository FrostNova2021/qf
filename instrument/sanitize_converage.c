
#include <errno.h>
#include <fcntl.h>
#include <memory.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <linux/shm.h>
#include <sys/stat.h>

#include <sanitizer/coverage_interface.h>

#include "sanitize_converage.h"
#include "signal_number.h"

#define MAX_PATH_SIZE 512

/// -fsanitize-coverage-whitelist=


static int __sancov_trace_pc_switch = 1;
static const size_t __sancov_trace_pc_map_max = 1 << 16;
static const size_t __sancov_trace_pc_map_size = __sancov_trace_pc_map_max * sizeof(unsigned long);
static unsigned long  __sancov_trace_pc_table[__sancov_trace_pc_map_max] = {0};
static unsigned long __sancov_trace_pc_index = 0;
static unsigned long __sancov_current_all_guard_count = 0;
static pid_t __sancov_father_pid = 0;
static int __sancov_fuzz_loop = 0;


ATTRIBUTE_NO_SANITIZE_ALL
void __sanitizer_cov_trace_pc_guard_init(uint32_t *start,uint32_t *stop) {
    static uint64_t N;

    if (start == stop || *start)
        return;

    __sancov_father_pid = getppid();

    if (__sancov_father_pid > 1) {
        union sigval send_sigval;
        send_sigval.sival_int = getpid();

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

    __sanitizer_symbolize_pc(PC, "%p %F %L %n ", symbolize_data, sizeof(symbolize_data));
    __sanitizer_symbolize_pc(PC, "%F", current_function_name, sizeof(current_function_name));

    printf("Sanitizer Trace PC Guard : %p %x PC %s\n", PC, edge_id, symbolize_data);

    __sancov_trace_pc_table[__sancov_trace_pc_index++] = edge_id;
}

void dev_enter(void) {
    memset(&__sancov_trace_pc_table,0,sizeof(__sancov_trace_pc_table));

    __sancov_trace_pc_index = 0;
}

void dev_exit(void) {
    printf("Sanitizer All Execute Edges : %d \n",__sancov_trace_pc_index);

    /*
    if (__sancov_father_pid > 1) {
        unsigned long pipe_write_size = __sancov_trace_pc_index * sizeof(unsigned long);
        char save_dir[MAX_PATH_SIZE] = {0};

        sprintf(save_dir,"./temp_%d_%d",__sancov_father_pid,getpid());

        if (!opendir(save_dir))
            mkdir(save_dir,0777);

        char save_coverage_path[MAX_PATH_SIZE] = {0};

        sprintf(save_coverage_path,"%s/%d.dat",save_dir,__sancov_fuzz_loop);

        int save_data_handle = open(save_coverage_path,O_RDWR | O_CREAT,S_IRUSR | S_IWUSR | S_IROTH);

        if (NULL == save_data_handle) {
            printf("errno = %d \n",errno);

            return;
        }

        write(save_data_handle,&__sancov_trace_pc_table,pipe_write_size);
        close(save_data_handle);

        union sigval send_sigval;
        send_sigval.sival_int = __sancov_fuzz_loop;


        sigqueue(__sancov_father_pid,SIGNAL_FUZZ_ONCE,send_sigval);

        __sancov_fuzz_loop++;
    } else {
    }

    memset(__sancov_trace_pc_table,0,__sancov_trace_pc_map_size);

    __sancov_trace_pc_index = 0;*/
    __sanitizer_cov_dump();
}





