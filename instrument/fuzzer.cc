
#include <error.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/msg.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "sanitize_converage.h"
#include "signal_number.h"

#define MAX_FUZZER_READ_PIPE_DATA_SIZE (10 * 1024)
#define MAX_FUZZER_SUBPROCESS 5


typedef struct _ {
    int pid;
    int start_time;
    int pipe_write;
    int pipe_read;
} subprocess_envirement;


subprocess_envirement sub_fuzzer_share_memory_table[MAX_FUZZER_SUBPROCESS] = {0};
int current_all_sub_fuzzer = 0;
pid_t current_fuzzer_pid = 0;


subprocess_envirement* get_subprocess_envirement(int pid) {
    for (int index = 0;index < MAX_FUZZER_SUBPROCESS;++index) {
        //printf("%d %d %d\n",pid,sub_fuzzer_share_memory_table[index].pid,sub_fuzzer_share_memory_table[index].start_time);
        if (pid == sub_fuzzer_share_memory_table[index].pid) {
            return &sub_fuzzer_share_memory_table[index];
        }
    }

    return NULL;
}

void signal_handler(int signal_code,siginfo_t *singnal_info,void *p)
{
    //if (SIGUSR1 != signal_code)
    //    return;

    int parameter = singnal_info->si_value.sival_int;
    int subprocess_pid = singnal_info->si_pid;

    switch (signal_code) {
        case SIGNAL_CREATE_FUZZER_TARGET: {
            //  parameter  =>  pid
            int pid = parameter;
            
            printf("Create SubProcess Success ==> PID:%d \n",subprocess_pid);

            sub_fuzzer_share_memory_table[current_all_sub_fuzzer].start_time = time();
            sub_fuzzer_share_memory_table[current_all_sub_fuzzer].pid = subprocess_pid;

            current_all_sub_fuzzer++;

            break;
        } case SIGNAL_FUZZ_ONCE: {
            //  parameter  =>  fuzz_index
            int trace_count = parameter;

            printf("SubProcess Fuzz ==> PID:%d All Edge:%d \n",subprocess_pid,trace_count);

            subprocess_envirement* subprocess_data = get_subprocess_envirement(subprocess_pid);

            if (NULL == subprocess_data) {
                printf("Catch Error PID !! \n");

                return;
            }

            char save_coverage_path[MAX_PATH_SIZE] = {0};

            sprintf(save_coverage_path,"./temp_%d_%d/%d.dat",current_fuzzer_pid,subprocess_pid,trace_count);

            int save_data_handle = open(save_coverage_path,O_RDONLY);
            struct stat file_state = {0};

            fstat(save_data_handle, &file_state);

            uint_t trace_pc_map_count = 0;

            read(save_data_handle,&trace_pc_map_count,sizeof(uint_t));

            uint_t coverage_result_size = file_state.st_size - sizeof(uint_t);
            __sancov_trace_pc_map* coverage_result = (__sancov_trace_pc_map*)malloc(coverage_result_size);
            uint_t read_offset = 0;
            int read_length = 0;

            memset(coverage_result,0,coverage_result_size);

            while ((read_length = read(save_data_handle,
                                        &((unsigned char*)coverage_result)[read_offset],
                                        MAX_FUZZER_READ_PIPE_DATA_SIZE)) > 0) {
                read_offset += read_length;
            }

            for (uint_t index = 0;index < trace_pc_map_count;++index) {
                printf("%d %d Coverage ID %X ,Count %d\n",index,trace_pc_map_count,
                        coverage_result[index].current_address,
                        coverage_result[index].current_function_edge_count);
            }

            break;
        } default: {
            printf("Error Status Code ==> PID:%d \n",subprocess_pid);
        }

    }
}

int main(int argc,char** argv) {
    if (2 != argc) {
        printf("Using: fuzzer %%detect_elf_path%% \n");

        return 1;
    }

    struct sigaction action;
    action.sa_sigaction = signal_handler;
    action.sa_flags = SA_SIGINFO;

    sigemptyset(&action.sa_mask);

    if(sigaction(SIGNAL_CREATE_FUZZER_TARGET,&action,NULL) < 0) {
        printf("sigaction error!\n");
        exit(-1);
    }

    if(sigaction(SIGNAL_FUZZ_ONCE,&action,NULL) < 0) {
        printf("sigaction error!\n");
        exit(-1);
    }

    printf("fuzzer pid = %d \n",getpid());

    int pid = fork();

    if (!pid) {
        execl(argv[1],NULL);
    } else {
        int status;
        current_fuzzer_pid = getpid();

        while(waitpid(pid, &status, 0) < 0);

        printf("Fuzzer Exit! \n");
    }

    return 0;
}


