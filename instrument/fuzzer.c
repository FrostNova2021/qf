
#include <error.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

//#include <linux/shm.h>
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
static int current_all_sub_fuzzer = 0;


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

            /*
            unsigned long* coverage_result = (unsigned long*)malloc(buffer_size);
            unsigned long read_offset = 0;
            int read_length = 0;

            memset(coverage_result,0,buffer_size);

            while ((read_length = read(subprocess_data->pipe_read,
                                        &coverage_result[read_offset],
                                        MAX_FUZZER_READ_PIPE_DATA_SIZE)) > 0) {
                read_offset += read_length;
            }

            printf("%d  length=%d\n",subprocess_data->pipe_read,read_length);

            */
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

        while(waitpid(pid, &status, 0) < 0);

        printf("Fuzzer Exit! \n");
    }

    return 0;
}


