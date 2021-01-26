
#include <error.h>
#include <fcntl.h>
#include <inttypes.h>
#include <malloc.h>
#include <memory.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/msg.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <map>
#include <vector>

#include "sanitize_converage.h"
#include "signal_number.h"

#define MAX_FUZZER_READ_PIPE_DATA_SIZE (10 * 1024)
#define MAX_FUZZER_SUBPROCESS 5

using namespace std;



class subprocess_fuzz_function {
    public:
        subprocess_fuzz_function() {

        }

        subprocess_fuzz_function(uint_t function_address,uint_t function_edge_count) {
            this->function_address = function_address;
            this->function_edge_count = function_edge_count;
        }

        bool is_exist_edge_id(uint_t edge_id) {
            for (auto iterator = this->function_execute_edge_list.begin();
                 iterator != this->function_execute_edge_list.end();
                 ++iterator) {
                if (*iterator == edge_id)
                    return true;
            }

            return false;
        }

        void add_execute_edge(uint_t edge_id) {
            if (this->is_exist_edge_id(edge_id))
                return;

            this->function_execute_edge_list.push_back(edge_id);
        }

        uint_t get_function_address(void) {
            return this->function_address;
        }

        uint_t get_function_edge_count(void) {
            return this->function_edge_count;
        }

        uint_t get_function_execute_edge_count(void) {
            return this->function_execute_edge_list.size();
        }

    private:
        uint_t function_address;
        uint_t function_edge_count;
        std::vector<uint_t> function_execute_edge_list;
};

class subprocess_fuzz_process {
    public:
        subprocess_fuzz_process() {
        }

        bool is_exist_function(uint_t function_address) {
            if (this->process_function_table.count(function_address))
                return true;

            return false;
        }

        void add_function(uint_t function_address,uint_t function_edge_count) {
            if (this->is_exist_function(function_address))
                return;

            subprocess_fuzz_function new_object(function_address,function_edge_count);

            this->process_function_table[function_address] = new_object;
        }

        void add_function_execute_edge(uint_t function_address,uint_t edge_id) {
            this->process_function_table[function_address].add_execute_edge(edge_id);
        }

        uint_t get_function_count() {
            return this->process_function_table.size();
        }

        uint_t get_edge_count() {
            uint_t edge_count = 0;

            for (auto iterator = this->process_function_table.begin();
                 iterator != this->process_function_table.end();
                 ++iterator)
                edge_count += iterator->second.get_function_edge_count();

            return edge_count;
        }

        uint_t get_execute_edge_count() {
            uint_t execute_edge_count = 0;

            for (auto iterator = this->process_function_table.begin();
                 iterator != this->process_function_table.end();
                 ++iterator)
                execute_edge_count += iterator->second.get_function_execute_edge_count();

            return execute_edge_count;
        }

        ufloat get_coverage_rate() {
            uint_t edge_count = this->get_edge_count();
            uint_t execute_edge_count = this->get_execute_edge_count();

            return ((ufloat)execute_edge_count / (ufloat)edge_count) * 100;
        }

    private:
        std::map<uint_t,subprocess_fuzz_function> process_function_table;
};

class subprocess_envirement {
    public:
        subprocess_envirement(
            uint_t pid,uint_t start_time) {
            this->start_time = start_time;
            this->pid = pid;
        }

        uint_t get_pid(void) {
            return this->pid;
        }

        uint_t get_start_time(void) {
            return this->start_time;
        }

    private:
        uint_t pid;
        uint_t start_time;
};

class subprocess_envirement_list {
    public:
        subprocess_envirement_list() {

        }

        bool is_exist(uint_t pid) {
            for (auto iterator = list_data.begin();
                 iterator != list_data.end();
                 ++iterator) {
                if (iterator->get_pid() == pid)
                    return true;
            }

            return false;
        }

        subprocess_envirement* get_by_pid(uint_t pid) {
            for (auto iterator = list_data.begin();
                 iterator != list_data.end();
                 ++iterator) {
                if (iterator->get_pid() == pid)
                    return (subprocess_envirement*)&iterator;
            }
            
            return NULL;
        }

        void add_record(uint_t pid,uint_t start_time) {
            subprocess_envirement new_object(pid,start_time);

            list_data.push_back(new_object);
        }

    private:
        std::vector<subprocess_envirement> list_data;
};

subprocess_envirement_list subprocess_envirement_table;
int current_all_sub_fuzzer = 0;
pid_t current_fuzzer_pid = 0;



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

            subprocess_envirement_table.add_record(subprocess_pid,time(NULL));

            current_all_sub_fuzzer++;

            break;
        } case SIGNAL_FUZZ_ONCE: {
            //  parameter  =>  fuzz_index
            int trace_count = parameter;

            printf("SubProcess Fuzz ==> PID:%d All Edge:%d \n",subprocess_pid,trace_count);

            subprocess_envirement* subprocess_data = subprocess_envirement_table.get_by_pid(subprocess_pid);

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

            subprocess_fuzz_process fuzz_static;

            for (uint_t index = 0;index < trace_pc_map_count;++index) {
                printf("%d Coverage ID %X (%X) ,Count %d\n",index,
                        coverage_result[index].current_edge_id,
                        coverage_result[index].current_function_entry,
                        coverage_result[index].current_function_edge_count);

                fuzz_static.add_function(coverage_result[index].current_function_entry,
                    coverage_result[index].current_function_edge_count);
                fuzz_static.add_function_execute_edge(coverage_result[index].current_function_entry,
                    coverage_result[index].current_edge_id);
            }

            printf("Fuzz Static :\n");
            printf("  Coverage Edge Count %d\n",fuzz_static.get_edge_count());
            printf("  Execute Edge Count %d\n",fuzz_static.get_execute_edge_count());
            printf("  Coverage Rate %.2f%%\n",fuzz_static.get_coverage_rate());

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
        _exit(-1);
    }

    if(sigaction(SIGNAL_FUZZ_ONCE,&action,NULL) < 0) {
        printf("sigaction error!\n");
        _exit(-1);
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

