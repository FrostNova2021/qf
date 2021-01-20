

#include <memory.h>
#include <stdint.h>
#include <stdio.h>
#include <sanitizer/coverage_interface.h>


/// -fsanitize-coverage-whitelist=


static int __sancov_trace_pc_switch = 1;
static const size_t __sancov_trace_pc_map_max = 1 << 16;
static unsigned long __sancov_trace_pc_table[__sancov_trace_pc_map_max] = {0};
static unsigned long __sancov_trace_pc_index = 0;
static unsigned long __sancov_current_all_guard_count = 0;


void __sanitizer_cov_trace_pc_guard_init(uint32_t *start,uint32_t *stop) {
    static uint64_t N;

    if (start == stop || *start)
        return;

    __sancov_current_all_guard_count = (stop - start);

    printf("all cov edges: 0x%X \n",__sancov_current_all_guard_count);

    for (uint32_t *x = start; x < stop; x++)
        *x = ++N;
}

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

    printf("guard: %p %x PC %s\n", edge_address, edge_id, symbolize_data);

    __sancov_trace_pc_table[__sancov_trace_pc_index++] = PC;
}





