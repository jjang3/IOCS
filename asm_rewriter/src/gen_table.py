import sys, getopt
import logging

# Get the same logger instance. Use __name__ to get a logger with a hierarchical name or a specific string to get the exact same logger.
logger = logging.getLogger('main')

from pprint import pprint
from dwarf_analysis import *

fun_table_offsets       = dict()

def debug_selector(fun_idx, fun, debug_idx=None, debug_name=None):
    """Check if the current function should be debugged based on index or name."""
    if debug_idx is not None and fun_idx == debug_idx:
        return True
    if debug_name is not None and fun.name == debug_name:
        return True
    if debug_idx is None and debug_name is None:
        return True
    return False

# Set these to the specific index or name you want to debug
debug_idx = None    # Set to an integer to debug by index, e.g., 0
debug_name = None   # Set to a string to debug by function name, e.g., "parse_request"

def generate_table(dwarf_fun_list, target_dir):
    logger.info("Generating the table offset for variables")
    fun_table_offsets       = dict()
    redir_table_offset      = set()
    table_offset            = 0
    var_count               = 0
    for fun_idx, fun in enumerate(dwarf_fun_list):
        fun: FunData
        if debug_selector(fun_idx, fun, debug_idx=debug_idx, debug_name=debug_name):
            fun.print_data()
            for var_idx, var in enumerate(fun.var_list):
                var: VarData
                # pprint.pprint(var)
                if var.var_type == "DW_TAG_base_type":
                    if var.offset != None:
                        logger.debug(f"Adding the variable: {var.name}")
                        redir_table_offset.add((var, table_offset))
                        table_offset += 8
                        var_count += 1
                elif var.var_type == "DW_TAG_pointer_type" or var.var_type == "DW_TAG_array_type":
                    if var.offset != None:
                        logger.debug(f"Adding the variable: {var.name}")
                        redir_table_offset.add((var, table_offset))
                        table_offset += 8
                        var_count += 1
                else:
                    logger.error(f"Skipping: {var.var_type}")
        fun_table_offsets[fun.name] = redir_table_offset.copy()
        redir_table_offset.clear()
    
    logger.info(f"Generating the table with variable count: {var_count}")
    if var_count % 2 != 0 and var_count != 1:
        # This is to avoid malloc(): corrupted top size error, malloc needs to happen in mod 2
        var_count += 1
    include_lib_flags="""
#include <sys/auxv.h>
#include <elf.h>
#include <immintrin.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
/* Will be eventually in asm/hwcap.h */
#ifndef HWCAP2_FSGSBASE
#define HWCAP2_FSGSBASE        (1 << 1)
#endif
#define _GNU_SOURCE
#define PAGE_SIZE 4096
"""
    begin_table="""
void **table;
void __attribute__((constructor)) create_table()
{    
    table = malloc(sizeof(void*)*%d);\n
    if (!table) {
        perror("Failed to allocate memory for page table");
        exit(EXIT_FAILURE);
    }
    /* Pointer to shared memory region */    
""" % (var_count)
    loop_table="""
    // Map each page
    for (int i = 0; i < %d; ++i) {
        table[i] = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_32BIT | MAP_PRIVATE, -1, 0);
        if (table[i] == MAP_FAILED) {
            perror("Memory mapping failed");
            // Clean up previously mapped pages
            for (int j = 0; j < i; ++j) {
                munmap(table[j], PAGE_SIZE);
            }
            free(table);
            exit(EXIT_FAILURE);
        }
    }
""" % (var_count)
    end_table="""\t_writegsbase_u64((long long unsigned int)table);
}
void __attribute__((destructor)) cleanup_table() {
    // Unmap each page and free the table
    for (int i = 0; i < %d; ++i) {
        if (table[i]) {
            munmap(table[i], PAGE_SIZE);
        }
    }
    free(table);
}
""" % (var_count)
    table_file = open("%s/table.c" % target_dir, "w")
    table_file.write(include_lib_flags)
    table_file.write(begin_table)
    table_file.write(loop_table)
    table_file.write(end_table)
    table_file.close()
    logger.critical("Finished generating the table")
    return fun_table_offsets