import logging
import sys
import fileinput
import inspect
import argparse
import shutil
import pprint 
import os
import re
import signal

from pathlib import Path, PosixPath

from asm_analysis import * # Imports PatchingInst
from dwarf_analysis import *

# Get the same logger instance. Use __name__ to get a logger with a hierarchical name or a specific string to get the exact same logger.
logger = logging.getLogger('custom_logger')

asm_macros = """# var_c14n macros
# Load effective address macro
.macro lea_gs dest, offset
\trdgsbase %r11
\tmov   \offset(%r11), %r11
\tlea   (%r11), \dest
.endm

.macro lea_store_gs src, offset
\tleaq  \src, %r11
\tmovq  (%r11), %r10
\trdgsbase %r11
\tmovq  \offset(%r11), %r11
\tmovq  %r10, (%r11)
.endm

# Data movement macros
.macro mov_store_gs src, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tmovb \src, (%r11)  # 8-bit 
\t.elseif \\value == 16
\t\tmovw \src, (%r11)  # 16-bit
\t.elseif \\value == 32
\t\tmovl \src, (%r11)  # 32-bit
\t.elseif \\value == 64
\t\tmovq \src, (%r11)  # 64-bit
\t.endif
.endm

.macro mov_load_gs dest, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tmovb (%r11), \dest  # 8-bit 
\t.elseif \\value == 16
\t\tmovw (%r11), \dest  # 16-bit
\t.elseif \\value == 32
\t\tmovl (%r11), \dest  # 32-bit
\t.elseif \\value == 64
\t\tmovq (%r11), \dest  # 64-bit
\t.endif
.endm

.macro mov_arr_store_gs src, offset, disp, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\tadd \disp, %r11
\t.if \\value == 8
\t\tmovb \src, (%r11)  # 8-bit 
\t.elseif \\value == 16
\t\tmovw \src, (%r11)  # 16-bit 
\t.elseif \\value == 32
\t\tmovl \src, (%r11)  # 32-bit 
\t.elseif \\value == 64
\t\tmovq \src, (%r11)  # 64-bit 
\t.endif
.endm

.macro mov_arr_load_gs src, offset, disp, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\tadd \disp, %r11
\t.if \\value == 8
\t\tmovb (%r11), \dest  # 8-bit
\t.elseif \\value == 16
\t\tmovw (%r11), \dest  # 16-bit
\t.elseif \\value == 32
\t\tmovl (%r11), \dest  # 32-bit
\t.elseif \\value == 64
\t\tmovq (%r11), \dest  # 64-bit
\t.endif
.endm

.macro movss_store_gs src, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t\tmovss \src, (%r11)  # 64-bit
.endm

.macro movss_load_gs dest, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\tmovss (%r11), \dest  # 64-bit
.endm

.macro movzx_load_gs dest, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tmovzbl (%r11), \dest  # 8-bit 
\t.elseif \\value == 16
\t\tmovzx (%r11), \dest  # 16-bit 
\t.elseif \\value == 32
\t\tmovzwl (%r11), \dest  # 32-bit
\t.endif
.endm

# Comparison / Shift macros
# ---- Comparison ---- #
.macro cmp_store_gs operand, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tcmpb \operand, (%r11)  # 8-bit 
\t.elseif \\value == 16
\t\tcmpw \operand, (%r11)  # 16-bit
\t.elseif \\value == 32
\t\tcmpl \operand, (%r11)  # 32-bit
\t.elseif \\value == 64
\t\tcmpq \operand, (%r11)  # 64-bit
\t.endif
.endm

.macro cmp_load_gs operand, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tcmpb (%r11), \operand  # 8-bit 
\t.elseif \\value == 16
\t\tcmpw (%r11), \operand  # 16-bit
\t.elseif \\value == 32
\t\tcmpl (%r11), \operand  # 32-bit
\t.elseif \\value == 64
\t\tcmpq (%r11), \operand  # 64-bit
\t.endif
.endm

.macro and_store_gs operand, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tandb \operand, (%r11)  # 8-bit 
\t.elseif \\value == 16
\t\tandw \operand, (%r11)  # 16-bit
\t.elseif \\value == 32
\t\tandl \operand, (%r11)  # 32-bit
\t.elseif \\value == 64
\t\tandq \operand, (%r11)  # 64-bit
\t.endif
.endm

.macro and_load_gs operand, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tandb (%r11), \operand  # 8-bit 
\t.elseif \\value == 16
\t\tandw (%r11), \operand  # 16-bit
\t.elseif \\value == 32
\t\tandl (%r11), \operand  # 32-bit
\t.elseif \\value == 64
\t\tandq (%r11), \operand  # 64-bit
\t.endif
.endm

# Arithmetic macros
# ---- Addition ---- #
.macro add_store_gs operand, offset, value
\trdgsbase %r10
\tmov	\offset(%r10), %r10 
\trdgsbase %r11
\tmov	\offset(%r11), %r11
\tmov (%r11), %r11
\t.if \\value == 8
\tadd \\operand, %r11b  # 8-bit 
\tmov %r11b, (%r10)
\t.elseif \\value == 16
\tadd \\operand, %r11w  # 16-bit 
\tmov %r11w, (%r10)
\t.elseif \\value == 32
\tadd \\operand, %r11d  # 32-bit 
\tmov %r11d, (%r10)
\t.elseif \\value == 64
\tadd \\operand, %r11   # 64-bit 
\tmov %r11, (%r10)
\t.endif
.endm

.macro add_load_gs dest, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\tmov (%r11), %r11b
\tadd %r11b, \dest  # 8-bit 
\t.elseif \\value == 16
\tmov (%r11), %r11w
\tadd %r11w, \dest  # 16-bit 
\t.elseif \\value == 32
\tmov (%r11), %r11d
\tadd %r11d, \dest  # 32-bit 
\t.elseif \\value == 64
\tmov (%r11), %r11
\tadd %r11, \dest   # 64-bit 
\t.endif
.endm

# ---- Subtraction ---- #
.macro sub_store_gs operand, offset, value
\trdgsbase %r10
\tmov	\offset(%r10), %r10 
\trdgsbase %r11
\tmov	\offset(%r11), %r11
\tmov (%r11), %r11
\t.if \\value == 8
\tsub \\operand, %r11b  # 8-bit 
\tmov %r11b, (%r10)
\t.elseif \\value == 16
\tsub \\operand, %r11w  # 16-bit 
\tmov %r11w, (%r10)
\t.elseif \\value == 32
\tsub \\operand, %r11d  # 32-bit 
\tmov %r11d, (%r10)
\t.elseif \\value == 64
\tsub \\operand, %r11   # 64-bit 
\tmov %r11, (%r10)
\t.endif
.endm

.macro sub_load_gs dest, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\tmov (%r11), %r11b
\tsub %r11b, \dest  # 8-bit 
\t.elseif \\value == 16
\tmov (%r11), %r11w
\tsub %r11w, \dest  # 16-bit 
\t.elseif \\value == 32
\tmov (%r11), %r11d
\tsub %r11d, \dest  # 32-bit 
\t.elseif \\value == 64
\tmov (%r11), %r11
\tsub %r11, \dest   # 64-bit 
\t.endif
.endm

# ---- Multiplication ---- #
.macro imul_store_gs operand, offset, value
\trdgsbase %r10
\tmov	\offset(%r10), %r10 
\trdgsbase %r11
\tmov	\offset(%r11), %r11
\tmov (%r11), %r11
\t.if \\value == 8
\timul \\operand, %r9b  # 8-bit 
\tmov %r9b, (%r10)
\t.elseif \\value == 16
\timul \\operand, %r9w  # 16-bit 
\tmov %r9w, (%r10)
\t.elseif \\value == 32
\timul \\operand, %r9d  # 32-bit 
\tmov %r9d, (%r10)
\t.elseif \\value == 64
\timul \\operand, %r9   # 64-bit 
\tmov %r9, (%r10)
\t.endif
.endm

.macro imul_load_gs dest, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\tmov (%r11), %r12b
\timul %r12b, \dest  # 8-bit 
\t.elseif \\value == 16
\tmov (%r11), %r12w
\timul %r12w, \dest  # 16-bit 
\t.elseif \\value == 32
\tmov (%r11), %r12d
\timul %r12d, \dest  # 32-bit 
\t.elseif \\value == 64
\tmov (%r11), %r10
\timul %r10, \dest   # 64-bit 
\t.endif
.endm

.macro shl_store_gs operand, offset, value
\trdgsbase %r10
\tmov	\offset(%r10), %r10 
\trdgsbase %r11
\tmov	\offset(%r11), %r11
\tmov (%r11), %r11
\t.if \\value == 8
\tshl \\operand, %r11b  # 8-bit 
\tmov %r11b, (%r10)
\t.elseif \\value == 16
\tshl \\operand, %r11w  # 16-bit 
\tmov %r11w, (%r10)
\t.elseif \\value == 32
\tshl \\operand, %r11d  # 32-bit 
\tmov %r11d, (%r10)
\t.elseif \\value == 64
\tshl \\operand, %r11   # 64-bit 
\tmov %r11, (%r10)
\t.endif
.endm
"""

class AsmRewriter:
    def __init__(self, analysis_list, result_dir, asm_item, fun_table_offsets, dwarf_info):
        self.analysis_list = analysis_list
        self.result_dir = result_dir
        self.asm_item = asm_item
        self.fun_table_offsets = fun_table_offsets  
        self.dwarf_info = dwarf_info
        self.patch_count = 0

    def patch_inst(self, dis_inst, temp_inst: PatchingInst, redir_offset):
        patched_line = None
        patch_target = None
        if temp_inst.patch == "src":
            patch_target = temp_inst.src
        else:
            patch_target = temp_inst.dest
        logger.critical(f"Patching the instruction {dis_inst} | Operand: {patch_target}")
        # To-do: Need to add Asm Syntax Tree feature later.
        if patched_line == None:
            value = 0
            if temp_inst.prefix == "b":
                value = 8
            elif temp_inst.prefix == "w":
                value = 16
            elif temp_inst.prefix == "l":
                value = 32
            elif temp_inst.prefix == "q":
                value = 64
            elif temp_inst.prefix == "bl":  # For movzbl
                value = 8
            elif temp_inst.prefix == "x":   # For movzx
                value = 16
            elif temp_inst.prefix == "wl":  # For movzwl
                value = 32

            # re.sub(pattern, replacement, string, count=0, flags=0)
            if temp_inst.opcode == "mov":
                logger.info("Patching with mov_gs")
                if temp_inst.patch == "src":
                    new_opcode = "mov_load_gs"
                    patched_line = re.sub(
                        r"^\s*(\S+)\s+(\S+),\s*(\S+)", 
                        r"\t%s\t%s, %d, %d\t # %s" % (new_opcode, temp_inst.dest, redir_offset, value, dis_inst.strip()), 
                        dis_inst
                    )
                    logger.warning(patched_line)
                elif temp_inst.patch == "dest":
                    new_opcode = "mov_store_gs"
                    patched_line = re.sub(
                        r"^\s*(\S+)\s+(\S+),\s*(\S+)", 
                        r"\t%s\t%s, %d, %d\t # %s" % (new_opcode, temp_inst.src, redir_offset, value, dis_inst.strip()), 
                        dis_inst
                    )
                    logger.warning(patched_line)

            if temp_inst.opcode == "movz":
                logger.info("Patching with movzx_gs")
                if temp_inst.patch == "src":
                    new_opcode = "movzx_load_gs"
                    patched_line = re.sub(
                        r"^\s*(\S+)\s+(\S+),\s*(\S+)", 
                        r"\t%s\t%s, %d, %d\t # %s" % (new_opcode, temp_inst.dest, redir_offset, value, dis_inst.strip()), 
                        dis_inst
                    )
                    logger.warning(patched_line)

            if temp_inst.opcode == "lea":
                logger.info("Patching with lea_gs")
                new_opcode = "lea_gs"
                patched_line = re.sub(
                    r"^\s*(\S+)\s+(\S+),\s*(\S+)", 
                    r"\t%s\t%s, %d\t # %s" % (new_opcode, temp_inst.dest, redir_offset, dis_inst.strip()), 
                    dis_inst
                )
                logger.warning(patched_line)

            if temp_inst.opcode == "cmp":
                logger.info("Patching with cmp_gs")
                if temp_inst.patch == "src":
                    new_opcode = "cmp_load_gs"
                    patched_line = re.sub(
                        r"^\s*(\S+)\s+(\S+),\s*(\S+)", 
                        r"\t%s\t%s, %d, %d\t # %s" % (new_opcode, temp_inst.dest, redir_offset, value, dis_inst.strip()), 
                        dis_inst
                    )
                    logger.warning(patched_line)
                    
                elif temp_inst.patch == "dest":
                    new_opcode = "cmp_store_gs"
                    patched_line = re.sub(
                        r"^\s*(\S+)\s+(\S+),\s*(\S+)", 
                        r"\t%s\t%s, %d, %d\t # %s" % (new_opcode, temp_inst.src, redir_offset, value, dis_inst.strip()), 
                        dis_inst
                    )
                    logger.warning(patched_line)

        if patched_line != None:
            # patch_inst_list.append(patch_inst_line)
            return patched_line

    def process_asm_file(self):
        # Regexes related to rewriting the asm file
        file_pattern = re.compile(r'\.file\s+"([^"]+)"')
        fun_begin_regex = r'(?<=.type\t)(.*)(?=,\s@function)'
        fun_end_regex   = r'(\t.cfi_endproc)'
        dis_line_regex = r'(?P<opcode>(mov|movz|lea|sub|add|cmp|sal|and|imul|movss))(?P<prefix>l|b|w|q|bl|xw|wl)?\s+(?P<operand1>\S+)(?:,\s*(?P<operand2>\S+))'
        # Regex to capture offset in operands like -24(%rbp)
        reg_offset_regex = r'(?P<offset>-?\d+)\(%[a-zA-Z]+\)'
        
        debug = False # This debug flag is for inplace feature; False = Overwrite | True = Don't
        fun_check = False # This is going to be initialized as false for now
        fun_name = None
        patching_candidates = set() # This set will consist of a tuple of (variable offset, redirection offset)
        
        # ANSI escape codes for colors
        LIGHT_BLUE = "\033[96m"
        RESET = "\033[0m"
        with fileinput.input(self.asm_item, inplace=(not debug), encoding="utf-8", backup='.bak') as f:
            for line in f:
                # logger.debug(line)
                if file_pattern.findall(line):
                    # This finds the .file of the asm file and add the assembly macros at the top
                    print(asm_macros, end='')
                    print(line)

                fun_begin = re.search(fun_begin_regex, line)
                if fun_begin is not None:
                    # This finds the function declaration in the assembly file and enables the check along with getting the targets
                    fun_check = True
                    fun_name = fun_begin.group(1)
                    if fun_name in self.analysis_list:
                        logger.debug(f"Patching function {fun_name} found")
                    
                        # self.fun_table_offsets contain the redirection table offset per this particular function
                        if len(self.fun_table_offsets[fun_name]) > 0:
                            logger.info(f"Checking the function: {fun_name}")
                            for var in self.fun_table_offsets[fun_name]:
                                var: VarData
                                # Specify the variable type in order to choose the patching candidates. This can be flexible; 
                                # the current method is to choose specific type (e.g., DW_TAG_base_type), but if necessary, can be
                                # extended to support specific offsets per function if the result from a taint analysis must be used 
                                # (e.g., offset: -16 from the function main).
                                if var[0].var_type == "DW_TAG_base_type":
                                    logger.debug(f"{LIGHT_BLUE}Adding candidate {var[0].name}{RESET}")
                                    patching_candidates.add((var[0].offset, var[1]))
                                    # print_var_data(var[0]) # Debug function
                                    # print()
                                elif var[0].var_type == "DW_TAG_array_type":
                                    logger.debug(f"{LIGHT_BLUE}Adding candidate {var[0].name}{RESET}")
                                    patching_candidates.add((var[0].offset, var[1]))
                                    # exit()
                                    # print_var_data(var[0]) # Debug function
                                elif var[0].var_type == "DW_TAG_pointer_type":
                                    # If a heap variable needs to be compartmentalized, then there needs to be a handler here.
                                    None
                        if (len(patching_candidates) > 0):
                            logger.info("Candidates:")
                            for candidate in patching_candidates:
                                logger.debug(candidate)

                fun_end = re.search(fun_end_regex, line)
                if fun_end is not None:
                    # This detects the function end and disables the check along with cleanup for sets
                    fun_check = False
                    fun_name = None
                    logger.error("Patching candidates cleared")
                    patching_candidates.clear()
                
                # ------ Patching ------ #
                if fun_check == True and fun_name != None:
                    logger.debug(line)
                    temp_inst: PatchingInst = None
                    new_inst = None
                    dis_regex   = re.search(dis_line_regex, line)
                    if dis_regex is not None:
                        opcode = dis_regex.group('opcode')
                        prefix = dis_regex.group('prefix')
                        operand_1 = dis_regex.group('operand1')
                        operand_2 = dis_regex.group('operand2')
                        # logger.warning(f"{opcode} - {prefix} - {operand_1} - {operand_2}")
                        temp_inst = PatchingInst(opcode, prefix, operand_1, operand_2)
                        # Check for offsets in operands
                        for operand, position in [(operand_1, "src"), (operand_2, "dest")]:
                            if operand:
                                offset_match = re.search(reg_offset_regex, operand)
                                if offset_match:
                                    offset_value = int(offset_match.group('offset'))
                                    logger.warning(f"Searching the offset: {offset_value}")
                                    # Format patching_candidates using pprint.pformat and pass it to logger
                                    if len(patching_candidates) > 0:
                                        logger.debug(f"{LIGHT_BLUE}Patching candidates for the function {fun_name}:\n{pprint.pformat(patching_candidates)}{RESET}")
                                    temp_inst.patch = position
                                    for candidate in patching_candidates:
                                        # logger.debug(f"{offset_value} | {candidate[0]}")
                                        if offset_value == candidate[0]:
                                            logger.warning("Patching target found")
                                            redir_offset = candidate[1]  # Set redir_offset from candidate[1]
                                            new_inst = self.patch_inst(line, temp_inst, redir_offset)
                                            if new_inst != None:
                                                logger.critical(new_inst)
                                                print(new_inst, end='')
                                                break
                                                exit()
                                            else:
                                                # Exit out of entire script if we find a missing instruction
                                                logger.error("Error, cannot patch the instruction")
                                                temp_inst.inst_print()
                                                os.kill(os.getppid(),signal.SIGTERM)
                                                sys.exit(2)
                        if new_inst == None:
                            print(line, end='')
                        temp_inst.inst_print()
                    else: # End else for dis_regex (i.e., non-patching candidates in the functio)
                        print(line, end='')
                else:
                    # logger.error("Skip for now")
                    print(line, end='')
                    None

    def run(self):
        fun_table_offsets: dict
        patch_count = 0
        logger.info("Rewriting the assembly file")
        target_path = None
        if self.result_dir != None:
            self.asm_item: PosixPath
            # print(type(target_file)s)
            debug_file = str(self.asm_item) + ".bak"
            logger.debug(f"{self.asm_item}, {debug_file}")
            debug_path = os.path.join(self.result_dir, debug_file)
            target_path = os.path.join(self.result_dir, self.asm_item)
            if os.path.isfile(debug_path):
                os.remove(self.asm_item)
                shutil.copyfile(debug_path, target_path)
                if os.path.isfile(target_path):
                    logger.warning(f"Debug file copied successfully to: {target_path}")
            else:
                logger.warning("No debug file exists")
        
            if target_path != None:
                self.process_asm_file()

        return self.patch_count