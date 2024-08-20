import logging
import sys
import fileinput
import inspect
import argparse
import shutil
import pprint 
import os
import re

from pathlib import Path, PosixPath

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

    def process_asm_file(self):
        # Regexes related to rewriting the asm file
        file_pattern = re.compile(r'\.file\s+"([^"]+)"')
        fun_begin_regex = r'(?<=.type\t)(.*)(?=,\s@function)'
        fun_end_regex   = r'(\t.cfi_endproc)'
        dis_line_regex = r'(?P<opcode>(mov|movz|lea|sub|add|cmp|sal|and|imul|movss))(?P<prefix>l|b|w|q|bl|xw|wl)?\s+(?P<operand1>\S+)(?:,\s*(?P<operand2>\S+))'
        
        debug = False # This debug flag is for inplace feature; False = Overwrite | True = Don't
        fun_check = False # This is going to be initialized as false for now
        with fileinput.input(self.asm_item, inplace=(not debug), encoding="utf-8", backup='.bak') as f:
            for line in f:
                # logger.debug(line)
                if file_pattern.findall(line):
                    # This finds the .file of the asm file and add the assembly macros at the top
                    print(asm_macros, end='')
                    print(line)

                fun_begin = re.search(fun_begin_regex, line)
                if fun_begin is not None:
                    # This finds the function declaration in the assembly file and enables the check
                    fun_check = True
                    fun_name = fun_begin.group(1)
                    if fun_name in self.analysis_list:
                        logger.debug(f"Patching function {fun_name} found")
                        # exit()
                fun_end = re.search(fun_end_regex, line)
                if fun_end is not None:
                    # This detects the function end and disables the check
                    fun_check = False
                
                # ------ Patching ------ #
                if fun_check == True:
                    logger.debug(line)
                    dis_regex   = re.search(dis_line_regex, line)
                    if dis_regex is not None:
                        opcode = dis_regex.group('opcode')
                        prefix = dis_regex.group('prefix')
                        operand1 = dis_regex.group('operand1')
                        operand2 = dis_regex.group('operand2')
                        logger.warning(f"{opcode} - {prefix} - {operand1} - {operand2}")
                else:
                    # logger.error("Skip for now")
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