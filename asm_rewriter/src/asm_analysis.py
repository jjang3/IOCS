import logging
import sys
import fileinput
import inspect
import argparse
import shutil
import pprint 
import os
import re

# Get the same logger instance. Use __name__ to get a logger with a hierarchical name or a specific string to get the exact same logger.
logger = logging.getLogger('custom_logger')

class PatchingInst:
    def __init__(self, opcode, prefix, operand_1, operand_2, assembly_code = None):
        # This is based on AT&T syntax, where it is opcode, src, dest ->
        self.opcode = opcode
        self.prefix = prefix
        self.src = operand_1
        self.dest = operand_2
        self.patch = None
        self.assembly_code = assembly_code
    
    def inst_print(self):
        logger.debug(
            f"Instruction Details:\n"
            f"  - Opcode      : {self.opcode}\n"
            f"  - Prefix      : {self.prefix}\n"
            f"  - Source      : {self.src}\n"
            f"  - Destination : {self.dest}\n"
            f"  - Assembly    : {self.assembly_code if self.assembly_code else 'N/A'}\n"
            # f"  - Pointer     : {getattr(self, 'ptr_op', 'N/A')}\n" # Need to be added later
        )

class BnNode:
    def __repr__(self):
        return self.__class__.__name__ 

class RegNode(BnNode):
    def __init__(self, value):
        self.value = value

class BnSSAOp(BnNode):
    def __init__(self, left, op, right):
        self.left = left
        self.op = op
        self.right = right

from binaryninja import *
from binaryninja.binaryview import BinaryViewType
from binaryninja.architecture import Architecture, ArchitectureHook

arrow = 'U+21B3'
 # ANSI escape codes for colors
LIGHT_BLUE = "\033[96m"
RESET = "\033[0m"

class BinAnalysis:
    suffix_map = {
        "qword": "q",  # Quadword -> q
        "dword": "l",  # Doubleword -> l
        "word": "w",   # Word -> w
        "byte": "b"    # Byte -> b
    }

    def determine_prefix_from_registers(self, reg1, reg2):
        if reg1 and reg2:
            if reg1.startswith("%r") and reg2.startswith("%r"):  # 64-bit registers
                return "q"
            elif reg1.startswith("%e") and reg2.startswith("%e"):  # 32-bit registers
                return "l"
            elif len(reg1) == 3 and len(reg2) == 3:  # For 16-bit registers (e.g., %ax, %di)
                return "w"
            elif len(reg1) == 2 and len(reg2) == 2:  # For 8-bit registers (e.g., %al, %bl)
                return "b"
        elif reg1:
            if reg1.startswith("%r"):  # 64-bit register
                return "q"
            elif reg1.startswith("%e"):  # 32-bit register
                return "l"
            elif len(reg1) == 3:  # 16-bit register
                return "w"
            elif len(reg1) == 2:  # 8-bit register
                return "b"
        elif reg2:
            if reg2.startswith("%r"):  # 64-bit register
                return "q"
            elif reg2.startswith("%e"):  # 32-bit register
                return "l"
            elif len(reg2) == 3:  # 16-bit register
                return "w"
            elif len(reg2) == 2:  # 8-bit register
                return "b"
        return ""

    def process_instruction(self, dis_inst):
        dis_line_regex = r"""
        (?P<opcode>\w+)\s+
        (?P<operand1>
            (?P<memsize1>(qword|dword|word|byte)\s+ptr\s*)?  # Memory size specifier (optional)
            (
                \[(?P<register1>%\w+)?(?P<offset1>[+\-*\/]?\s*0x[\da-fA-F]+)?\]  # Memory reference (e.g., [%rbp-0x8])
                |
                (?P<imm1>\$0x[\da-fA-F]+)               # Immediate value (e.g., $0x0)
                |
                (?P<reg1>%\w+)                 # Register (e.g., %rax)
            )
        )\s*,?\s*
        (?P<operand2>
            (?P<memsize2>(qword|dword|word|byte)\s+ptr\s*)?  # Memory size specifier for second operand (optional)
            (
                \[(?P<register2>%\w+)?(?P<offset2>[+\-*\/]?\s*0x[\da-fA-F]+)?\]  # Memory reference (e.g., [%rbp-0x8])
                |
                (?P<imm2>\$0x[\da-fA-F]+)               # Immediate value (e.g., $0x0)
                |
                (?P<reg2>%\w+)                 # Register (e.g., %rax)
            )
        )?
        """

        dis_pattern = re.compile(dis_line_regex, re.VERBOSE)
        match = dis_pattern.match(dis_inst.strip())

        if match:
            opcode = match.group('opcode')

            # Operand 1
            memsize1 = match.group('memsize1')
            reg1 = match.group('reg1')
            register1 = match.group('register1') if match.group('register1') else reg1
            offset1 = match.group('offset1')
            imm1 = match.group('imm1')

            # Operand 2 - Initialize operand2 early
            operand2 = None
            memsize2 = match.group('memsize2')
            reg2 = match.group('reg2')
            register2 = match.group('register2') if match.group('register2') else reg2
            offset2 = match.group('offset2')
            imm2 = match.group('imm2')

            # Handle immediate values (properly set them to actual values)
            if imm1:
                operand1 = int(imm1.replace('$0x', '0x'), 16)  # Convert immediate value to int
            else:
                if offset1 and not register1:
                    # Only offset, convert to plain int (no register, no brackets)
                    operand1 = str(int(offset1, 16))  # Convert offset from hex to integer
                elif register1 and offset1:
                    # Both register and offset exist
                    operand1 = f"{int(offset1, 16)}({register1})"
                else:
                    operand1 = register1 if register1 else None

            if imm2:
                operand2 = int(imm2.replace('$0x', '0x'), 16)  # Convert immediate value to int
            else:
                if offset2 and not register2:
                    # Only offset, convert to plain int (no register, no brackets)
                    operand2 = str(int(offset2, 16))
                elif register2 and offset2:
                    # Both register and offset exist
                    operand2 = f"{int(offset2, 16)}({register2})"
                else:
                    operand2 = register2 if register2 else None

            # Determine the appropriate prefix based on memory size or register type
            prefix = ""
            if memsize1:
                memsize1 = memsize1.strip()  # Remove extra spaces
                prefix = self.suffix_map.get(memsize1.split()[0], "")  # Get the prefix without "ptr"
            elif memsize2:
                memsize2 = memsize2.strip()  # Remove extra spaces
                prefix = self.suffix_map.get(memsize2.split()[0], "")  # Get the prefix without "ptr"
            else:
                # Determine prefix based on registers and immediate values
                if imm1 and register2:  # If operand1 is an immediate and operand2 is a register
                    prefix = self.determine_prefix_from_registers(None, register2)
                elif imm2 and register1:  # If operand2 is an immediate and operand1 is a register
                    prefix = self.determine_prefix_from_registers(register1, None)
                else:
                    prefix = self.determine_prefix_from_registers(register1, register2)

            # Ensure prefix is applied correctly for immediate and register cases
            if imm1 and register2:  # Immediate + Register case
                prefix = self.determine_prefix_from_registers(None, register2)
            elif imm2 and register1:  # Register + Immediate case
                prefix = self.determine_prefix_from_registers(register1, None)

            # Construct the patching instruction using PatchingInst class
            patching_inst = PatchingInst(
                opcode=opcode,
                prefix=prefix,
                operand_1=operand1,
                operand_2=operand2,
                assembly_code=dis_inst  # The full instruction text
            )

            # Use the PatchingInst's inst_print method to display the patching details
            patching_inst.inst_print()

            # Log the results with the debug logger
            logger.debug(f"{LIGHT_BLUE}Opcode: {opcode} with prefix: {prefix}{RESET}")
            logger.debug(f"{LIGHT_BLUE}Operand 1: {operand1} (Memory size: {memsize1}, Register: {register1}, Offset: {offset1}, Immediate: {imm1}){RESET}")
            logger.debug(f"{LIGHT_BLUE}Operand 2: {operand2} (Memory size: {memsize2}, Register: {register2}, Offset: {offset2}, Immediate: {imm2}){RESET}")

    def analyze_inst(self, inst):
        if isinstance(inst, LowLevelILInstruction):
            addr = inst.address
            dis_inst = self.bv.get_disassembly(addr)
            pro_inst = self.process_instruction(dis_inst)
            
        elif isinstance(inst, MediumLevelILInstruction):
            logger.debug(inst)
        else:
            logger.warning(f"Skipping instruction of unexpected type: {inst}")

    def analyze_bb(self, bb):
        for inst in bb:
            # Ensure the correct type before proceeding
            self.analyze_inst(inst)

    def analyze_fun(self):
        llil_fun = self.fun.low_level_il
        for llil_bb in llil_fun:
            self.analyze_bb(llil_bb)

    def asm_lex_analysis(self, analysis_list):
        print("")
        columns, rows = shutil.get_terminal_size(fallback=(80, 20))
        logger.info("Binary analysis (Binary Ninja)")
        for func in self.bv.functions:
            func: Function 
            if func.name in analysis_list:
                self.fun = func
                addr_range = func.address_ranges[0]
                self.begin   = addr_range.start
                self.end     = addr_range.end
                # Format the log message to span across the width of the terminal
                log_message = f"Function: {self.fun}\t| begin: {self.begin} | end: {self.end}"
                if len(log_message) > columns:
                    log_message = log_message[:columns-3] + "..."
                logger.info(log_message)
                self.analyze_fun()
      
    def __init__(self, bv):
        self.bv = bv
        self.fun: Optional[Function] = None
        self.fun_begin = None
        self.fun_end = None
    
def process_binary(input_binary, analysis_list):
    input_binary_path = str(input_binary)
    
    # Define the cache file (Binary Ninja Database file)
    bndb_file = input_binary_path + ".bndb"
    
    # Load the cache file if it exists
    if os.path.exists(bndb_file):
        logger.warning(f"Loading cached analysis from {bndb_file}")
        bv = BinaryViewType.get_view_of_file(bndb_file)
    else:
        # Load and analyze the binary with options that prioritize speed
        bv = BinaryViewType.get_view_of_file_with_options(input_binary_path, options={
            "arch.x86.disassembly.syntax": "AT&T"
        })
        logger.info(f"Loaded binary and starting analysis for {input_binary_path}")
        # Perform background analysis and wait for it to finish
        bv.update_analysis_and_wait()
        logger.warning(f"Saving analysis to {bndb_file}")
        bv.create_database(bndb_file)

    # Create a BinAnalysis object and run the analysis
    bn = BinAnalysis(bv)
    return bn.asm_lex_analysis(analysis_list)

   