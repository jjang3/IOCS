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
        self.assembly_code: assembly_code
    
    def inst_print(self):
        logger.debug(
            f"Instruction Details:\n"
            f"  - Opcode      : {self.opcode}\n"
            f"  - Prefix      : {self.prefix}\n"
            f"  - Source      : {self.src}\n"
            f"  - Destination : {self.dest}\n"
            f"  - Patching    : {self.patch}\n"
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
    def analyze_inst(self, inst):
        if isinstance(inst, LowLevelILInstruction):
            addr = inst.address
            dis_inst = self.bv.get_disassembly(addr)
            logger.debug(inst)
            logger.debug(f"{LIGHT_BLUE}{chr(int(arrow[2:], 16))} {dis_inst}{RESET}")
            print()
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

   