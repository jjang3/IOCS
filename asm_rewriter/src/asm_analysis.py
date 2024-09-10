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
    def __init__(self, opcode, prefix, operand_1, operand_2):
        # This is based on AT&T syntax, where it is opcode, src, dest ->
        self.opcode = opcode
        self.prefix = prefix
        self.src = operand_1
        self.dest = operand_2
        self.patch = None
    
    def inst_print(self):
        logger.debug(
            f"Instruction Details:\n"
            f"  - Opcode      : {self.opcode}\n"
            f"  - Prefix      : {self.prefix}\n"
            f"  - Source      : {self.src}\n"
            f"  - Destination : {self.dest}\n"
            f"  - Patching    : {self.patch}\n"
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
    def analyze_bb(self, bb, type):
        for inst in bb: 
            if type is "llil":
                inst: LowLevelILInstruction
            addr = inst.address
            dis_inst = self.bv.get_disassembly(addr)
            logger.debug(inst)
            logger.debug(f"{LIGHT_BLUE}{chr(int(arrow[2:], 16))} {dis_inst}{RESET}")
            print()
            
    def analyze_fun(self):
        llil_fun_ssa = self.fun.low_level_il.ssa_form
        for llil_bb_ssa in llil_fun_ssa:
            self.analyze_bb(llil_bb_ssa, "llil")

    def bn_analysis(self, analysis_list):
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
                logger.info("Function: %s\t| begin: %s | end: %s", self.fun, self.begin, self.end)
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
    return bn.bn_analysis(analysis_list)

   