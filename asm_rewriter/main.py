import logging
import sys
import fileinput
import inspect
import argparse
import shutil
import pprint 
import os

from enum import Enum, auto
from pickle import FALSE
from tkinter import N
from termcolor import colored
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

from elftools.dwarf.die import DIE
from elftools.elf.elffile import DWARFInfo, ELFFile
from elftools.dwarf.dwarf_expr import DWARFExprParser, DWARFExprOp
from elftools.dwarf.descriptions import (
    describe_DWARF_expr, set_global_machine_arch)
from elftools.dwarf.locationlists import (
    LocationEntry, LocationExpr, LocationParser)
from elftools.dwarf.descriptions import describe_form_class
from elftools.dwarf.callframe import (
    CallFrameInfo, CIE, FDE, instruction_name, CallFrameInstruction,
    RegisterRule, DecodedCallFrameTable, CFARule)
from elftools.dwarf.structs import DWARFStructs
from elftools.dwarf.descriptions import (describe_CFI_instructions,
    set_global_machine_arch)
from elftools.dwarf.enums import DW_EH_encoding_flags

# Print current sys.path
# print("Before cleaning sys.path:")
# for path in sys.path:
#     print(path)

# Get the directory of the current Python file (asm_rewriter/main.py)
current_dir = os.path.dirname(os.path.abspath(__file__))

# Get the project root directory (one level up from asm_rewriter)
project_root = os.path.dirname(current_dir)

# Add the 'src' directory from the 'dwarf_analysis' module to sys.path
sys.path.append(os.path.join(project_root, 'dwarf_analysis', 'src'))

# Add the 'src' directory relative to the current directory (asm_rewriter/src)
sys.path.append(os.path.join(current_dir, 'src'))

# Print sys.path after cleaning
# print("\nAfter cleaning sys.path:")
# for path in sys.path:
#     print(path)
    
# Import from dwarf_analysis and its own src folder
from dwarf_analysis import *
from gen_table import *
from rewriter import *

"""
from bin_analysis import *
from rewriter import *
from verifier import *
"""

class CustomFormatter(logging.Formatter):

    # FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s | %(levelname)s"
    # logging.basicConfig(level=os.environ.get("LOGLEVEL", "DEBUG"), format=FORMAT)
    blue = "\x1b[33;34m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_green = "\x1b[42;1m"
    purp = "\x1b[38;5;13m"
    reset = "\x1b[0m"
    # format = "%(funcName)5s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"
    format = "[%(filename)17s: Line:%(lineno)4s - %(funcName)-18s] %(levelname)-8s: %(message)s"



    FORMATS = {
        logging.DEBUG: yellow + format + reset,
        logging.INFO: blue + format + reset,
        logging.WARNING: purp + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_green + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)
    
def setup_logger(name: str, level=logging.DEBUG, log_disable=False):
    """Set up a logger with a custom name."""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Avoid adding multiple handlers if the logger is already configured
    if not logger.hasHandlers():
        ch = logging.StreamHandler()
        ch.setLevel(level)
        ch.setFormatter(CustomFormatter())
        logger.addHandler(ch)

    logger.disabled = log_disable
    return logger

# Example of creating a logger with a specific name
log = setup_logger("custom_logger")

@dataclass(unsafe_hash = True)
class FileData:
    name: str = None
    asm_path: str = None
    obj_path: str = None
    fun_list: Optional[list] = None
    intel_path: str = None

def analyze_directory(target_dir, base_name):
    analysis_file = target_dir / f"{base_name}.analysis"
    # analysis_list = process_analysis_file(analysis_file)

def analyze_binary(args, base_name):
    result_dir = Path(args.binary).resolve().parent.parent / "result" / base_name
    analysis_file   = result_dir / f"{base_name}.analysis"
    # Debugging analysis file
    # analysis_file = "/home/jaewon/IBCS/result/tiny/tiny.analysis"
    with open(analysis_file) as ff:
        for line in ff:
            analysis_list = line.split(',')
    binary_file     = result_dir / f"{base_name}.out"
    asm_item        = result_dir / f"{base_name}.s"  # Updated variable name for clarity
    obj_item        = result_dir / f"{base_name}.o"  # Updated variable name for clarity
    log.debug(f"{binary_file}, {asm_item}, {obj_item}")
    # print(os.path.join(project_root, 'dwarf_analysis', 'src'))

    dwarf_fun_list = dwarf_analysis(binary_file)
    # for fun in dwarf_fun_list:
    #     fun: FunData
    #     fun.print_data()

    fun_table_offsets = generate_table(dwarf_fun_list, result_dir)
    for fun in fun_table_offsets:
        if len(fun_table_offsets[fun]) > 0:
            logger.info(f"Variables for the function: {fun}")
            for var in fun_table_offsets[fun]:
                var: VarData
                # pprint.pprint(var[0])
                print_var_data(var[0])
            print()
        else:
            logger.warning(f"No variables for {fun}")
            print()
    
    rewriter = AsmRewriter(analysis_list, result_dir, asm_item, fun_table_offsets, dwarf_fun_list)
    patch_count = rewriter.run()

def main():
    # Get the size of the terminal
    columns, rows = shutil.get_terminal_size(fallback=(80, 20))

    # Create a string that fills the terminal width with spaces
    # Subtract 1 to accommodate the newline character at the end of the string
    empty_space = ' ' * (columns - 1)

    # Create the parser
    parser = argparse.ArgumentParser(description='Process some inputs.')

    # Add arguments
    parser.add_argument('--binary', type=str, help='Path to a binary file')
    parser.add_argument('--directory', type=str, help='Specify a directory (optional)', default=None)

    # Parse arguments
    args = parser.parse_args()

    # Determine base_name if binary is provided
    base_name = None
    if args.binary is not None:
        base_name = Path(args.binary).stem  # Extracts the base name without extension

    # Perform the appropriate analysis based on the provided arguments
    if args.directory is not None:
        log.info("Analyzing the directory")
        # Handle directory-based processing
        target_dir = Path(args.directory).resolve()
        if base_name is None:
            log.error("Base name could not be determined since no binary was provided.")
            return
        analyze_directory(target_dir, base_name)
    elif args.binary is not None:
        log.info("Analyzing the binary")
        # Handle binary-based processing
        analyze_binary(args, base_name)
    else:
        log.error("Neither a binary file nor a directory was provided.")
        return

    # Printing the empty space with a newline
    print(colored(f"{empty_space}\n", 'grey', attrs=['underline']))

# Call main function
if __name__ == '__main__':
    main()