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
from asm_analysis import *

class CustomFormatter(logging.Formatter):

    # FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s | %(levelname)s"
    # logging.basicConfig(level=os.environ.get("LOGLEVEL", "DEBUG"), format=FORMAT)
    blue = "\x1b[33;34m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_green = "\x1b[42;1m"
    light_green = "\x1b[32;1m"  # Changed from bold green to a lighter green
    purp = "\x1b[38;5;13m"
    reset = "\x1b[0m"
    # format = "%(funcName)5s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"
    format = "[%(filename)17s: Line:%(lineno)4s - %(funcName)-18s] %(levelname)-8s: %(message)s"



    FORMATS = {
        logging.DEBUG: yellow + format + reset,
        logging.INFO: blue + format + reset,
        logging.WARNING: purp + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: light_green + format + reset
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
    name: str = None  # Base name of the file without extension
    asm_path: str = None  # Path to the assembly file (.s)
    obj_path: str = None  # Path to the object file (.o)
    fun_list: Optional[list] = None  # Optional list of functions (can be populated later)
    dwarf_info: Optional[list] = None

# Initialize an empty list to store FileData objects for files encountered.
file_list = list()
# This list contains all functions analyzed per asm file
fun_list = list() 
# This list will contain all target files based on searching through all directories
target_list = list()

def visit_dir(dir_list):
    for root, dirs, files in os.walk(dir_list):  # Walk through the directory structure
        for file_name in files:
            temp_file = None  # Temporary variable to hold a matching FileData object
            tgt_index = None  # Index to locate an existing FileData object if it already exists

            base_name = os.path.splitext(os.path.basename(file_name))[0]  # Extract the file base name (without extension)
            
            # Check if there's already a FileData object for the file
            for index, file_item in enumerate(file_list):
                if isinstance(file_item, FileData) and file_item.name == base_name:
                    tgt_index = index  # Save the index if a match is found

            # If a matching FileData object was found, retrieve it, otherwise create a new one
            if tgt_index is not None:
                temp_file = file_list[tgt_index]
            else:
                temp_file = FileData(base_name)  # Create a new FileData object with the base name
                file_list.append(temp_file)  # Append the new FileData to the list immediately

            # Check file extensions to update the appropriate path in the FileData object
            if file_name.endswith(".s"):  # If it's an assembly file
                file_path = os.path.join(root, file_name)  # Get the full path
                temp_file.asm_path = file_path  # Store the assembly file path
                # logger.debug(f"Updated asm_path for {temp_file}")
            elif file_name.endswith(".o"):  # If it's an object file
                file_path = os.path.join(root, file_name)  # Get the full path
                temp_file.obj_path = file_path  # Store the object file path
                # logger.debug(f"Updated obj_path for {temp_file}")


def find_funs(file_list):
    fun_regex = re.compile(r'\t\.type\s+.*,\s*@function\n\b(^.[a-zA-Z_.\d]+)\s*:', re.MULTILINE)
    for file_item in file_list:
        if file_item.asm_path != None:
            with open(file_item.asm_path, 'r') as asm_file:
                asm_string = asm_file.read()
                fun_names = fun_regex.findall(asm_string)
            for name in fun_names:
                fun_list.append(name)
            if file_item.fun_list == None:
                file_item.fun_list = fun_list.copy()
            fun_list.clear()

def analyze_directory(target_dir, base_name):
    result_dir = target_dir
    logger.debug(result_dir)

    # Check subdirectories
    visit_dir(target_dir)

    # Find function(s) from all the files
    find_funs(file_list)

    # Debugging analysis file
    analysis_list = list()
    analysis_file = result_dir / f"{base_name}.analysis"
    with open(analysis_file) as ff:
        for line in ff:
            analysis_list = line.split(',')
    for file_item in file_list:
        if file_item.fun_list != None:
            file_fun_list = file_item.fun_list
            found = [element for element in analysis_list if element in file_fun_list]
            if found:
                target_list.append(file_item)
    
    dwarf_fun_list = list()
    # Generate DWARF information for each file
    
    for file_item in target_list:
        file_item: FileData
        log.info("Analyzing %s", file_item) 
        # if file_item.name == "chall_fork": # Use this to debug a particular file
        if file_item.obj_path == None:
            logger.error("No obj file exists (maybe from reassembly error, please generate a new obj file)")
            os.kill(os.getppid(),signal.SIGTERM)
            sys.exit(2)
        file_item.dwarf_info = dwarf_analysis(file_item.obj_path)
        for fun in file_item.dwarf_info:
            dwarf_fun_list.append(fun)
            fun: FunData
            # logger.info(fun.name)
            # for var in fun.var_list:
            #     print_var_data(var)

    fun_table_offsets = generate_table(dwarf_fun_list, result_dir)
    logger.info("Redirection table offsets:")
    pprint.pprint(fun_table_offsets)
    
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

    patch_count = 0
    for file_item in target_list:
        file_item: FileData
        log.info("Rewriting %s", file_item)
            
        rewriter = AsmRewriter(analysis_list, result_dir, file_item.asm_path, fun_table_offsets, dwarf_fun_list)
        patch_count += rewriter.run()
    
def clean_redundant_result_path(path):
    # Convert the path to a string, replace 'result/result' with 'result', and return it as a Path object
    return Path(str(path).replace('/result/result', '/result'))

def analyze_binary(args, base_name):
    logger.debug("Analyzing a binary")
    result_dir = Path(args.binary).resolve().parent.parent / "result" / base_name
    result_dir = clean_redundant_result_path(result_dir)
    logger.debug(f"Cleaned result directory: {result_dir}")
    
    analysis_file   = result_dir / f"{base_name}.analysis"
    # Debugging analysis file
    analysis_list = list()
    # analysis_file = "/home/jaewon/IBCS/result/tiny/tiny.analysis"
    
    # Read the analysis file and handle newlines
    with open(analysis_file, 'r') as ff:
        for line in ff:
            # Strip whitespace and split by commas
            cleaned_line = line.strip()
            if cleaned_line:
                analysis_list.extend(cleaned_line.split(','))

    binary_file     = result_dir / f"{base_name}.out"
    asm_item        = result_dir / f"{base_name}.s"  # Updated variable name for clarity
    obj_item        = result_dir / f"{base_name}.o"  # Updated variable name for clarity
    log.debug(f"{binary_file}, {asm_item}, {obj_item}")
    # print(os.path.join(project_root, 'dwarf_analysis', 'src'))

    dwarf_fun_list = dwarf_analysis(binary_file)
    # exit()
    print()
    for fun in dwarf_fun_list:
        fun: FunData
        fun.print_data()

    asm_tree_list = process_binary(binary_file, analysis_list)
    
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
    parser.add_argument('--dir', type=str, help='Specify a directory (optional)', default=None)

    # Parse arguments
    args = parser.parse_args()

    # Determine base_name if binary is provided
    base_name = None
    if args.binary is not None:
        base_name = Path(args.binary).stem  # Extracts the base name without extension
    elif args.dir is not None:
        base_name = Path(args.dir).stem  # Extracts the base name without extension

    # Perform the appropriate analysis based on the provided arguments
    if args.dir is not None:
        log.info("Analyzing the directory")
        # Handle directory-based processing
        target_dir = Path(args.dir).resolve()
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