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
from dataclasses import dataclass, field


# Get the directory where the current script is located
current_dir = os.path.dirname(os.path.abspath(__file__))

# Get the parent directory of the current script
parent_dir = os.path.dirname(current_dir)

# Add the 'utilities' directory from the parent directory to sys.path
sys.path.append(os.path.join(parent_dir, 'utilities'))

# Add the 'src' directory from the current directory to sys.path
sys.path.append(os.path.join(current_dir, 'src'))

#from dwarf_analysis import *
from dwarf_analysis import *
"""
from gen_table import *
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
    format = "[%(filename)s: Line:%(lineno)4s - %(funcName)20s()] %(levelname)7s    %(message)s "

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
    
# Debug options here
debug_level = logging.DEBUG
ch = logging.StreamHandler()
ch.setLevel(debug_level) 
ch.setFormatter(CustomFormatter())

log = logging.getLogger(__name__)
log.setLevel(debug_level)

# create console handler with a higher log level
log_disable = False
log.addHandler(ch)
log.disabled = log_disable

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

def main():
    # Get the size of the terminal
    columns, rows = shutil.get_terminal_size(fallback=(80, 20))

    # Create a string that fills the terminal width with spaces
    # Subtract 1 to accommodate the newline character at the end of the string
    empty_space = ' ' * (columns - 1)
    
    # Initialize the logger (example, adjust according to your needs)
    # logging.basicConfig(level=logging.INFO)
    # log = logging.getLogger(__name__)

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