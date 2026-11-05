import logging
import sys
import os
import fileinput
import argparse
import shutil
import inspect

from pickle import FALSE
from tkinter import N
from termcolor import colored

from pathlib import Path
from pprint import pprint
from dataclasses import dataclass, field
from typing import Optional

import taint_analysis

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
    format = "[Line:%(lineno)4s -%(funcName)18s()] %(levelname)7s    %(message)s "

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

@dataclass(unsafe_hash = True)
class FileData:
    name: str = None
    asm_path: str = None
    obj_path: str = None
    fun_list: Optional[list] = None
    
fun_list = list()       # This list contains all functions analyzed per asm file
file_list = list()      # This list contains all files

def custom_pprint(obj, color='blue', attrs=['reverse']):
    # Get the current frame and then the outer frame (caller's frame)
    frame = inspect.currentframe()
    outer_frame = inspect.getouterframes(frame)[1]
    filename = outer_frame.filename

    # Extract the base filename from the full path
    base_filename = filename.split('/')[-1]

    # Create the message prefix with the base filename
    message_prefix = f"{base_filename}:\n"

    # Prepare the object for pretty printing as a string
    obj_str = pprint.pformat(obj)

    # Combine the message prefix and the pretty printed object
    combined_message = message_prefix + obj_str

    # Print the combined message with color and attributes
    print(colored(combined_message, color, attrs=attrs))

    # Cleanup to avoid reference cycles
    del frame, outer_frame
    
def visit_dir(dir_list):
    for root, dirs, files in os.walk(dir_list):
        for file_name in files:
            temp_file = None
            tgt_index = None
            base_name = os.path.splitext(os.path.basename(file_name))[0]
            for index, file_item in enumerate(file_list):
                if isinstance(file_item, FileData) and file_item.name == base_name:
                    tgt_index = index
            if tgt_index != None:
                temp_file = file_list[tgt_index]
            else:
                temp_file = FileData(base_name)

            if file_name.endswith(".s"):
                file_path = os.path.join(root, file_name)
                temp_file.asm_path = file_path
            elif file_name.endswith(".o"):
                file_path = os.path.join(root, file_name)
                temp_file.obj_path = file_path
                
            if temp_file != None and tgt_index == None:
                file_list.append(temp_file)
    
def main():
    # Get the size of the terminal
    columns, rows = shutil.get_terminal_size(fallback=(80, 20))

    # Create a string that fills the terminal width with spaces
    # Subtract 1 to accommodate the newline character at the end of the string
    empty_space = ' ' * (columns - 1)
    
    # Call functions in an organized manner
    # Create the parser
    parser = argparse.ArgumentParser(description='Process some inputs.')

    # Add arguments
    parser.add_argument('--binary', type=str, help='Path to a binary file')
    parser.add_argument('--directory', type=str, help='Specify a directory (optional)', default=None)
    
    # Parse arguments
    args = parser.parse_args()
    base_name       = Path(args.binary).stem  # Extracts the base name without extension
    
    if args.directory is not None:
        target_dir = Path(os.path.abspath(args.directory))
        visit_dir(target_dir)
        binary_item     = target_dir / f"{base_name}.out"  # Updated variable name for clarity
    else:
        # Assuming 'args.binary' is a predefined variable
        target_dir      = Path(args.binary).resolve().parent.parent / base_name
        binary_item     = target_dir / f"{base_name}.out"  # Updated variable name for clarity
        output          = taint_analysis.process_binary(binary_item)
        
        config_file = target_dir.joinpath("%s.config" % base_name)
        fp = open(config_file, "w") 
        for fun in output:
            name = fun[0].name
            for funs in taint_analysis.BinTaintAnalysis.fun_param_info:
                # print(funs, name)
                if funs[0].name == name:
                    op = funs[1]
                    fp.write("%s MY_IOCTL 0_%d\n" % (name, op))
            # print("%s: Operand Index: %d", )
        # print(fp)
        fp.close()
        
        
# Call main function
if __name__ == '__main__':
    main()