import logging
import sys
import fileinput
import inspect
import argparse
import shutil

from enum import Enum, auto

from pickle import FALSE
from tkinter import N
from termcolor import colored
import os
sys.path.append(os.path.join(os.getcwd(), 'src'))
# sys.path.append('src')  # Add the src directory to the import path

# from dwarf_analysis import *
from dwarf_analysis_old import *
from gen_table import *
from bin_analysis import *
from rewriter import *
from verifier import *

from pathlib import Path
import pprint 
from dataclasses import dataclass, field



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

# Total number of variables from the DWARF analysis
dwarf_var_count = 0

# This list will contain all target files based on searching through all directories
target_files = list()

# This dict will have function -> fun_list relationship
file_fun = dict()
fun_list = list() # This list contains all functions analyzed per asm file
file_list = list()

patch_count = 0

# Split the instructions list into two lists using "#####CTX#####" as the delimiter
def split_by_ctx(instructions):
    # Initialize a list to hold lists of instructions
    segments = []
    current_segment = []
    for instruction in instructions:
        if instruction.startswith('#####CTX#####'):
            # When a #####CTX##### marker is found, add the current segment to segments
            # and start a new segment
            if current_segment:
                segments.append(current_segment)
                current_segment = []
            # Optionally, add or don't add the CTX line itself, depending on requirements
            # current_segment.append(instruction)  # Uncomment to include CTX lines
        else:
            # Add instruction to the current segment
            current_segment.append(instruction)
    
    # Add the last segment if it's not empty
    if current_segment:
        segments.append(current_segment)
    
    return segments

def extract_taints(file_path, vuln_file):
    var_name_sets = set()
    
    # Dictionary to store the function names and their instructions
    taint_insts = {}

    # Temporary variable to store current function name
    curr_fun_name = ""

    # Open the file and read line by line
    with open(vuln_file, 'r', encoding='utf-8') as file:
        for line in file:
            # Trim whitespace for consistency
            line = line.strip()
            if line.startswith("file:"):
                # This line contains the function name, extract it
                parts = line.split("-")
                # Extracting the actual function name
                curr_fun_name = parts[2].split(":")[1].strip()
            elif line.startswith("- instruction:"):
                # This line contains the instruction, extract it
                current_instruction = line.split(":", 1)[1].strip()
                # Add the instruction to the current function name in the dictionary
                if curr_fun_name not in taint_insts:
                    taint_insts[curr_fun_name] = set()
                taint_insts[curr_fun_name].add(current_instruction)
    
    pprint.pprint(taint_insts)
    
    
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()
    
    # Pattern to match the instructions block, capturing instructions until an empty line
    block_pattern = re.compile(r'#####INSTS#####\n(.*?)(?=\n\n|\Z)', re.DOTALL)

    # Specific pattern to match only the desired format of instruction lines
    # ((\w+\/\w+\.c@(\d+)) \(\s*(.+?)\s*\))
    combined_pattern = re.compile(
    r'((\w+\/\w+\.c@(\d+)) \(\s*(.+?)\s*\))|'
    r'(#####CTX#####\s+(\w+)\s+->\s+(\w+))', re.DOTALL)
    
    # Find all blocks of instructions
    blocks = block_pattern.findall(content)

    instruction_sets = []
    for block in blocks:
        matches = combined_pattern.findall(block)
        block_instructions = []
        for match in matches:
            if match[0]:  # This means it matched an instruction line
                file_path_line = match[1]
                instruction = match[3]
                print(instruction)
                if re.search(r"^(?!.*\balloca\b).+$", instruction):
                    # block_instructions.append(f"{file_path_line} ({instruction})")
                    block_instructions.append(f"{instruction}")
                else:
                    logger.warning("Ignore alloca")
            elif match[4]:  # This means it matched a context line
                ctx_info = match[4]
                block_instructions.append(ctx_info)
        segments = split_by_ctx(block_instructions)
        # Print the segments
        for i, segment in enumerate(segments):
            print(f"Segment {i + 1}:")
            for instruction in segment:
                print(instruction)
            print("\n---\n")
            instruction_sets.append(segment)
    # exit()
            # instruction_sets.append(block_instructions)
        
        # instruction_sets.append(block_instructions)

    pprint.pprint(instruction_sets)
    
    for fun in taint_insts:
        logger.info(fun)
        for inst in taint_insts[fun]:
            logger.debug(inst)
            for segment in instruction_sets:
                last_element = segment[-1]
                if inst == last_element:
                    var_name = re.search(r"%([a-zA-Z_][a-zA-Z0-9_]*)\s*\,", segment[0])
                    log.critical("Var name: %s", var_name.group(1))
                    var_name_sets.add((var_name.group(1), fun))
    pprint.pprint(var_name_sets)
    # exit()
    return var_name_sets
    # return instruction_sets

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
    
def find_funs(file_list):
    fun_regex = re.compile(r'\t\.type\s+.*,\s*@function\n\b(^.[a-zA-Z_.\d]+)\s*:', re.MULTILINE)
    for file_item in file_list:
        if file_item.asm_path != None:
            # pprint(file_item)
            with open(file_item.asm_path, 'r') as asm_file:
                asm_string = asm_file.read()
                fun_names = fun_regex.findall(asm_string)
            for name in fun_names:
                fun_list.append(name)
            if file_item.fun_list == None:
                file_item.fun_list = fun_list.copy()
            fun_list.clear()
            
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
            elif file_name.endswith(".intel"):
                file_path = os.path.join(root, file_name)
                temp_file.intel_path = file_path
                
            if temp_file != None and tgt_index == None:
                file_list.append(temp_file)

def gen_obj_file(filename):
    print(filename.asm_path, filename.obj_path)
    try:
        # Call GNU assembler with the source and destination file paths
        subprocess.run(['as', filename.asm_path, '-o', filename.obj_path], check=True)
        print(f"Assembly of {filename.asm_path} completed. Output in {filename.obj_path}")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
    except FileNotFoundError:
        print("GNU assembler (as) not found. Please ensure it is installed and in your PATH.")

dwarf_fun_var_info  = dict()
bn_fun_var_info     = dict()
fun_table_offsets   = dict()

target_fun_var_info = dict()

def process_file(input_item, analysis_list, taint_sets):
    global dwarf_var_count
    dwarf_output: list[FunData] = []
    dwarf_output = dwarf_analysis(input_item)
    # exit()
    for fun in dwarf_output:
        if fun.name in analysis_list:
            dwarf_fun_var_info[fun.name] = fun.var_list.copy()
            dwarf_var_count += fun.var_count
    pprint.pprint(dwarf_fun_var_info)
    # Print the extracted instructions
    for idx, var in enumerate(taint_sets):
        print(f"Var target: {idx, var[0]} - Fun: {var[1]}")
        try:
            # pprint.pprint(dwarf_fun_var_info[var[1]])
            target_var_list = list()
            for dwarf_var in dwarf_fun_var_info[var[1]]:
                print(dwarf_var.name)
                if dwarf_var.name == var[0]:
                    log.critical("Found")
                    target_var_list.append(dwarf_var)
            target_fun_var_info[var[1]] = target_var_list.copy()
        except:
            log.error("Not part of tainted path")

    # exit()
    
    
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
    
    if args.binary != None:
        base_name       = Path(args.binary).stem  # Extracts the base name without extension
    
    analysis_list = None
    
    if args.directory is not None:
        target_dir = Path(os.path.abspath(args.directory))
        analysis_file   = target_dir / f"{base_name}.analysis"
        with open(analysis_file) as ff:
            for line in ff:
                analysis_list = line.split(',')
                # need to modify this code later to make it support "context path" with new lines or not.
        visit_dir(target_dir)
        find_funs(file_list)
        for file_item in file_list:
            if file_item.fun_list != None:
                file_fun_list = file_item.fun_list
                found = [element for element in analysis_list if element in file_fun_list]
                if found:
                    target_files.append(file_item)
                    
        # 1) generate table based on DWARF information
        for file_item in target_files:
            log.info("Analyzing %s", file_item)
            process_file(file_item.obj_path, analysis_list, set())
        print(colored(f"{empty_space}\n", 'grey', attrs=['underline']))
        fun_table_offsets = generate_table(dwarf_var_count, dwarf_fun_var_info, target_dir)
        # print(colored(f"{empty_space}\n"), 'grey', attrs=['underline'])
        patch_count = 0
        # Recursion is a property of the whole program: the call graph spans all of its objects
        reentry = Reentry([file_item.asm_path for file_item in file_list if file_item.asm_path != None])
        # # 2) after generating table, need to perform binary analysis for each files
        for file_item in target_files:
            bn_fun_var_info = process_binary(file_item.obj_path, analysis_list)
            if not static_verifier(file_item.intel_path, "PRE", None):
                exit()
            patch_count += rewriter(analysis_list, target_dir, file_item.asm_path, dwarf_fun_var_info, bn_fun_var_info, fun_table_offsets, reentry)
            gen_obj_file(file_item)
            log.critical("Patch count %d", patch_count)
        
    else:
        # Assuming 'args.binary' is a predefined variable
        target_dir      = Path(args.binary).resolve().parent.parent / base_name
        result_dir      = Path(args.binary).resolve().parent.parent / "result" / base_name
        print(result_dir)
        
        # exit()
        vuln_file   = result_dir / f"{base_name}.vuln"
        taint_file  = result_dir / f"{base_name}.taint"
        intel_file  = result_dir / f"{base_name}.intel"
        # Use the function to extract instructions from the file
        taint_sets = extract_taints(taint_file, vuln_file)

        analysis_file   = result_dir / f"{base_name}.analysis"
        with open(analysis_file) as ff:
            for line in ff:
                # print(line)
                analysis_list = line.split(',')
        binary_item     = result_dir / f"{base_name}.out"  # Updated variable name for clarity
        asm_item        = result_dir / f"{base_name}.s"  # Updated variable name for clarity
        obj_item        = result_dir / f"{base_name}.o"  # Updated variable name for clarity
        temp_file = FileData(base_name)
        temp_file.asm_path = asm_item
        temp_file.obj_path = obj_item
        temp_file.intel_path = intel_file
        log.info("Analyzing %s", binary_item)
        process_file(binary_item, analysis_list, taint_sets)
        pprint.pprint(target_fun_var_info)
        # exit()
        print(colored(f"{empty_space}\n", 'grey', attrs=['underline']))
        # fun_table_offsets = generate_table(dwarf_var_count, dwarf_fun_var_info, result_dir)
        fun_table_offsets = generate_table(dwarf_var_count, target_fun_var_info, result_dir)
        pprint.pprint(fun_table_offsets)
        # exit()
        print(colored(f"{empty_space}\n", 'grey', attrs=['underline']))
        bn_fun_var_info = process_binary(binary_item, analysis_list)
        # exit()
        print(colored(f"{empty_space}\n", 'grey', attrs=['underline']))
        custom_pprint(bn_fun_var_info)
        custom_pprint(fun_table_offsets)
        failed_insts = list()
        result, failed_insts = static_verifier(intel_file, "PRE", None)
        result = True
        if not result:
            log.error("Failed check")
            for inst in failed_insts:
                log.debug(inst)
            # exit()
            
        else:
            patch_count = rewriter(analysis_list, result_dir, str(asm_item), dwarf_fun_var_info, bn_fun_var_info, fun_table_offsets, Reentry([asm_item]))
            log.critical("Patch count %d", patch_count)
            gen_obj_file(temp_file)
            # time.sleep(5)
            static_verifier(temp_file.obj_path, "POST", analysis_list)
        
        patch_count = rewriter(analysis_list, result_dir, str(asm_item), dwarf_fun_var_info, bn_fun_var_info, fun_table_offsets, Reentry([asm_item]))
        log.critical("Patch count %d", patch_count)
        #  There should be a new output file here to be passed into verifier
        #verifier(output_file, Verify.POST)
        exit()


# Call main function
if __name__ == '__main__':
    main()