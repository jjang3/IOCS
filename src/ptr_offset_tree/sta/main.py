import logging
import re
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

# dwarf_analysis_old (and taint_analysis, which imports it) live in the rewriter's src/
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'asm_rewriter', 'src'))

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
    
def ll_callers(ll_file):
    """callee -> set of callers, the direct calls of an LLVM IR module (.ll)."""
    callers, cur = dict(), None
    define = re.compile(r'^define .*?@([\w.$]+)\(')
    call = re.compile(r'\b(?:call|invoke)\b.*?@([\w.$]+)\(')
    with open(ll_file, errors="replace") as f:
        for line in f:
            if line.startswith('define '):
                m = define.match(line)
                cur = m.group(1) if m else None
            elif line.startswith('}'):
                cur = None
            elif cur is not None:
                for m in call.finditer(line):
                    callers.setdefault(m.group(1), set()).add(cur)
    return callers

def dta_entry_config(binary, analysis_file, config_file, ll_file=None):
    """SUTURE entry config from a DTA trace: each traced function the program defines, with every
    parameter user-controlled ("f MY_IOCTL 0_1_2"). The DTA saw the input reach these functions
    but does not say through which parameter. Parameters come from DWARF; a function without
    parameters has nothing to taint and is left out."""
    import logging as _logging
    _logging.disable(_logging.CRITICAL)     # (dwarf_analysis logs every DIE)
    import io, contextlib
    from dwarf_analysis_old import dwarf_analysis
    with contextlib.redirect_stdout(io.StringIO()):
        funs = dwarf_analysis(binary)
    _logging.disable(_logging.NOTSET)
    nparams = dict()
    for fun in funs:
        n = sum(1 for v in fun.var_list if v.tag == "DW_TAG_formal_parameter")
        nparams[fun.name] = max(n, nparams.get(fun.name, 0))
    with open(analysis_file) as f:
        names = [n.strip() for n in f.read().replace('\n', ',').split(',') if n.strip()]
    names = list(dict.fromkeys(names))
    traced = len(names)
    if ll_file is not None:
        # SUTURE's entry functions are the program's external interface, not every function the
        # input reached: keep the traced functions that no other traced function calls (where the
        # input enters the traced region); SUTURE follows the calls from there itself.
        callers = ll_callers(ll_file)
        dta = set(names)
        names = [n for n in names if not (callers.get(n, set()) & (dta - {n}))]
        print("entry config: %d of %d DTA functions have no caller among them" % (len(names), traced))
    written = 0
    with open(config_file or Path(binary).with_suffix('.config'), "w") as fp:
        for name in dict.fromkeys(names):
            if nparams.get(name, 0) > 0:
                fp.write("%s MY_IOCTL %s\n" % (name, "_".join(str(i) for i in range(nparams[name]))))
                written += 1
    print("entry config: %d of %d DTA functions (%d without DWARF or parameters)" % (written, traced, len(names) - written))

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
    parser.add_argument('--analysis', type=str, default=None,
                        help='DTA function list: the entry config is these functions, all parameters user-controlled')
    parser.add_argument('--config', type=str, default=None, help='entry config to write (with --analysis)')
    parser.add_argument('--roots', type=str, default=None, metavar='LL',
                        help='with --analysis: only the DTA functions no other DTA function calls (call graph of this .ll)')
    
    # Parse arguments
    args = parser.parse_args()
    base_name       = Path(args.binary).stem  # Extracts the base name without extension
    
    if args.analysis is not None:
        dta_entry_config(args.binary, args.analysis, args.config, args.roots)
    elif args.directory is not None:
        target_dir = Path(os.path.abspath(args.directory))
        visit_dir(target_dir)
        binary_item     = target_dir / f"{base_name}.out"  # Updated variable name for clarity
    else:
        # Assuming 'args.binary' is a predefined variable
        target_dir      = Path(args.binary).resolve().parent.parent / base_name
        binary_item     = target_dir / f"{base_name}.out"  # Updated variable name for clarity
        print(binary_item)
        import taint_analysis
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