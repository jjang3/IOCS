import logging
import sys
import fileinput
import inspect
import argparse
import shutil
import subprocess

from enum import Enum, auto

from pickle import FALSE
from tkinter import N
from termcolor import colored
import os
sys.path.append(os.path.join(os.getcwd(), 'src'))
# sys.path.append('src')  # Add the src directory to the import path

# from dwarf_analysis import *
from dwarf_analysis_old import *
# from dwarf_analysis_new import *
from gen_table import *
import gen_table as gen_table_mod
# from bin_analysis import *
# from rewriter import *
from verifier import *
import bin_analysis
import rewriter

current_dir = os.path.dirname(os.path.abspath(__file__))
target_dir = os.path.join(current_dir, '..', 'sta')
normalized_path = os.path.normpath(target_dir)
sys.path.append(normalized_path)
import taint_analysis

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
# Set up the logger
log = logging.getLogger(__name__)
log.setLevel(debug_level)  # Set the debug level
if not log.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(CustomFormatter())
    log.addHandler(ch)
log.propagate = False  # Disable propagation to prevent duplicate logging


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
    print(vuln_file)
    # Open the file and read line by line
    try:
        with open(vuln_file, 'r', encoding='utf-8') as file:
            for line in file:
                # Trim whitespace for consistency
                line = line.strip()
                if line.startswith("file:"):
                    # The function name ("... - fun_name: <f>"; a file name may contain '-' itself:
                    # src/chown-core.c, so the line is not split on '-')
                    m = re.search(r"fun_name:\s*(\S+)", line)
                    curr_fun_name = m.group(1) if m else ""
                elif line.startswith("- instruction:"):
                    # This line contains the instruction, extract it
                    current_instruction = line.split(":", 1)[1].strip()
                    # Add the instruction to the current function name in the dictionary
                    if curr_fun_name not in taint_insts:
                        taint_insts[curr_fun_name] = set()
                    taint_insts[curr_fun_name].add(current_instruction)
    except:
        log.error("Vuln file not provided")

    pprint.pprint(taint_insts)
    
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
        # Pattern to match the instructions block, capturing instructions until an empty line
        block_pattern = re.compile(r'#####INSTS#####\n(.*?)(?=\n\n|\Z)', re.DOTALL)

        # Specific pattern to match only the desired format of instruction lines
        # ((\w+\/\w+\.c@(\d+)) \(\s*(.+?)\s*\))
        combined_pattern = re.compile(
        r'(([\w./+-]+\.c@(\d+)) \(\s*(.+?)\s*\))|'   # (any source path: src/chown-core.c, src/blake2/b2sum.c)
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
                        # The first named value of the trace (a segment can start with a call whose
                        # operands are all numbered, %0, %1: then the next instruction names it).
                        # Before, that raised, and the bare except below dropped every taint.
                        var_name = None
                        for seg_inst in segment:
                            var_name = re.search(r"%([a-zA-Z_][a-zA-Z0-9_]*)\s*\,", seg_inst)
                            if var_name:
                                break
                        if var_name is None:
                            log.warning("No variable named in the trace of %s: %s", fun, inst)
                            continue
                        log.critical("Var name: %s", var_name.group(1))
                        var_name_sets.add((var_name.group(1), fun))
        pprint.pprint(var_name_sets)
    except Exception as err:
        log.error("SUTURE report %s not read: %s", file_path, err)
    
    
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
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        # Fatal: the object would keep the compiler's code and the relink would hide that
        log.error("Assembling %s failed: %s", filename.asm_path, e)
        sys.exit(3)

all_dwarf_info      = dict()
dwarf_fun_var_info  = dict()
bn_fun_var_info     = dict()
fun_table_offsets   = dict()

target_fun_var_info = dict()
param_locs          = dict()   # function -> where each DWARF parameter is passed (SysV), or None

def process_file(input_item, analysis_list, taint_sets):
    global dwarf_var_count
    # dwarf_analysis = DwarfAnalysis(input_item)
    # dwarf_analysis.process_dwarf_info()
    dwarf_output: list[FunData] = []
    # dwarf_output = process_dwarf_info(input_item)
    dwarf_output = dwarf_analysis(input_item)
    # A function is analysed (DWARF kept, binary analysed, rewritten) if the DTA trace lists it or
    # SUTURE found a tainted variable in it: SUTURE's tainted functions are not always a subset of
    # the DTA list (cp's make_dir_parents_private, re_protect), and their variables are lifted into
    # a traced caller's object by the trees, or isolated in place when no tree lifts them.
    taint_funs = {f for _, f in taint_sets}
    for fun in dwarf_output:
        log.debug(fun.name)
        all_dwarf_info[fun.name] = fun.var_list.copy()
        # (two static functions of one name that pass their parameters differently: unknown)
        locs = getattr(fun, "param_locs", None)
        param_locs[fun.name] = locs if param_locs.get(fun.name, locs) == locs else None
        if fun.name in analysis_list or fun.name in taint_funs:
            dwarf_fun_var_info[fun.name] = fun.var_list.copy()
            dwarf_var_count += fun.var_count
    # exit()
    pprint.pprint(dwarf_fun_var_info)

    # print(taint_sets)
    # Print the extracted instructions
    if len(taint_sets) != 0:
        for idx, var in enumerate(taint_sets):
            print(f"Var target: {idx, var[0]} - Fun: {var[1]}")
            if var[1] not in all_dwarf_info:
                log.error("Tainted function %s has no DWARF", var[1])
                continue
            # Accumulate: a function with several tainted variables keeps all of them (before,
            # target_fun_var_info[fun] was overwritten once per variable, so only the last stayed).
            target_var_list = target_fun_var_info.setdefault(var[1], [])
            for dwarf_var in all_dwarf_info[var[1]]:
                # print(dwarf_var)
                dwarf_var: VarData
                if dwarf_var.name == var[0] and dwarf_var not in target_var_list:
                    log.critical("Found")
                    dwarf_var.vuln = True
                    target_var_list.append(dwarf_var)
    else:
        # True tree mode: with no SUTURE warnings there is nothing to isolate, and nothing for the
        # pointer offset trees to lift, so no compartment is created (e.g. pwd). (Protecting every
        # variable here would be directory mode, not the tree.)
        log.info("No taint information given: no tainted variables to compartmentalise")
    pprint.pprint(target_fun_var_info)
    # exit()
    
def read_fun_bodies(asm_paths):
    """function -> its lines in the compiler's assembly (the .bak an earlier rewrite left, else
    the .s); a name defined in several objects (two static functions) gets all of their lines,
    so a stack-only reason found in either holds for both."""
    bodies = dict()
    for path in asm_paths:
        src = path + ".bak" if os.path.isfile(path + ".bak") else path
        with open(src, encoding="utf-8", errors="replace") as f:
            cur = None
            for line in f:
                begin = re.search(r'(?<=.type\t)(.*)(?=,\s@function)', line)
                if begin is not None:
                    cur = begin.group(1)
                    bodies.setdefault(cur, list())
                elif cur is not None:
                    bodies[cur].append(line)
                    if re.search(r'(\t.cfi_endproc)', line):
                        cur = None
    return bodies

class StackOnly:
    """Whether a variable can get a compartment, decided before any lift (tree_stack_only on the
    compiler's assembly, plus the accesses an earlier rewrite pass could not redirect)."""
    def __init__(self, bodies, reentry):
        self.bodies, self.reentry = bodies, reentry
        self.extra = dict()     # fun -> {slot expr: instruction} (tree_uncovered)
        self.cache = dict()

    def reasons(self, fun):
        if fun not in self.cache:
            dwarf = all_dwarf_info.get(fun, [])
            exprs = {(v.offset_expr, 0) for v in dwarf if v.offset_expr is not None}
            self.cache[fun] = rewriter.tree_stack_only(fun, dwarf, exprs, self.bodies.get(fun, []), self.reentry,
                                                       self.extra.get(fun), log=False)
        return self.cache[fun]

    def add_uncovered(self, found):
        new = False
        for fun, slots in found.items():
            for expr, why in slots.items():
                if expr not in self.extra.setdefault(fun, dict()):
                    self.extra[fun][expr] = why
                    new = True
            self.cache.pop(fun, None)
        return new

    def why(self, fun, var):
        """(reason, instruction) if fun's var stays on the stack, else None."""
        if fun not in self.bodies:
            return ("no-code", "%s is not in the rewritten objects" % fun)
        if var_slot(var) is None:
            return ("no-slot", "no frame slot (register, global or void)")
        if var.tag == "DW_TAG_formal_parameter" and (frame_offset(var) is None or frame_offset(var) >= 0):
            return ("stack-passed", "a parameter the caller passes on the stack")
        return self.reasons(fun).get(var.offset_expr)

def frame_offset(var):
    m = re.match(r"(-?\d+)\(%rbp\)$", str(var.offset_expr))
    return int(m.group(1)) if m else None

def param_index(fun, var):
    """var's index among fun's DWARF formal parameters (as taint_analysis numbers them)."""
    idx = 0
    for v in all_dwarf_info.get(fun, []):
        if v.tag == "DW_TAG_formal_parameter":
            if v is var or (v.name == var.name and v.offset == var.offset):
                return idx
            idx += 1
    return None

def root_vars(root):
    """The DWARF variables at a root object's start (variables of disjoint scopes share a slot)."""
    fun, start, name = root
    return [v for v in all_dwarf_info.get(fun, []) if v.offset_expr is not None and frame_offset(v) == start
            and v.tag in ("DW_TAG_variable", "DW_TAG_formal_parameter")]

def decide_compartments(tainted, resolutions, stack_only):
    """fun -> [VarData] that get a compartment, and the report lines (lifts, kept slots).
    A tainted pointer parameter is lifted to the caller objects it can point to, over every call
    of its function (resolutions); its own slot is dropped only when every one of those objects
    gets a compartment. Otherwise it keeps its own slot, and the objects that can be isolated
    are isolated too. A variable that cannot have a compartment stays on the stack, logged."""
    comp, lines, kept = dict(), [], []
    def add(fun, var):
        lst = comp.setdefault(fun, [])
        if var not in lst:
            lst.append(var)
    def label(fun, var):
        return "%s %s@%s" % (fun, var.name, var.offset)
    for fun, vars in sorted(tainted.items()):     # (sorted: the same table on every run)
        for var in vars:
            res = None
            if var.tag == "DW_TAG_formal_parameter" and var.ptr:
                res = resolutions.get((fun, param_index(fun, var)))
            if res is None:
                add(fun, var)
                continue
            if res[0] != 'ok' or not res[1]:
                lines.append("own slot: %s (%s)" % (label(fun, var), res[1] if res[0] != 'ok' else "no caller object"))
                add(fun, var)
                continue
            good, bad = [], []
            for root in sorted(res[1]):
                rvars = root_vars(root)
                why = None
                if not rvars:
                    why = ("no-dwarf", "no DWARF variable at %s:%d" % (root[0], root[1]))
                else:
                    why = next((w for w in (stack_only.why(root[0], v) for v in rvars) if w), None)
                (bad if why else good).append((root, rvars, why))
            for root, rvars, _ in good:
                for v in rvars:
                    add(root[0], v)
            roots_txt = ", ".join("%s:%d(%s)" % r[0] for r in good)
            if not bad:
                lines.append("lifted: %s -> %s" % (label(fun, var), roots_txt))
            else:
                lines.append("own slot: %s (caller object %s stays on the stack: %s)%s" % (
                    label(fun, var), "%s:%d(%s)" % bad[0][0], bad[0][2][0], "; also isolated: " + roots_txt if good else ""))
                add(fun, var)
    final = dict()
    for fun, vars in sorted(comp.items()):
        for var in vars:
            why = stack_only.why(fun, var)
            if why:
                kept.append((fun, var.offset_expr, why))
            else:
                final.setdefault(fun, []).append(var)
    return final, lines, kept

macro_slot_regex = re.compile(r'^\s+[a-z_]+_gs\s+[^,#]+,\s*(\d+)\b')
def used_slots(asm_paths):
    """Table offsets that the rewritten code reaches (every *_gs macro names its slot second)."""
    used = set()
    for path in asm_paths:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = macro_slot_regex.match(line)
                if m:
                    used.add(int(m.group(1)))
    return used

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
    parser.add_argument('--binary', type=str, help='Path to the linked program (.out)')
    parser.add_argument('--directory', type=str, default=None,
                        help='Directory of the objects (.s/.o/.intel) to rewrite; default: the result dir')
    parser.add_argument('--result', type=str, default=None,
                        help='Result dir with <stem>.taint/.vuln/.analysis; table.c is written here')

    # Parse arguments
    args = parser.parse_args()
    base_name = Path(args.binary).stem    # the linked program's stem (tiny, basename, nginx, ...)

    # One pipeline for every input (single object, a program's several objects, or Nginx's tree):
    #   result_dir holds the SUTURE/DTA inputs and receives table.c; asm_dir holds the .s/.o/.intel.
    #   For a single result dir (coreutils, tiny) the two are the same; Nginx keeps its .s in
    #   objs/src (--directory) and its SUTURE inputs in a separate result dir (--result).
    if args.result is not None:
        result_dir = Path(os.path.abspath(args.result))
    else:
        # <grandparent of --binary>/result/<stem>, de-duplicating a "result/result" (iocs.sh passes
        # result/<t>.out, so the grandparent is the repo root).
        result_dir = Path(args.binary).resolve().parent.parent / "result" / base_name
        result_dir = Path(str(result_dir).replace("result/result", "result", 1))
    asm_dir = Path(os.path.abspath(args.directory)) if args.directory is not None else result_dir

    binary_item = Path(args.binary).resolve()
    vuln_file   = result_dir / f"{base_name}.vuln"
    taint_file  = result_dir / f"{base_name}.taint"
    analysis_file = result_dir / f"{base_name}.analysis"

    # The DTA function list (deduplicated, order kept).
    with open(analysis_file) as ff:
        analysis_list = ff.read().replace('\n', ',').split(',')
    analysis_list = [x.strip() for x in analysis_list if x.strip()]
    seen = set()
    analysis_list = [x for x in analysis_list if not (x in seen or seen.add(x))]

    # SUTURE's tainted variables (<fun>, <var>). An empty or missing .vuln means SUTURE found
    # nothing: true tree mode then protects only what the pointer offset trees lift.
    taint_insts_set = set()
    if os.path.isfile(vuln_file) and os.path.getsize(vuln_file) > 0:
        taint_insts_set = extract_taints(taint_file, vuln_file)

    # Catalogue every object (.s/.o/.intel) and the functions each .s defines; which ones are
    # rewritten is decided once funlist is known (below).
    visit_dir(asm_dir)
    find_funs(file_list)
    analysis_set = set(analysis_list)

    # 1) DWARF of every analysed function (from the linked program: it carries them all), and the
    #    tainted variables marked on it (accumulated per function, not overwritten).
    log.info("Analyzing %s", binary_item)
    process_file(binary_item, analysis_list, taint_insts_set)

    # 2) Pointer offset trees on the linked program (trees.txt, paper Listing 3), and for each
    #    tainted pointer parameter the caller objects it can point to over every call of its
    #    function (taint_analysis.resolve_param).
    lift_candidates = sorted({(fun, param_index(fun, var)) for fun, vars in target_fun_var_info.items() for var in vars
                              if var.tag == "DW_TAG_formal_parameter" and var.ptr and param_index(fun, var) is not None})
    ptr_offset_trees, resolutions = taint_analysis.process_offset(binary_item, all_dwarf_info, analysis_list,
                                                                  param_locs, lift_candidates)
    trees_path = result_dir / "trees.txt"
    with open(trees_path, "w") as tf:
        tf.write("# Pointer offset trees (paper Listing 3): a caller's object -> the callee "
                 "parameters it reaches.\n# %s, %d function(s) on the taint path.\n\n"
                 % (base_name, len(analysis_list)))
        if ptr_offset_trees:
            for tree in ptr_offset_trees:
                tf.write("\n".join(tree.format_tree()) + "\n\n")
        else:
            tf.write("(no pointer offset trees)\n")
        tf.write("\n# Function summaries (function trees' nodes)\n")
        tf.write("\n".join(taint_analysis.last_summaries) + "\n")
    log.info("Wrote %s", trees_path)

    # IOCS_DEBUG_STOP=552 stops after the pointer-offset-tree pass (debugging aid).
    if os.environ.get('IOCS_DEBUG_STOP') == '552':
        exit()

    # Whether a variable can be compartmentalised is known before any lift: tree_stack_only on the
    # compiler's assembly, and (after a rewrite) the accesses the rewrite could not redirect.
    asm_paths = [str(f.asm_path) for f in file_list if f.asm_path is not None]
    stack_only = StackOnly(read_fun_bodies(asm_paths), rewriter.Reentry(asm_paths))
    # Every function that can get a compartment: Binary Ninja info is taken once for all of them.
    root_funs = {r[0] for res in resolutions.values() if res[0] == 'ok' for r in res[1]}
    for fun in root_funs:
        if fun not in dwarf_fun_var_info and fun in all_dwarf_info:
            dwarf_fun_var_info[fun] = all_dwarf_info[fun].copy()
    bn_funs = sorted(analysis_set | set(target_fun_var_info) | root_funs)
    bn_fun_var_info = bin_analysis.process_binary(binary_item, bn_funs)

    # 3)-5) Decide the compartments, write the table, rewrite every object that defines a function
    #    with one (stores REPLACE the stack write: true isolation). A slot with an access the
    #    rewrite did not redirect stays on the stack; the lifts are then decided again (its
    #    callee keeps its own slot) and every object is rewritten from its original. Each round
    #    moves at least one slot to the stack, so it ends.
    rewritten = dict()          # asm path -> FileData, every file rewritten in some round
    rounds = 0
    while True:
        rounds += 1
        comp, lift_lines, kept = decide_compartments(target_fun_var_info, resolutions, stack_only)
        print(colored(f"{empty_space}\n", 'grey', attrs=['underline']))
        fun_table_offsets.clear()
        gen_table_mod.fun_table_offsets.clear()
        fun_table_offsets.update(generate_table(dwarf_var_count, comp, result_dir))
        funlist = sorted(analysis_set | {f for f, v in comp.items() if v})
        funset = set(funlist)
        targets = [f for f in file_list if f.asm_path is not None and f.fun_list and funset.intersection(f.fun_list)]
        reentry = stack_only.reentry
        found_all = dict()
        patch_count = 0
        for file_item in targets:
            log.info("Rewriting %s", file_item.asm_path)
            patch_count += rewriter.rewriter(funlist, "", str(file_item.asm_path), dwarf_fun_var_info,
                                             bn_fun_var_info, fun_table_offsets, reentry, stack_only.extra)
            rewritten[str(file_item.asm_path)] = file_item
            for fun, found in rewriter.last_uncovered.items():
                found_all.setdefault(fun, dict()).update(found)
        # (a file rewritten in an earlier round that has no compartment now: back to its original)
        for path, file_item in list(rewritten.items()):
            if file_item not in targets and os.path.isfile(path + ".bak"):
                shutil.copyfile(path + ".bak", path)
        if not stack_only.add_uncovered(found_all):
            break
        log.warning("consistency: round %d: again with %s on the stack", rounds,
                    "; ".join("%s %s" % (f, " ".join(sorted(s))) for f, s in sorted(found_all.items())))
    for file_item in rewritten.values():
        if file_item.obj_path is not None:
            gen_obj_file(file_item)

    # Variables kept on the stack, in the form the sweep reports read
    for fun, expr, (reason, why) in sorted(kept):
        log.warning("consistency: %s: %s stays on the stack (%s: %s)", fun, expr, reason, why)
    with open(result_dir / "lifted.txt", "w") as lf:
        lf.write("# Tainted pointer parameters: lifted to the caller objects they point to, or kept in their\n"
                 "# own slot (why). Variables without a compartment: kept-on-stack lines.\n")
        lf.write("\n".join(lift_lines) + ("\n" if lift_lines else ""))
        for fun, expr, (reason, why) in sorted(kept):
            lf.write("kept on stack: %s %s (%s: %s)\n" % (fun, expr, reason, why))
    # Compartments = slots the rewritten code uses; table.c may also hold a placeholder (no slot)
    # or a padding slot, and a slot whose variable no access reached.
    used = used_slots([p for p in rewritten if os.path.isfile(p)])
    slots = sorted(((t, fun, expr) for fun, ts in fun_table_offsets.items() for expr, t in ts))
    table_count = int(re.search(r'#define SLOT_COUNT (\d+)', open(result_dir / "table.c").read()).group(1))
    with open(result_dir / "compartments.txt", "w") as cf:
        cf.write("compartments: %d (slots the rewritten code uses)\n" % len([s for s in slots if s[0] in used]))
        cf.write("table slots: %d (unused: %d, placeholder/padding: %d), kept on stack: %d, rounds: %d\n" % (
            table_count, len([s for s in slots if s[0] not in used]), table_count - len(slots), len(kept), rounds))
        for t, fun, expr in slots:
            names = ",".join(sorted({v.name for v in comp.get(fun, []) if v.offset_expr == expr and v.name}))
            cf.write("%-6s %4d %s %s %s\n" % ("used" if t in used else "unused", t // 8, fun, expr, names))
    log.critical("Patch count %d", patch_count)
    exit()


# Call main function
if __name__ == '__main__':
    main()