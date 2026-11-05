from cgi import parse_multipart
import cgitb
import sys, getopt
import logging
import shutil
import pprint
import inspect
import os
import webbrowser
import time
import traceback
import re

from binaryninja import *
from binaryninja.mediumlevelil import MediumLevelILInstruction 
from binaryninja.binaryview import BinaryViewType
from binaryninja.architecture import Architecture, ArchitectureHook
from binaryninja.interaction import get_save_filename_input, show_message_box, TextLineField, ChoiceField, SaveFileNameField, get_form_input
from binaryninja.settings import Settings
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon, MessageBoxButtonResult, InstructionTextTokenType, BranchType, DisassemblyOption, FunctionGraphType, ThemeColor
from binaryninja.function import DisassemblySettings
from binaryninja.plugin import PluginCommand
from termcolor import colored
from functools import partial

import dwarf_analysis_old
import export_cg

@dataclass
class OperandData:
    callee_fun_name: Optional[str] = None
    oper_idx: Optional[int] = None
    taint_inst: Optional[binaryninja.lowlevelil.LowLevelILSetRegSsa] = None
    offset: Optional[int] = None
    ptr_ref: Optional[bool] = False

@dataclass
class LocalData:
    var_name: Optional[str] = None
    param_idx: Optional[int] = None
    offset: Optional[int] = None
    pointer: Optional[bool] = False

@dataclass
class FunctionNode:
    fun: Function
    function_name: str
    operands: List[OperandData] = field(default_factory=list)  # Direct operands of the function
    callee_funs: List['FunctionNode'] = field(default_factory=list)  # Nested callee functions
    checked: bool = False
    params:     List[LocalData]  = field(default_factory=list)  # Direct operands of the function
    local_vars: List[LocalData]  = field(default_factory=list)  # Direct operands of the function
    calls:      List['CallSite'] = field(default_factory=list)   # calls to functions defined in the binary

    def add_operand(self, operand: OperandData):
        self.operands.append(operand)

    def add_callee_function(self, callee_function: 'FunctionNode'):
        self.callee_funs.append(callee_function)

    def print_structure(self, indent=""):
        print(f"{indent}Function: {self.function_name}")
        for param in self.params:
            print(f"{indent}  Param: {param.param_idx}, Offset: {param.offset}, Ptr: {param.pointer}")
        for var in self.local_vars:
            print(f"{indent}  Var: {var.var_name}, Offset: {var.offset}, Ptr: {var.pointer}")
        for operand in self.operands:
            print(f"{indent}  OperIdx: {operand.oper_idx}, Offset: {operand.offset}, Ptr: {operand.ptr_ref}")
        for callee in self.callee_funs:
            print(f"{indent}  Calls: {callee.function_name}")
            callee.print_structure(indent + "    ")
            
    def print_fun_structure(self, indent=""):
        print(f"{indent}Function: {self.function_name}")
        for param in self.params:
            print(f"{indent}  Param: {param.param_idx}, Offset: {param.offset}, Ptr: {param.pointer}")
        for var in self.local_vars:
            print(f"{indent}  Var: {var.var_name}, Offset: {var.offset}")
        for callee in self.callee_funs:
            print(f"{indent}  Calls: {callee.function_name}")
            for operand in callee.operands:
                print(f"{indent}  OperIdx: {operand.oper_idx}, Offset: {operand.offset}, Ptr: {operand.ptr_ref}")
    
    def traverse_callees(self, action: Optional[Callable[['FunctionNode', Any], None]] = None, *args, **kwargs):
        """
        Recursively traverse all callee functions from this function node.
        Optionally, an action can be performed on each visited FunctionNode, with additional arguments.

        Args:
        - action: A callable that takes a FunctionNode as its first argument, followed by any number of additional arguments.
        - *args, **kwargs: Additional arguments to pass to the action callable.
        """
        if action:
            action(self, *args, **kwargs)

        for callee in self.callee_funs:
            callee.traverse_callees(action, *args, **kwargs)

# class CustomFormatter(logging.Formatter):
#     # FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s | %(levelname)s"
#     # logging.basicConfig(level=os.environ.get("LOGLEVEL", "DEBUG"), format=FORMAT)
#     blue = "\x1b[33;34m"
#     yellow = "\x1b[33;20m"
#     red = "\x1b[31;20m"
#     bold_green = "\x1b[42;1m"
#     purp = "\x1b[38;5;13m"
#     reset = "\x1b[0m"
#     # format = "%(funcName)5s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"
#     format = "[%(filename)s: Line:%(lineno)4s - %(funcName)20s()] %(levelname)7s    %(message)s "

#     FORMATS = {
#         logging.DEBUG: yellow + format + reset,
#         logging.INFO: blue + format + reset,
#         logging.WARNING: purp + format + reset,
#         logging.ERROR: red + format + reset,
#         logging.CRITICAL: bold_green + format + reset
#     }

#     def format(self, record):
#         log_fmt = self.FORMATS.get(record.levelno)
#         formatter = logging.Formatter(log_fmt)
#         return formatter.format(record)
    
# # Debug options here
# debug_level = logging.DEBUG
# ch = logging.StreamHandler()
# ch.setLevel(debug_level) 
# ch.setFormatter(CustomFormatter())

# log = logging.getLogger(__name__)
# logger.setLevel(debug_level)

# # create console handler with a higher log level
# log_disable = False
# logger.addHandler(ch)
# logger.disabled = log_disable

# Get the same logger instance. Use __name__ to get a logger with a hierarchical name or a specific string to get the exact same logger.
logger = logging.getLogger('main')

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
    
def process_binary(input_item):
    with load(input_item.__str__(), options={"arch.x86.disassembly.syntax": "AT&T"}) as bv:
        arch = Architecture['x86_64']
        # List of taint source funs and index of taint source
        taint_src_funs = {('__isoc99_sscanf', 0), ('__isoc99_scanf', 1), ('__isoc99_fscanf', 0), 
                          ('fgets', 0), ('gets', 0), ('read', 1), ('recv', 1), ('recvfrom', 1)}
        bn = BinTaintAnalysis(bv, taint_src_funs, None, None)
        return bn.analyze_binary()
        
def process_offset(input_item, dwarf_info, analysis_list, param_locs=None, lift_candidates=()):
    """(pointer offset trees, {(function, parameter index): ('ok', caller objects) or ('fail', why)})
    for the tainted pointer parameters in lift_candidates. param_locs: function -> where each
    DWARF parameter is passed (dwarf_analysis_old.abi_param_locations)."""
    with load(input_item.__str__(), options={"arch.x86.disassembly.syntax": "AT&T"}) as bv:
        logger.info(input_item.__str__())
        bn = BinTaintAnalysis(bv, None, dwarf_info, analysis_list)
        bn.param_locs = param_locs or dict()
        return bn.analyze_offset(lift_candidates)

class PtrOffsetTreeNode:
    """One (function, frame offset) of a pointer offset tree: the root is a caller's local object
    (or local pointer); each child is a callee's parameter that receives it, at the argument index
    the parent passes it in. A parameter that is passed on to several callees has several children."""
    def __init__(self, fun_name, reg_offset, index, var_name=None):
        self.fun_name = fun_name            # The current node (caller function)
        self.local_offset = reg_offset      # Frame offset (from %rbp) of the variable in fun_name
        self.callee_arg_idx = index         # Root: the argument index of its first call; child: the index it arrives at
        self.var_name = var_name
        self.children = []

    def add_child(self, child_node):
        self.children.append(child_node)
        return child_node

    def print_node(self):
        """Prints the details of this node in a readable format."""
        print(f"Caller Function Name: {self.fun_name}")
        print(f"Local Offset: {self.local_offset}")
        print(f"Callee Argument Index: {self.callee_arg_idx}")

    def key(self):
        return (self.fun_name, self.local_offset, tuple(sorted(c.key() for c in self.children)))

class PtrOffsetTree:
    def __init__(self, root=None):
        self.root = root

    def nodes(self, node=None):
        node = node or self.root
        if node is None:
            return
        yield node
        for child in node.children:
            yield from self.nodes(child)

    def format_tree(self, node=None, prefix=""):
        """Lines of the tree in the form of the paper's Listing 3."""
        if node is None:
            node = self.root
            if node is None:
                return ["Root Function: (empty)"]
            lines = ["Root Function: %s, Register Offset: %s%s" % (node.fun_name, node.local_offset,
                     " (%s)" % node.var_name if node.var_name else "")]
            prefix = "   "
        else:
            lines = ["%s└─ Function: %s, Register Offset: %s (arg %s%s)" % (prefix, node.fun_name, node.local_offset,
                     node.callee_arg_idx, ", %s" % node.var_name if node.var_name else "")]
        for child in node.children:
            lines += self.format_tree(child, prefix + "   ")
        return lines

    def print_tree(self):
        print("\n".join(self.format_tree()))

    def find_parent(self, child_node, find_root=False):
        """The root (find_root) or the parent node of child_node; None if it is not in the tree."""
        if find_root:
            return self.root
        for node in self.nodes():
            if child_node in node.children:
                return node
        return None

    def find_nodes(self, fun_name, local_offset):
        """Every node of the tree for (fun_name, local_offset)."""
        return [n for n in self.nodes() if n.fun_name == fun_name and n.local_offset == local_offset]

    def find_node_by_fun_name_and_offset(self, fun_name, local_offset, node=None):
        found = self.find_nodes(fun_name, local_offset)
        return found[0] if found else None

    def has_children(self):
        return self.root is not None and len(self.root.children) > 0

    def is_subtree(self, subtrees):
        """Whether this tree is a branch of one of the given trees (its root is an inner node there
        with the same descendants)."""
        if not isinstance(subtrees, list):
            subtrees = [subtrees]
        mine = self.root.key()
        return any(n is not t.root and n.key() == mine for t in subtrees for n in t.nodes())

def compare_trees(tree1, tree2):
    """Compares two PtrOffsetTree instances to check if they are equivalent."""
    return tree1.root.key() == tree2.root.key()

def add_tree_if_unique(tree_list, new_tree):
    for existing_tree in tree_list:
        if compare_trees(existing_tree, new_tree):
            return False
    tree_list.append(new_tree)
    return True

@dataclass
class CallSite:
    """A call in a function to a function defined in the binary, with the frame offset (and
    whether it is the address, ptr_ref) of each argument the call passes."""
    callee_name: str
    address: int
    operands: List[OperandData] = field(default_factory=list)

last_summaries = list()

class BinTaintAnalysis:
    ptr_trees = list()
    callee_funs_op_info = dict()
    fun_to_check = list()
    fun_param_info = set(())
    
    def __init__(self, bv, taint_src_funs, dwarf_info, analysis_list):
        self.bv = bv
        self.analysis_list = analysis_list
        self.fun = None
        self.currFunNode = FunctionNode(None, None)
        self.rootFun = None
        self.currFun = None
        self.taint_list = list()
        self.taint_funs = taint_src_funs
        self.taint_var = None
        self.taint_inst = None
        self.dwarf_info = dwarf_info
        self.fun_set = set()
        self.fun_graph = list()
            
    def extract_offset(self, operand: str) -> int:
        """
        Extracts the offset from a string like '-4(%rbp)'.

        Args:
        - operand: The operand string to extract the offset from.

        Returns:
        - The offset as an integer, or None if the pattern does not match.
        """
        try:
            match = re.search(r'([+-]?\d+)\(%rbp\)', operand)
            if match:
                return int(match.group(1))  # Convert the matched offset to an integer
            else:
                return None  # or raise an exception, depending on how you want to handle unmatched cases
        except:
            return None

        
    def calc_ssa_off_expr(self, inst_ssa):
        # This is for binary ninja diassembly
        arrow = 'U+21B3'
        logger.info("Calculating the offset of %s %s", inst_ssa, type(inst_ssa)) 
        offset_expr_regex = r'(\-[0-9].*)\((.*)\)'
        if type(inst_ssa) == binaryninja.lowlevelil.LowLevelILLoadSsa:
            logger.debug("%s LoadReg", chr(int(arrow[2:], 16)))
            mapped_MLLIL = inst_ssa.mapped_medium_level_il # This is done to get the var (or find if not)
            if mapped_MLLIL != None:
                result = self.calc_ssa_off_expr(inst_ssa.src)
                if result != None:
                    return result
            else:
                logger.error("No variable assigned, skip")
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILStoreSsa:
            logger.debug("%s StoreSSA",  chr(int(arrow[2:], 16)))
            result = self.calc_ssa_off_expr(inst_ssa.dest)
            if result != None:
                return result
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILSetRegSsa:
            logger.debug("%s SetRegSSA",  chr(int(arrow[2:], 16)))
            result = self.calc_ssa_off_expr(inst_ssa.src)
            if result != None:
                return result
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILSetRegSsaPartial:
            logger.debug("%s SetRegSSAPartial",  chr(int(arrow[2:], 16)))
            # reg_def = llil_fun.get_ssa_reg_definition(llil_inst.full_reg)
            result = self.calc_ssa_off_expr(inst_ssa.src)
            if result != None:
                return result
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILZx:
            logger.debug("%s ZeroExtendSSA",  chr(int(arrow[2:], 16)))
            result = self.calc_ssa_off_expr(inst_ssa.src)
            if result != None:
                return result
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILSx:
            logger.debug("%s SignExtendSSA",  chr(int(arrow[2:], 16)))
            result = self.calc_ssa_off_expr(inst_ssa.src)
            if result != None:
                return result
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILRegPhi:
            # We do not deal with PHI which has multiple possible values
            logger.debug("%s PhiSSA",  chr(int(arrow[2:], 16)))
            return None
        elif binaryninja.commonil.Arithmetic in inst_ssa.__class__.__bases__:
            logger.debug("%s Arithmetic",  chr(int(arrow[2:], 16)))
            try:
                # Expression
                logger.debug("Expression %s", inst_ssa)
                reg: SSARegister
                reg = inst_ssa.left.src
                if (binaryninja.commonil.Arithmetic in inst_ssa.left.__class__.__bases__ and 
                  type(inst_ssa.right) == binaryninja.lowlevelil.LowLevelILConst):
                    logger.debug("Array access found")
                    base_reg    = inst_ssa.left.left.src.reg.__str__()
                    array_reg   = inst_ssa.left.right.src.reg.__str__()
                    offset      = inst_ssa.right.constant
                    expr = str(offset) + "(" + base_reg + "," + array_reg + ")"
                else:
                    logger.debug("Not array access %s", reg.reg.name)
                    if reg.reg.name != "%rbp":
                        try:
                            reg_defs = self.currFun.llil.ssa_form.get_ssa_reg_definition(reg)
                            logger.warning("Struct access %s", reg_defs)
                            base_offset = self.calc_ssa_off_expr(reg_defs)
                            if base_offset == None:
                                return None
                            base_offset = self.extract_offset(base_offset)
                            logger.debug("Base offset: %d", base_offset)
                            new_offset = base_offset + int(inst_ssa.right.constant)
                            expr = str(new_offset) + "(" + "%rbp" + ")" 
                            # exit() 
                        except Exception as e:
                            print(e)
                            logger.error("Can't find the definition")
                    else:
                        # logger.debug("Return offset")
                        offset = str(int(inst_ssa.right.__str__(), base=16))
                        expr = offset + "(" + reg.reg.__str__() + ")"
                # reg = inst_ssa.left.src
            except:
                # Single register
                reg = inst_ssa.left
            # if (binaryninja.commonil.Arithmetic in inst_ssa.left.__class__.__bases__ and 
            #       type(inst_ssa.right) == binaryninja.lowlevelil.LowLevelILConst):
            #     print("Array access found")
            #     base_reg    = inst_ssa.left.left.src.reg.__str__()
            #     array_reg   = inst_ssa.left.right.src.reg.__str__()
            #     offset      = inst_ssa.right.constant
            #     expr = str(offset) + "(" + base_reg + "," + array_reg + ")"
            # else:
            #     try:
            #     # print(inst_ssa.right, type(inst_ssa.right))
            #         offset = str(int(inst_ssa.right.__str__(), base=16))
            #         expr = offset + "(" + reg.reg.__str__() + ")"
            #     except:
            #         return None
            
            logger.debug(expr)
            return expr
    
    def get_ssa_reg(self, inst_ssa):
        arrow = 'U+21B3'
        logger.info("Getting the SSA register of %s %s", inst_ssa, type(inst_ssa)) 
        if type(inst_ssa) == binaryninja.lowlevelil.SSARegister:
            return inst_ssa
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILSetRegSsa:
            return self.get_ssa_reg(inst_ssa.src)
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILRegSsa:
            return self.get_ssa_reg(inst_ssa.src)
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILRegSsaPartial:
            return self.get_ssa_reg(inst_ssa.full_reg)
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILLoadSsa:
            logger.debug("%s LoadReg", chr(int(arrow[2:], 16)))
            # return inst_ssa
            return self.get_ssa_reg(inst_ssa.src)
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILZx:
            # print(type(inst_ssa.src))
            try:
                return self.get_ssa_reg(inst_ssa.src.full_reg)
            except:
                # If type is LoadSSA
                return self.get_ssa_reg(inst_ssa.src)
        elif binaryninja.commonil.Arithmetic in inst_ssa.__class__.__bases__:
            # this is where we should handle %rax#3 + 4 orcase;
            if inst_ssa.left.src.reg == "%rbp":
                return None
            else:
                return self.get_ssa_reg(inst_ssa.left.src)
            # return inst_ssa
        else:
            print(inst_ssa.__class__.__bases__)

    # Function to search for a given string and return the string along with its associated numerical value if found
    def search_fun_indx(self, search_str):
        for func_name, value in self.taint_funs:
            if func_name == search_str:
                return value
        return None
    
    def get_or_set_call_node(self, callgraph, function_nodes, function):
        # create a new node if one doesn't exist already
        if function not in function_nodes:
            node = FlowGraphNode(callgraph)

            function_nodes[function] = node

            if function.symbol.type == SymbolType.ImportedFunctionSymbol:
                token_type = InstructionTextTokenType.ImportToken
            else:
                token_type = InstructionTextTokenType.CodeSymbolToken

            # Set the node's text to be the name of the function
            node.lines = [
                DisassemblyTextLine(
                    [
                        InstructionTextToken(
                            token_type,
                            function.name,
                            function.start
                        )
                    ]
                )
            ]
            callgraph.append(node)
        else:
            node = function_nodes[function]

        return node

    def collect_calls(self, view, rootFun):
        logger.info("collect_calls")
        #  dict containing callee -> set(callers)    
        calls = {}
        if (self.rootFun == None):
            funs = view.functions
            logger.debug(funs)
            rootlines = ['ROOT']
        else:
            funs = map(lambda x: x.function, view.get_code_refs(self.rootFun.start))
            rootlines = [self.rootFun.name]
            
        for fun in self.bv.functions:
            for ref in self.bv.get_code_refs(fun.start):
                caller = ref.function
                calls[fun] = calls.get(fun, set())
                call_il = caller.get_low_level_il_at(ref.address)
                if isinstance(call_il, Call) and isinstance(call_il.dest, Constant):
                    calls[fun].add(caller)
        
        callgraph = FlowGraph()
        callgraph.function = view.get_function_at(view.entry_point)
        root_node = FlowGraphNode(callgraph)
        root_node.lines = rootlines
        callgraph.append(root_node)
        function_nodes = {}
    
        for callee in view.functions:
        # create a new node if one doesn't exist already
            callee_node = self.get_or_set_call_node(callgraph, function_nodes, callee)

            # create nodes for the callers, and add edges
            callers = calls.get(callee, set())

            if not callers:
                root_node.add_outgoing_edge(
                    BranchType.FalseBranch, callee_node
                )
            for caller in callers:
                caller_node = self.get_or_set_call_node(callgraph, function_nodes, caller)

                # Add the edge between the caller and the callee
                if ctypes.addressof(callee_node.handle.contents) not in [
                    ctypes.addressof(edge.target.handle.contents)
                    for edge in caller_node.outgoing_edges]:
                        caller_node.add_outgoing_edge(
                            BranchType.TrueBranch,
                            callee_node
                        )
        callgraph.layout_and_wait()
        return callgraph

    def check_import_fun(self, func_name):
        symbol = self.bv.symbols[func_name]
        if len(symbol) > 1:
            for sym_type in symbol:
                if sym_type.type == SymbolType.ImportedFunctionSymbol:
                    return True
                else:
                    return False
    
    def find_root_fun(self, start_fun):
        # Find the function which has caller to the entry point, this will be the root function
        for func in self.bv.functions:
            func: Function
            if start_fun in func.callers:
                return func
            
    def visit(self, illest, expr, operations):
        # print(illest, expr)
        # print(expr.operation)
        logger.debug(expr)
        # print(operations[expr.operation])
        for field in operations[expr.operation]:
            print(field, getattr(expr, field[0]))
            if field[1] == "expr":
                self.visit(illest, getattr(expr, field[0]), operations)
        illest.add(expr.operation)
    
    def taint_prop_fw(self):
        arrow = 'U+21B3'
        # taint_uses = self.rootFun.mlil.ssa_form.get_ssa_var_uses(self.taint_var)    
        # print(taint_uses, self.taint_list)
        visited = list()
        logger.info("Taint propagation forward")
        # exit()
        while len(self.taint_list) > 0:
            self.taint_inst = self.taint_list.pop()
            if self.taint_inst in visited:
                continue
            elif type(self.taint_inst) == binaryninja.mediumlevelil.SSAVariable:
                logger.debug("%s", self.taint_inst)
                print()
                taint_uses = self.currFun.mlil.ssa_form.get_ssa_var_uses(self.taint_inst)
                for use in taint_uses:
                    use: MediumLevelILInstruction
                    logger.warning("%s", use)
                    logger.warning("%s %s", chr(int(arrow[2:], 16)), use.operation)
                    print()
                    self.taint_list.append(use)
                visited.append(self.taint_inst)
            elif self.taint_inst.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA:
                use_refs = self.currFun.mlil.ssa_form.get_ssa_var_uses(self.taint_inst.dest)
                for ref in use_refs:
                    ref: MediumLevelILInstruction
                    logger.warning("%s", ref)
                    logger.warning("%s %s", chr(int(arrow[2:], 16)), ref.operation)
                    print()
                    self.taint_list.append(ref)
                # Update the taint_var as the taint variable gets propagated.
                self.taint_var = self.taint_inst
                visited.append(self.taint_inst)
            elif self.taint_inst.operation == MediumLevelILOperation.MLIL_CALL_SSA:
                # print(self.taint_var)
                # An indirect call (cp: through a function pointer) has no constant target to follow;
                # its result is still treated as tainted.
                dest = self.taint_inst.dest
                dest_fun = self.bv.get_function_at(dest.constant) if hasattr(dest, "constant") else None
                if dest_fun is None:
                    logger.error("Unresolved call target: %s", dest)
                    if len(self.taint_inst.output) > 0:
                        self.taint_list.append(self.taint_inst.output[0])
                    visited.append(self.taint_inst)
                    continue
                dest_fun_name = dest_fun.name
                
                if self.check_import_fun(dest_fun_name):
                    logger.error("Import fun: %s", dest_fun_name)
                else:
                    fun_param_len = len(self.taint_inst.params)-1
                    # Need to add the function into the function set with proper argument
                    found = False
                    for oper_idx, param in enumerate(self.taint_inst.params):
                        if self.taint_var.dest in param.operands:
                            inner_idx = param.operands.index(self.taint_var.dest)
                            # print(f"Here at operand {oper_idx}, inner idx {inner_idx}")
                            found = True
                            idx = oper_idx
                            break  # Stop searching after the first match
                    if not found:
                        print("Element not found")
                    else:
                        print("Inserting: ", type(dest_fun), idx)
                        self.fun_param_info.add((dest_fun, fun_param_len))
                        self.fun_set.add((dest_fun, idx))
                    logger.critical("Fun to visit: %s", dest_fun_name)
                print()
                
                if dest_fun_name in self.taint_funs:
                    logger.error("Danger fun found")                   
                else:
                    # IF output register exists for the call inst (i.e., var = atoi)
                    if len(self.taint_inst.output) > 0:
                        # logger.warning("Inserting %s", self.taint_inst.output[0])
                        self.taint_list.append(self.taint_inst.output[0])
                visited.append(self.taint_inst)
            elif self.taint_inst.operation == MediumLevelILOperation.MLIL_VAR_PHI:
                # var_c#4 = ϕ(var_c#1, var_c#2, var_c#3) 
                # logger.debug(self.taint_inst.dest)
                use_refs = self.currFun.mlil.ssa_form.get_ssa_var_uses(self.taint_inst.dest)
                for ref in use_refs:
                    ref: MediumLevelILInstruction
                    logger.warning("%s", ref)
                    logger.warning("%s %s", chr(int(arrow[2:], 16)), ref.operation)
                    print()
                    self.taint_list.append(ref)
                visited.append(self.taint_inst)
            elif self.taint_inst.operation == MediumLevelILOperation.MLIL_ADDRESS_OF:
                # This is because mlil_fun.get_var_uses cannot be used for address of variable taken
                logger.debug("Search through address of variable uses")
                for bb in self.currFun.mlil.ssa_form:
                    for inst in bb:
                        # logger.debug("%s %s", self.taint_inst, inst)
                        self.taint_inst.vars_address_taken[0]
                        if len(inst.vars_address_taken) > 0:
                            if self.taint_inst.src == inst.vars_address_taken[0]:
                                # logger.critical(inst)
                                self.taint_list.append(inst)
            elif self.taint_inst.operation == MediumLevelILOperation.MLIL_IF:
                # May need to revamp this part.
                # print()
                visited.append(self.taint_inst)
            elif self.taint_inst.operation == MediumLevelILOperation.MLIL_RET:
                visited.append(self.taint_inst)
            elif self.taint_inst.operation == MediumLevelILOperation.MLIL_STORE_SSA:
                visited.append(self.taint_inst)
            elif self.taint_inst.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD:
                visited.append(self.taint_inst)
            elif self.taint_inst.operation == MediumLevelILOperation.MLIL_JUMP_TO:
                visited.append(self.taint_inst)
            else:
                logger.error("Not taken consideration")
                logger.debug("%s %s", self.taint_inst.operation, self.taint_inst)
                exit()
                
                # self.taint_list.append(inst)
                # exit()
                
    def taint_prop_bw(self):
        arrow = 'U+21B3'
        logger.info("Taint propagation backward")
        for op in self.currFunNode.operands:
            ssa_reg = self.get_ssa_reg(op.taint_inst)
            logger.warning("%s %s", op.taint_inst, ssa_reg)
            if ssa_reg == None:
                # this means we don't need to find the definition
                offset = self.calc_ssa_off_expr(op.taint_inst)
                op.offset = self.extract_offset(offset)
            else:
                taint_defs = self.currFun.llil.ssa_form.get_ssa_reg_definition(ssa_reg)  
                offset = self.calc_ssa_off_expr(taint_defs)
                op.offset = self.extract_offset(offset)
            logger.debug(op)
        
    
    def dwarf_fun_analysis(self, fun_name):
        for fun in self.dwarf_info:
            # print(fun, fun_name)
            if fun == fun_name:
                logger.critical("Found")
                temp_list = list()
                temp_list = self.dwarf_info[fun].copy()
                return temp_list
                # temp_list = self.dwarf_info[fun].var_list.copy()
                # return temp_list
    
    def fun_taint_analysis(self, fun, oper_idx):
        # First need to convert arg# to ssa variable
        fun: Function
        self.currFun = fun
        for index, param in enumerate(fun.parameter_vars): 
            if index == oper_idx:
                # print(param, type(param))
                self.taint_var = param
        
        for bb in fun.medium_level_il:
            for inst in bb:
                try:
                    if self.taint_var == inst.src.vars_read[0]:
                        self.taint_var = inst.ssa_form.dest
                        break
                except:
                    pass
        # If taint variable is established by then, insert it into taint list
        if self.taint_var != None:
            print(self.taint_var)
            self.taint_list.append(self.taint_var)
        # exit()
        self.taint_prop_fw()
    
    # ---- Function trees (Algorithm 1) and pointer offset trees (Algorithm 2) ----
    # Each function is analysed once (its summary: DWARF parameters and locals, and per call to a
    # function defined in the binary what each argument is), and the trees are built from the
    # summaries. The call tree is not unrolled per call site: a program like ls calls hundreds of
    # functions from main, and a recursive call would unroll forever.
    #
    # An argument creates an alias edge only when it IS the address of a frame object: a lea of
    # the object (plus a constant), or the value of a variable that holds such an address (a
    # callee's spilled pointer parameter, passed on; a local pointer whose only assignment is a
    # lea). A value loaded through a pointer (foo(p->field)) or computed otherwise is not an alias
    # of anything in the frame.
    call_ops = (MediumLevelILOperation.MLIL_CALL_SSA, MediumLevelILOperation.MLIL_CALL_UNTYPED_SSA,
                MediumLevelILOperation.MLIL_TAILCALL_SSA, MediumLevelILOperation.MLIL_TAILCALL_UNTYPED_SSA)
    max_tree_nodes = 5000
    max_resolve_steps = 20000

    def stack_var_offset(self, var):
        """%rbp displacement of a Binary Ninja stack variable: its storage is relative to the entry
        %rsp, and the -O0 prologue pushes %rbp (%rbp = entry %rsp - 8)."""
        try:
            if var.source_type == VariableSourceType.StackVariableSourceType:
                return var.storage + 8
        except Exception:
            pass
        return None

    def mlil_source(self, fun, expr):
        """What an MLIL value is: ('addr', d) the address of frame byte d (lea d(%rbp), plus a
        constant), ('value', d) the value of the frame variable at d (a pointer read from the
        frame, unchanged), or (None, None) for anything else (a load through a pointer, a call's
        result, arithmetic on a value)."""
        mlil_ssa = fun.mlil.ssa_form
        add = 0
        for _ in range(32):
            if isinstance(expr, binaryninja.mediumlevelil.SSAVariable):
                # (an untyped call's arguments are the argument registers themselves)
                off = self.stack_var_offset(expr.var)
                if off is not None:
                    return ('value', off) if add == 0 else (None, None)
                var_def = mlil_ssa.get_ssa_var_definition(expr)
                if var_def is None or var_def.operation != MediumLevelILOperation.MLIL_SET_VAR_SSA:
                    return (None, None)
                expr = var_def.src
                continue
            op = expr.operation
            if op == MediumLevelILOperation.MLIL_ADDRESS_OF:
                off = self.stack_var_offset(expr.src)
                return ('addr', off + add) if off is not None else (None, None)
            if op == MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD:
                off = self.stack_var_offset(expr.src)
                return ('addr', off + expr.offset + add) if off is not None else (None, None)
            if add == 0 and op in (MediumLevelILOperation.MLIL_VAR_ALIASED, MediumLevelILOperation.MLIL_VAR_ALIASED_FIELD):
                off = self.stack_var_offset(expr.src.var)
                return ('value', off + getattr(expr, "offset", 0)) if off is not None else (None, None)
            if op == MediumLevelILOperation.MLIL_VAR_SSA:
                off = self.stack_var_offset(expr.src.var)
                if off is not None:
                    # (a pointer read from the frame plus a constant is not the variable's value)
                    return ('value', off) if add == 0 else (None, None)
                var_def = mlil_ssa.get_ssa_var_definition(expr.src)
                if var_def is None or var_def.operation != MediumLevelILOperation.MLIL_SET_VAR_SSA:
                    return (None, None)
                expr = var_def.src
                continue
            if op in (MediumLevelILOperation.MLIL_ADD, MediumLevelILOperation.MLIL_SUB):
                left, right = expr.left, expr.right
                if right.operation == MediumLevelILOperation.MLIL_CONST:
                    add += right.constant if op == MediumLevelILOperation.MLIL_ADD else -right.constant
                    expr = left
                    continue
                if op == MediumLevelILOperation.MLIL_ADD and left.operation == MediumLevelILOperation.MLIL_CONST:
                    add += left.constant
                    expr = right
                    continue
                return (None, None)
            # (MLIL_LOAD and everything else: not a frame address)
            return (None, None)
        return (None, None)

    def var_location(self, var):
        """("reg", full register name) or ("stack", d above the entry %rsp) of a Binary Ninja
        variable, None for anything else."""
        try:
            if var.source_type == VariableSourceType.RegisterVariableSourceType:
                name = self.bv.arch.get_reg_name(var.storage)
                return ("reg", str(self.bv.arch.regs[name].full_width_reg).lstrip("%"))   # (AT&T names: %rdi)
            if var.source_type == VariableSourceType.StackVariableSourceType:
                return ("stack", var.storage)
        except Exception:
            pass
        return None

    def call_arguments(self, fun, callee, mlil):
        """([(DWARF parameter index, MLIL argument)], {indices of the DWARF pointer parameters whose
        argument is not found}) of a call. An argument is matched to a parameter by where it is
        passed: the register or stack slot of the parameter's SysV classification (param_locs,
        which counts a hidden struct-return pointer in %rdi) against the location of Binary Ninja's
        argument. Binary Ninja numbers the arguments by its own idea of the callee's type, so a
        float, a long double or a by-value struct before a pointer puts the indices out of step."""
        dwarf = self.summary(callee.name)
        if dwarf is None:
            return [], set()
        pointers = {p.param_idx for p in dwarf.params if p.pointer}
        locs = self.param_locs.get(callee.name)
        if locs is None or len(locs) != len(dwarf.params):
            return [], pointers
        params = list(mlil.params)
        where = dict()
        if mlil.operation in (MediumLevelILOperation.MLIL_CALL_UNTYPED_SSA, MediumLevelILOperation.MLIL_TAILCALL_UNTYPED_SSA):
            # (an untyped call's arguments are the argument registers themselves)
            for p in params:
                var = p.var if isinstance(p, binaryninja.mediumlevelil.SSAVariable) else \
                    (p.src.var if getattr(p, "operation", None) == MediumLevelILOperation.MLIL_VAR_SSA else None)
                loc = self.var_location(var) if var is not None else None
                if loc is not None and loc[0] == "reg":
                    where[loc] = p
        else:
            try:
                adjusted = fun.get_call_type_adjustment(mlil.address) is not None
            except Exception:
                adjusted = False
            pvars = list(callee.parameter_vars) if not adjusted else []
            if len(pvars) == len(params):
                for var, p in zip(pvars, params):
                    loc = self.var_location(var)
                    if loc is not None:
                        where.setdefault(loc, p)
        out, missing = [], set()
        for i, loc in enumerate(locs):
            if loc is not None and loc[0] in ("reg", "stack") and loc in where:
                out.append((i, where[loc]))
            elif i in pointers:
                missing.add(i)
        return out, missing

    def summary(self, name):
        """FunctionNode of a function with DWARF information: params, local_vars, calls."""
        if name in self.summaries:
            return self.summaries[name]
        self.summaries[name] = None
        var_list = self.dwarf_info.get(name) if self.dwarf_info else None
        fun = self.funs_by_name.get(name)
        if var_list is None or fun is None:
            return None
        node = FunctionNode(fun=fun, function_name=name)
        node.objects = []       # (start, end, name, is pointer variable) of every frame variable
        self.summaries[name] = node     # (before its calls: a recursive call finds it)
        for var in var_list:
            offset = int(var.offset) if var.offset_expr is not None and var.offset is not None else None
            if var.tag == "DW_TAG_formal_parameter":
                node.params.append(LocalData(var.name, len(node.params), offset, bool(var.ptr)))
            elif var.tag == "DW_TAG_variable" and offset is not None:
                node.local_vars.append(LocalData(var.name, None, offset, bool(var.ptr)))
            if offset is not None and var.tag in ("DW_TAG_formal_parameter", "DW_TAG_variable"):
                size = int(var.struct.size) if var.struct is not None and getattr(var.struct, "size", None) else int(var.size or 8)
                node.objects.append((offset, offset + size, var.name, bool(var.ptr)))
        for ref in fun.call_sites:
            try:
                llil = fun.get_low_level_il_at(ref.address)
                mlil = llil.mlil if llil is not None else None
                if mlil is None or mlil.ssa_form.operation not in self.call_ops:
                    continue
                mlil = mlil.ssa_form
                dest = mlil.dest
                if not hasattr(dest, "constant"):
                    continue        # an indirect call: no tree follows it
                callee = self.bv.get_function_at(dest.constant)
                if callee is None or callee.symbol.type == SymbolType.ImportedFunctionSymbol:
                    continue
                site = CallSite(callee.name, ref.address)
                args, site.unmapped = self.call_arguments(fun, callee, mlil)
                for idx, param in args:
                    kind, offset = self.mlil_source(fun, param)
                    if kind is not None:
                        site.operands.append(OperandData(callee.name, idx, None, offset, kind == 'addr'))
                node.calls.append(site)
            except Exception as err:
                logger.error("%s: call at %#x not analysed: %s", name, ref.address, err)
        return node

    def frame_object(self, node, addr):
        """(start, name) of the frame variable whose bytes hold addr (the innermost: a member's
        struct is the whole variable, since DWARF lists only variables); None if none does."""
        best = None
        for start, end, var_name, _ in node.objects:
            if start <= addr < end and (best is None or end - start < best[2]):
                best = (start, var_name, end - start)
        return (best[0], best[1]) if best else None

    def pointer_target(self, node, offset):
        """The frame address a local pointer variable at offset holds: its only assignment is the
        address of a frame object (struct stat st; struct stat *sbuf = &st), and its own address
        is never taken (nothing else can write it). None otherwise."""
        key = (node.function_name, offset)
        if key not in self.pointer_targets:
            self.pointer_targets[key] = self.find_pointer_target(node, offset)
        return self.pointer_targets[key]

    def find_pointer_target(self, node, offset):
        fun = node.fun
        targets = []
        for block in fun.mlil.ssa_form:
            for inst in block:
                if inst.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA:
                    if self.stack_var_offset(inst.dest.var) == offset:
                        targets.append(self.mlil_source(fun, inst.src))
                elif inst.operation in (MediumLevelILOperation.MLIL_SET_VAR_ALIASED, MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD,
                                        MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD, MediumLevelILOperation.MLIL_SET_VAR_SPLIT_SSA):
                    dests = inst.vars_written if hasattr(inst, "vars_written") else []
                    if any(self.stack_var_offset(getattr(v, "var", v)) == offset for v in dests):
                        return None
                for v in getattr(inst, "vars_address_taken", []) or []:
                    if self.stack_var_offset(getattr(v, "var", v)) == offset:
                        return None
        if len(targets) == 1 and targets[0][0] == 'addr':
            return targets[0][1]
        return None

    def param_unchanged(self, node, offset):
        """Whether the parameter spilled at offset points into the caller's object wherever it is
        read: its frame slot is written only by the prologue's spill of an incoming register (a
        stack parameter: never written) and by stepping it from its own value (p++, p += n: in C
        the result is in the same object), and its address is never taken. A parameter reassigned
        before a call (p = loc; sink(p)) passes something other than what the callers passed."""
        key = (node.function_name, offset)
        if key not in self.unchanged:
            self.unchanged[key] = self.find_param_unchanged(node, offset)
        return self.unchanged[key]

    def find_param_unchanged(self, node, offset):
        defs = []
        for block in node.fun.mlil.ssa_form:
            for inst in block:
                if inst.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA:
                    if self.stack_var_offset(inst.dest.var) == offset:
                        defs.append(inst.src)
                elif inst.operation in (MediumLevelILOperation.MLIL_SET_VAR_ALIASED, MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD,
                                        MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD, MediumLevelILOperation.MLIL_SET_VAR_SPLIT_SSA):
                    dests = inst.vars_written if hasattr(inst, "vars_written") else []
                    if any(self.stack_var_offset(getattr(v, "var", v)) == offset for v in dests):
                        return False
                for v in getattr(inst, "vars_address_taken", []) or []:
                    if self.stack_var_offset(getattr(v, "var", v)) == offset:
                        return False
        spills = [d for d in defs if not self.steps_self(node.fun, d, offset)]
        if offset > 0:
            return not spills
        if len(spills) != 1 or spills[0].operation != MediumLevelILOperation.MLIL_VAR_SSA:
            return False
        src = spills[0].src
        return src.version == 0 and src.var.source_type == VariableSourceType.RegisterVariableSourceType

    def steps_self(self, fun, expr, offset):
        """Whether expr is the frame variable at offset plus or minus an integer (no address
        of a frame variable in it), through register copies."""
        mlil_ssa = fun.mlil.ssa_form
        def reads_self(e):
            for _ in range(16):
                if e.operation != MediumLevelILOperation.MLIL_VAR_SSA:
                    return False
                if self.stack_var_offset(e.src.var) == offset:
                    return True
                if self.stack_var_offset(e.src.var) is not None:
                    return False
                d = mlil_ssa.get_ssa_var_definition(e.src)
                if d is None or d.operation != MediumLevelILOperation.MLIL_SET_VAR_SSA:
                    return False
                e = d.src
            return False
        def no_address(e):
            if e.operation in (MediumLevelILOperation.MLIL_ADDRESS_OF, MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD):
                return False
            return all(no_address(o) for o in e.operands if isinstance(o, binaryninja.mediumlevelil.MediumLevelILInstruction))
        for _ in range(16):
            if expr.operation == MediumLevelILOperation.MLIL_VAR_SSA and self.stack_var_offset(expr.src.var) is None:
                d = mlil_ssa.get_ssa_var_definition(expr.src)
                if d is None or d.operation != MediumLevelILOperation.MLIL_SET_VAR_SSA:
                    return False
                expr = d.src
                continue
            break
        if expr.operation == MediumLevelILOperation.MLIL_ADD:
            return (reads_self(expr.left) and no_address(expr.right)) or (reads_self(expr.right) and no_address(expr.left))
        if expr.operation == MediumLevelILOperation.MLIL_SUB:
            return reads_self(expr.left) and no_address(expr.right)
        return False

    def arg_root(self, node, kind, offset):
        """The frame object a caller passes: ('object', (fun, start, name)) for an object's address,
        ('param', index) for a pointer parameter of node's function that it passes on, or
        ('none', why)."""
        if kind == 'addr':
            obj = self.frame_object(node, offset)
            if obj is None:
                return ('none', "address %d is no frame variable of %s" % (offset, node.function_name))
            return ('object', (node.function_name, obj[0], obj[1]))
        for p in node.params:
            if p.offset == offset:
                if not p.pointer:
                    return ('none', "%s passes its non-pointer parameter %s" % (node.function_name, p.var_name))
                if not self.param_unchanged(node, offset):
                    return ('none', "%s passes its parameter %s, which it may have reassigned" % (node.function_name, p.var_name))
                return ('param', p.param_idx)
        for v in node.local_vars:
            if v.offset == offset:
                target = self.pointer_target(node, offset) if v.pointer else None
                if target is None:
                    return ('none', "%s passes %s, a pointer not set from one frame address" % (node.function_name, v.var_name))
                return self.arg_root(node, 'addr', target)
        return ('none', "%s passes the value at %d (no DWARF variable)" % (node.function_name, offset))

    def resolve_param(self, fun_name, idx, active=None, steps=None):
        """Every caller object that the pointer parameter idx of fun_name can point to, over all
        calls of fun_name in the program (and, through parameters passed on, their callers):
        ('ok', {(fun, start, name)}) or ('fail', why) when some call passes anything else, or the
        function can be reached other than by a direct call (its address is taken)."""
        top = active is None
        active = active if active is not None else set()
        steps = steps if steps is not None else [self.max_resolve_steps]
        key = (fun_name, idx)
        if key in self.resolved:
            return self.resolved[key]
        if key in active:
            return ('ok', set(), True)      # a recursive pass-through adds no object
        steps[0] -= 1
        if steps[0] < 0:
            return ('fail', "too many callers to follow")
        node = self.summary(fun_name)
        if node is None or idx >= len(node.params) or not node.params[idx].pointer:
            return ('fail', "%s parameter %d is not a pointer with DWARF" % (fun_name, idx))
        # (reassigned, it points to something else afterwards: its own slot must stay)
        if node.params[idx].offset is None or not self.param_unchanged(node, node.params[idx].offset):
            return self.memo(key, ('fail', "%s may reassign its parameter %s" % (fun_name, node.params[idx].var_name)))
        fun = node.fun
        if list(self.bv.get_data_refs(fun.start)):
            return self.memo(key, ('fail', "the address of %s is stored in data (indirect calls)" % fun_name))
        refs = list(self.bv.get_code_refs(fun.start))
        if not refs:
            return self.memo(key, ('fail', "%s has no direct caller in the program" % fun_name))
        active.add(key)
        roots, partial = set(), False
        result = None
        for ref in refs:
            caller = ref.function
            site = None
            cnode = self.summary(caller.name) if caller is not None else None
            if cnode is not None:
                site = next((s for s in cnode.calls if s.address == ref.address and s.callee_name == fun_name), None)
            if site is None:
                result = ('fail', "%s is referenced at %#x other than by a direct call from a function with DWARF" % (fun_name, ref.address))
                break
            if idx in site.unmapped:
                result = ('fail', "call of %s at %#x: no argument passed where its DWARF parameter %d goes" % (fun_name, ref.address, idx))
                break
            op = next((o for o in site.operands if o.oper_idx == idx), None)
            if op is None:
                result = ('fail', "call of %s at %#x passes no frame address" % (fun_name, ref.address))
                break
            what, val = self.arg_root(cnode, 'addr' if op.ptr_ref else 'value', op.offset)
            if what == 'object':
                roots.add(val)
            elif what == 'param':
                sub = self.resolve_param(caller.name, val, active, steps)
                if sub[0] == 'fail':
                    result = sub
                    break
                roots |= sub[1]
                partial = partial or (len(sub) > 2 and sub[2])
            else:
                result = ('fail', "call of %s at %#x: %s" % (fun_name, ref.address, val))
                break
        active.discard(key)
        if result is not None:
            return self.memo(key, result)
        if partial and not top:
            return ('ok', roots, True)      # (not final while a caller on the cycle is open)
        return self.memo(key, ('ok', roots))

    def memo(self, key, result):
        if result[0] == 'fail' or len(result) == 2:
            self.resolved[key] = result
        return result

    def pop_ptr_tree(self, parent, callee_name, arg_idx, path, budget):
        """Pop_Ptr_Tree: the callee's pointer parameter at arg_idx becomes a child of parent, and
        every call that passes that parameter's value on (to a pointer parameter) extends it (a
        recursive chain stops)."""
        callee = self.summary(callee_name)
        if callee is None or arg_idx >= len(callee.params) or callee.params[arg_idx].offset is None \
                or not callee.params[arg_idx].pointer:
            return
        param = callee.params[arg_idx]
        node = next((c for c in parent.children if c.fun_name == callee_name and c.local_offset == param.offset), None)
        if node is None:
            if budget[0] <= 0:
                return
            budget[0] -= 1
            node = parent.add_child(PtrOffsetTreeNode(callee_name, param.offset, arg_idx, param.var_name))
        key = (callee_name, param.offset)
        if key in path:
            return
        for site in callee.calls:
            for operand in site.operands:
                if operand.offset == param.offset and not operand.ptr_ref and self.param_unchanged(callee, param.offset):
                    self.pop_ptr_tree(node, site.callee_name, operand.oper_idx, path | {key}, budget)

    def analyze_offset(self, lift_candidates=()):
        """Gen_Fun_Trees and Gen_Ptr_Offset_Trees from every function in analysis_list, and the
        caller objects of each (function, parameter index) in lift_candidates (resolve_param)."""
        logger.info("Analyze offset")
        self.summaries = dict()
        self.resolved = dict()
        self.pointer_targets = dict()
        self.unchanged = dict()
        self.funs_by_name = dict()
        duplicate = set()
        for fun in self.bv.functions:
            if fun.name in self.funs_by_name:
                duplicate.add(fun.name)
            self.funs_by_name[fun.name] = fun
        for name in duplicate:      # (two static functions of one name: which one a tree means is unknown)
            logger.warning("Two functions named %s: no tree goes through it", name)
            del self.funs_by_name[name]
        roots = dict()              # (function, object start) -> root node
        for fun_name in dict.fromkeys(self.analysis_list):
            root_fun = self.summary(fun_name) if fun_name != '' else None
            if root_fun is None:
                continue
            for site in root_fun.calls:
                for operand in site.operands:
                    # Algorithm 2, line 17: the address of a local object (a member's address roots
                    # at the object); line 15: a local pointer's value, followed to the frame
                    # object it holds (T4); a pointer to anything else roots nothing.
                    if any(p.offset == operand.offset for p in root_fun.params) and not operand.ptr_ref:
                        continue    # (a parameter passed on: its tree starts in a caller)
                    what, val = self.arg_root(root_fun, 'addr' if operand.ptr_ref else 'value', operand.offset)
                    if what != 'object':
                        continue
                    _, start, var_name = val
                    via = None
                    if not operand.ptr_ref:
                        via = next((v.var_name for v in root_fun.local_vars if v.offset == operand.offset), None)
                    key = (fun_name, start)
                    if key not in roots:
                        roots[key] = PtrOffsetTreeNode(fun_name, start, operand.oper_idx,
                                                       var_name + (" via %s" % via if via else ""))
                    self.pop_ptr_tree(roots[key], site.callee_name, operand.oper_idx, {key}, [self.max_tree_nodes])
        for root in roots.values():
            tree = PtrOffsetTree(root)
            if tree.has_children():
                add_tree_if_unique(self.ptr_trees, tree)
        resolutions = dict()
        for fun_name, idx in lift_candidates:
            res = self.resolve_param(fun_name, idx)
            resolutions[(fun_name, idx)] = (res[0], res[1])
        global last_summaries
        last_summaries = self.format_summaries()
        return self.ptr_trees, resolutions

    def format_summaries(self):
        """Lines describing each analysed function (the function trees' nodes): per call, the
        DWARF parameter index of each argument that is a frame address (&d) or a frame
        variable's value (d)."""
        lines = []
        for name, node in sorted(self.summaries.items()):
            if node is None:
                continue
            lines.append("%s: params %s" % (name, ", ".join("%s@%s%s" % (p.var_name, p.offset, "*" if p.pointer else "")
                                                             for p in node.params) or "-"))
            for site in node.calls:
                ops = ", ".join("%d:%s%s" % (o.oper_idx, "&" if o.ptr_ref else "", o.offset) for o in site.operands
                                if o.offset is not None)
                lines.append("    %#x call %s(%s)%s" % (site.address, site.callee_name, ops,
                                                       "" if not site.unmapped else " [pointer parameter(s) %s: no argument found where they are passed]"
                                                       % ",".join(map(str, sorted(site.unmapped)))))
        return lines

    def analyze_binary(self):
        self.bv: BinaryView
        arrow = 'U+21B3'
        #  dict containing callee -> set(callers)    
        # Extract the first element of each tuple to create a set of function names
        fun_names = {t[0] for t in self.taint_funs}
        calls = {}
        for fun in self.bv.functions:
            for ref in self.bv.get_code_refs(fun.start):
                caller = ref.function
                calls[fun] = calls.get(fun, set())
                call_il = caller.get_low_level_il_at(ref.address)
                if isinstance(call_il, Call) and isinstance(call_il.dest, Constant):
                    calls[fun].add(caller)
                    
        for callee in calls:
            # Need to check available callee functions of all functions in a program, for dangerous functions
            # Put those callers into the list of functions
            if callee.name in fun_names:
                logger.warning(callee.name)    
                for fun in calls[callee]:
                    logger.debug(fun.name)
                    self.fun_to_check.append(fun.name)
            else:
                logger.error("Not in %s", callee.name)
        
        # Get the entry point function
        start_fun = self.bv.get_function_at(self.bv.entry_point)
        start_fun: Function
        
        self.rootFun: Function
        self.rootFun = self.find_root_fun(start_fun)
        self.currFun = self.rootFun
        
        
        # Temporary "graph" set:
        self.bv.get_function_at(self.rootFun.lowest_address)
        
        for index, param in enumerate(self.rootFun.parameter_vars): 
            if param.type is not None and param.type.type_class == TypeClass.PointerTypeClass:
                if param.name == "argv":
                    # print(type(param), index)
                    self.taint_var = param
                    # self.fun_graph.append((self.bv.get_function_at(self.rootFun.lowest_address), index))
                    # exit()
        # To-do: At the moment, we are only considering argv as the taint variable
        for bb in self.rootFun.medium_level_il:
            for inst in bb:
                try:
                    if self.taint_var == inst.src.vars_read[0]:
                        self.taint_var = inst.ssa_form.dest
                        break
                except:
                    pass
        
        
        
        # If taint variable is established by then, insert it into taint list
        if (self.taint_var != None and 
            type(self.taint_var) == binaryninja.mediumlevelil.SSAVariable):
            self.taint_list.append(self.taint_var)
        else:
        # In this case, argv is empty and we need to search for other potential source of taint funs
        # Add sensitive functions creating potential taint sources
            logger.info("Search for sensitive functions")
            for callee_addr in self.rootFun.callee_addresses:
                callee_fun = self.bv.get_function_at(callee_addr).name
                if callee_fun in fun_names:
                    # What if it is multi-source? How to handle this case? Allow multiple taint src var?
                    logger.critical("Track it's taint variable")
                    param_idx = self.search_fun_indx(callee_fun)
                    for ref in self.bv.get_code_refs(callee_addr):
                        # print(hex(ref.address))
                        call_il = self.rootFun.get_low_level_il_at(ref.address)
                        if call_il.mlil.ssa_form.operation == MediumLevelILOperation.MLIL_CALL_SSA:
                            # print(call_il.mlil)
                            for oper_idx, param in enumerate(call_il.mlil.params):
                                # print(type(param.ssa_form))
                                if (type(param.ssa_form) == binaryninja.mediumlevelil.MediumLevelILVarSsa and
                                    oper_idx == param_idx):
                                    var_def = self.rootFun.mlil.ssa_form.get_ssa_var_definition(param.ssa_form.src)
                                    self.taint_var = var_def.src
                                    self.taint_list.append(self.taint_var)
                                    
                                    
        
        
        # custom_pprint(self.mlillest)
        
        print(self.taint_var)
        # exit()
        self.taint_prop_fw()
        # exit()
        index = 0
        # Each (function, operand index) pair is analyzed once. Without this, a recursive callee
        # (coreutils' quotearg_buffer_restyled) re-queues itself at every visit and the loop never ends.
        analyzed = set()
        while len(self.fun_set) > 0 or index < 1:
            index += 1
            target_fun = self.fun_set.pop()
            if target_fun in analyzed:
                continue
            analyzed.add(target_fun)
            print(target_fun[0].name)
            
            # Temporary "graph" set:
            self.fun_graph.append(target_fun)
            print(target_fun[0], "idx: ", target_fun[1])
            # exit()
            self.fun_taint_analysis(target_fun[0], target_fun[1])
            
            
        for fun in self.fun_graph:
            logger.critical("%s: Operand Index: %d", fun[0].name, fun[1])
            
        return self.fun_graph