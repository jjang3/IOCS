import cgitb
import sys, getopt
import logging
import shutil
import pprint
import inspect
import os
import webbrowser
import time

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

import export_cg

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
        bn = BinTaintAnalysis(bv, taint_src_funs)
        return bn.analyze_binary()
        

class BinTaintAnalysis:
    
    fun_to_check = set()
    fun_param_info = set(())
    
    def __init__(self, bv, taint_src_funs):
        self.bv = bv
        self.fun = None
        self.rootFun = None
        self.currFun = None
        self.taint_list = list()
        self.taint_funs = taint_src_funs
        self.taint_var = None
        self.taint_inst = None
        self.fun_set = set()
        self.fun_graph = list()

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
        log.info("collect_calls")
        #  dict containing callee -> set(callers)    
        calls = {}
        if (self.rootFun == None):
            funs = view.functions
            log.debug(funs)
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
        log.debug(expr)
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
        visited = set()   # SSA variables and MLIL instructions are hashable; a list made this quadratic
        log.info("Taint propagation forward")
        while len(self.taint_list) > 0:
            self.taint_inst = self.taint_list.pop()
            if self.taint_inst in visited:
                continue
            elif type(self.taint_inst) == binaryninja.mediumlevelil.SSAVariable:
                log.debug("%s", self.taint_inst)
                print()
                taint_uses = self.currFun.mlil.ssa_form.get_ssa_var_uses(self.taint_inst)
                for use in taint_uses:
                    use: MediumLevelILInstruction
                    log.warning("%s", use)
                    log.warning("%s %s", chr(int(arrow[2:], 16)), use.operation)
                    print()
                    self.taint_list.append(use)
                visited.add(self.taint_inst)
            elif self.taint_inst.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA:
                use_refs = self.currFun.mlil.ssa_form.get_ssa_var_uses(self.taint_inst.dest)
                for ref in use_refs:
                    ref: MediumLevelILInstruction
                    log.warning("%s", ref)
                    log.warning("%s %s", chr(int(arrow[2:], 16)), ref.operation)
                    print()
                    self.taint_list.append(ref)
                # Update the taint_var as the taint variable gets propagated.
                self.taint_var = self.taint_inst
                visited.add(self.taint_inst)
            elif self.taint_inst.operation == MediumLevelILOperation.MLIL_CALL_SSA:
                # print(self.taint_var)
                # An indirect call (cp: through a function pointer) has no constant target to follow;
                # its result is still treated as tainted.
                dest = self.taint_inst.dest
                dest_fun = self.bv.get_function_at(dest.constant) if hasattr(dest, "constant") else None
                if dest_fun is None:
                    log.error("Unresolved call target: %s", dest)
                    if len(self.taint_inst.output) > 0:
                        self.taint_list.append(self.taint_inst.output[0])
                    visited.add(self.taint_inst)
                    continue
                dest_fun_name = dest_fun.name
                
                if self.check_import_fun(dest_fun_name):
                    log.error("Import fun: %s", dest_fun_name)
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
                    log.critical("Fun to visit: %s", dest_fun_name)
                print()
                
                if dest_fun_name in self.taint_funs:
                    log.error("Danger fun found")                   
                else:
                    # IF output register exists for the call inst (i.e., var = atoi)
                    if len(self.taint_inst.output) > 0:
                        # log.warning("Inserting %s", self.taint_inst.output[0])
                        self.taint_list.append(self.taint_inst.output[0])
                visited.add(self.taint_inst)
            elif self.taint_inst.operation == MediumLevelILOperation.MLIL_VAR_PHI:
                # var_c#4 = ϕ(var_c#1, var_c#2, var_c#3) 
                # log.debug(self.taint_inst.dest)
                use_refs = self.currFun.mlil.ssa_form.get_ssa_var_uses(self.taint_inst.dest)
                for ref in use_refs:
                    ref: MediumLevelILInstruction
                    log.warning("%s", ref)
                    log.warning("%s %s", chr(int(arrow[2:], 16)), ref.operation)
                    print()
                    self.taint_list.append(ref)
                visited.add(self.taint_inst)
            elif self.taint_inst.operation == MediumLevelILOperation.MLIL_ADDRESS_OF:
                # This is because mlil_fun.get_var_uses cannot be used for address of variable taken
                log.debug("Search through address of variable uses")
                for bb in self.currFun.mlil.ssa_form:
                    for inst in bb:
                        # log.debug("%s %s", self.taint_inst, inst)
                        self.taint_inst.vars_address_taken[0]
                        if len(inst.vars_address_taken) > 0:
                            if self.taint_inst.src == inst.vars_address_taken[0]:
                                # log.critical(inst)
                                self.taint_list.append(inst)
                
    
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
            # print(self.taint_var)
            self.taint_list.append(self.taint_var)
        self.taint_prop_fw()
    
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
                log.warning(callee.name)    
                for fun in calls[callee]:
                    log.debug(fun.name)
                    self.fun_to_check.add(fun.name)
            else:
                log.error("Not in %s", callee.name)
        
        
                
        # Get the entry point function
        start_fun = self.bv.get_function_at(self.bv.entry_point)
        start_fun: Function
        
        self.rootFun: Function
        self.rootFun = self.find_root_fun(start_fun)
        self.currFun = self.rootFun
        
        
        # Temporary "graph" set:
        self.bv.get_function_at(self.rootFun.lowest_address)
        
        for index, param in enumerate(self.rootFun.parameter_vars): 
            # print(self.rootFun.parameter_vars)
            # exit()
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
            log.info("Search for sensitive functions")
            for callee_addr in self.rootFun.callee_addresses:
                callee_fun = self.bv.get_function_at(callee_addr).name
                if callee_fun in fun_names:
                    # What if it is multi-source? How to handle this case? Allow multiple taint src var?
                    log.critical("Track it's taint variable")
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
        # taint_def = self.rootFun.mlil.ssa_form.get_ssa_var_definition(self.taint_var)
        # log.warning("Taint def: %s", taint_def)
        # First rootFun taint propagation to poulate self.fun_set
        self.taint_prop_fw()
        # Each (function, operand index) pair is analyzed once. Without this, a recursive callee
        # (coreutils' quotearg_buffer_restyled) re-queues itself at every visit and the loop never ends.
        analyzed = set()
        while len(self.fun_set) > 0:
            target_fun = self.fun_set.pop()
            if target_fun in analyzed:
                continue
            analyzed.add(target_fun)
            # Temporary "graph" set:
            self.fun_graph.append(target_fun)

            print(target_fun[0], "idx: ", target_fun[1])
            self.fun_taint_analysis(target_fun[0], target_fun[1])
            
        for fun in self.fun_graph:
            log.critical("%s: Operand Index: %d", fun[0].name, fun[1])
        return self.fun_graph