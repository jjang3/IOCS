import sys
import logging
import shutil
import sys
import os
import logging

# Get the same logger instance. Use __name__ to get a logger with a hierarchical name or a specific string to get the exact same logger.
logger = logging.getLogger('main')

# Add the parent directory to sys.path
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from main import *
from asm_analysis import *

from binaryninja import *
from binaryninja.binaryview import BinaryViewType
from binaryninja.architecture import Architecture, ArchitectureHook
from termcolor import colored

class PatchingInst:
    def __init__(self, inst_type, suffix, src, dest, ptr_op):#, struct_bool):
        self.inst_type = inst_type
        self.suffix = suffix
        self.src = src
        self.dest = dest
        self.ptr_op = ptr_op # This indicates whether ptr access is either src/dest 
        #self.struct = struct_bool # This indicates whether offset that is being accessed here is struct or not
    
    def inst_print(self):
        # print("Inst type: %s | Suffix: %s | Source: %s | Dest: %s" % (self.inst_type, self.suffix, self.src, self.dest))
        info = "Inst type: %s | Suffix: %s | Source: %s | Dest: %s | Ptr: %s" % (self.inst_type, self.suffix, self.src, self.dest, self.ptr_op)
        return info
    def inst_check(self, tgt_inst):
        # print(self.inst_print())
        # print(tgt_inst.inst_print())
        if (self.inst_type == tgt_inst.inst_type):
            if (self.suffix == tgt_inst.suffix):
                if (self.src == tgt_inst.src):
                    if (self.dest == tgt_inst.dest):
                        return True
                # else:
                #     print(self.src, tgt_inst.src)
                #     print(self.src == tgt_inst.src)
        else:
            # logger.debug("%s %s %s %s", 
            #           self.inst_type == tgt_inst.inst_type,
            #           self.suffix == tgt_inst.suffix,
            #           self.src == tgt_inst.src,
            #           self.dest == tgt_inst.dest)
            return False
        
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
        
@dataclass(unsafe_hash=True)
class BnVarData:
    name: str = None
    dis_inst: str = None
    patch_inst: PatchingInst = None
    offset_expr: str = None
    asm_syntax_tree: BnSSAOp = None
    llil_inst: LowLevelILInstruction = None
    arg: bool = None # Whether this bn_var is used for argument or not

@dataclass(unsafe_hash=True)
class BnFunData:
    name: str = None
    begin: int = None
    end: int = None
    vars: list[BnVarData] = None

# Creating a separate new binary disassembler as the purpose is a bit different (such as we need to analyze all functions)
def process_new_binary(input_item, analysis_list):
    with load(input_item.__str__(), options={"arch.x86.disassembly.syntax": "AT&T"}) as bv:
        arch = Architecture['x86_64']
        bn = BinAnalysis(bv)
        return bn.analyze_new_binary(analysis_list)
    
def process_binary(input_item, analysis_list):
    with load(input_item.__str__(), options={"arch.x86.disassembly.syntax": "AT&T"}) as bv:
        arch = Architecture['x86_64']
        bn = BinAnalysis(bv)
        return bn.analyze_binary(analysis_list)    

class BinAnalysis:
    # Binary ninja variable list; list is used to make it stack and remove instructions in orderily fashion
    bn_var_list         = list()
    fun_call_insts      = dict()
    addr_to_llil        = dict()
    
    def find_ssa_reg(self, ssa_form, llil_insts, mlil_fun):
        logger.info("Finding the SSA register among LLIL insts for %s", ssa_form)
        for addr in llil_insts:
            llil_inst = llil_insts[addr]
            # try:
            #     print(llil_inst, mlil_fun.get_ssa_var_uses(llil_inst.mapped_medium_level_il.ssa_form.src))
            # except:
            #     None
            # logger.debug(llil_inst.ssa_form)
    
    # Mark the stack variables that a call argument's defining instruction arg_llil_inst
    # (LLIL SSA, e.g. %rsi#6 = %rbp#1 - 0xb0 {var_b8}) or the one before it passes.
    def mark_arg_def(self, llil_fun, arg_llil_inst):
        try:
            print(arg_llil_inst)
            ssa_reg = self.get_ssa_reg(arg_llil_inst.src.ssa_form)
            logger.debug(ssa_reg)
        # if (type(ssa_reg) != binaryninja.lowlevelil.LowLevelILLoadSsa):
            def_llil_inst = llil_fun.get_ssa_reg_definition(ssa_reg).ssa_form
            for var in self.bn_var_list:
                if arg_llil_inst == var.llil_inst.ssa_form:
                    # %rdx#1 = %rax#3 + 4 {var_c}
                    logger.critical(var.llil_inst.ssa_form)
                    var.arg = True
                    print(var)
                if def_llil_inst == var.llil_inst.ssa_form:
                    #  %rax#3 = %rbp#1 - 8 {var_10}
                    logger.critical(var.llil_inst.ssa_form)
                    var.arg = True
                    print(var)
        # else:
        except:
            def_llil_inst = arg_llil_inst.ssa_form
            for var in self.bn_var_list:
                if def_llil_inst == var.llil_inst.ssa_form:
                    logger.critical(var.llil_inst.ssa_form)
                    var.arg = True

    def get_ssa_reg(self, inst_ssa):
        arrow = 'U+21B3'
        logger.info("Getting the SSA register of %s %s", inst_ssa, type(inst_ssa)) 
        if type(inst_ssa) == binaryninja.lowlevelil.SSARegister:
            return inst_ssa
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILRegSsa:
            return self.get_ssa_reg(inst_ssa.src)
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILRegSsaPartial:
            return self.get_ssa_reg(inst_ssa.full_reg)
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILLoadSsa:
            logger.debug("%s LoadReg", chr(int(arrow[2:], 16)))
            return inst_ssa
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILZx:
            return self.get_ssa_reg(inst_ssa.src.full_reg)
        elif binaryninja.commonil.Arithmetic in inst_ssa.__class__.__bases__:
            # this is where we should handle %rax#3 + 4 case;
            return self.get_ssa_reg(inst_ssa.left.src)
            # return inst_ssa
        else:
            print(inst_ssa.__class__.__bases__)
    
    def analyze_new_binary(self, analysis_list):
        bn_fun_var_info = dict()
        columns, rows = shutil.get_terminal_size(fallback=(80, 20))        
        logger.info("Analyzing new binary")
        
        dis_inst_pattern = r"^\s*(\S+)\s+([^,]+)\s*(?:,\s*(.*))?$"
                
        # Regex to match the start and relevant registers
        start_regex = re.compile(r"rdgsbase %r11")
        register_regex = re.compile(r"%r(11|10|9)")

        # To store the groups of instructions
        instruction_sets = []
        current_set = []
                
        # Flags
        in_set = False
        
        for func in self.bv.functions:
            self.fun = func.name
            llil_fun = func.low_level_il
            addr_range = func.address_ranges[0]
            begin   = addr_range.start
            end     = addr_range.end
            logger.info(self.fun)
            for llil_bb in llil_fun:
                for llil_inst in llil_bb:
                    dis_inst = self.bv.get_disassembly(llil_inst.address)
                    # logger.debug(dis_inst)
                    # print(dis_inst)
                    match = re.match(dis_inst_pattern, dis_inst)
                    if match:
                        opcode = match.group(1)
                        # logger.debug(opcode)
                        if opcode == "rdgsbase":
                            if self.fun not in analysis_list:
                                logger.error("Wrong patch found")
                                None
                            else:
                                logger.critical("Function successfully checked")
                                None
                    if start_regex.search(dis_inst):
                        # Start of a new set
                        in_set = True
                        logger.warning(dis_inst)
                        current_set.append(dis_inst)
                    elif in_set and register_regex.search(dis_inst):
                        # Within a set and line contains one of the registers
                        logger.debug(dis_inst)
                        current_set.append(dis_inst)
                    elif in_set:
                        # Still within a set but no relevant register in this line
                        current_set.append(dis_inst)
                    # If the current set ends with a relevant register, it's considered the last instruction of the set
                    if in_set and ("%r11" in dis_inst or "%r10" in dis_inst or "%r9" in dis_inst):
                        instruction_sets.append("\n".join(current_set))
                        current_set = []
                        in_set = False
                        
                
            # Ensure any remaining instructions are captured if they end the input
            if current_set:
                instruction_sets.append("\n".join(current_set))

            # # Output the instruction sets
            for i, inst_set in enumerate(instruction_sets, 1):
                print(f"Instruction Set {i}:\n{inst_set}\n")            
            
                    
    # Need debug info to handle static functions
    def analyze_binary(self, analysis_list):
        bn_fun_var_info = dict()
        columns, rows = shutil.get_terminal_size(fallback=(80, 20))        
        logger.info("Analyzing binary")
        debug_fun = "sort"
        gen_regs = {"%rax", "%rbx", "%rcx", "%rdx", "%rdi", "%rsi",
            "%eax", "%ebx", "%ecx", "%edx", "%edi", "%esi",
            "%ax",  "%bx",  "%cx",  "%dx",
            "%xmm0", "%xmm1", "%xmm2", "%xmm3",
            "%xmm4", "%xmm5", "%xmm6", "%xmm7",
            "%xmm8", "%xmm9", "%xmm10", "%xmm11",
            "%xmm12", "%xmm13", "%xmm14", "%xmm15"}
        arg_regs = {"%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9",
                    "%ecx", "%edx"}

        for func in self.bv.functions:
            self.fun = func.name
            llil_fun = func.low_level_il

            if self.fun in analysis_list:
                addr_range = func.address_ranges[0]
                begin   = addr_range.start
                end     = addr_range.end
                logger.info("Function: %s\t| begin: %s | end: %s", func.name, hex(begin), hex(end))
                empty_space = ' ' * (columns - 1)
                self.addr_to_llil.clear()
                for llil_bb in llil_fun:
                    if True: 
                    # if self.fun == debug_fun: # Specific function
                        # Making these variable per basic block level
                        arg_idx = 0
                        call_args = 1
                        for llil_inst in llil_bb:
                            self.addr_to_llil[llil_inst.address] = llil_inst
                            # print(llil_inst, llil_inst.operation)
                            mapped_il = llil_inst.mapped_medium_level_il
                            # logger.debug("%s | %s", llil_inst, mapped_il)
                            # if hex(llil_inst.address) == "0xbe27":
                            #     print(llil_inst, llil_inst.operation)
                            #     logger.error("%s | %s", llil_inst, mapped_il)
                                # exit()
                            if llil_inst.operation == LowLevelILOperation.LLIL_SET_REG:
                                # try:
                                #     # Try to catch argument register
                                #     # if llil_inst.dest.name.__str__() in arg_regs and arg_idx < call_args:
                                #     #     # 64-bit arg register
                                #     #     # print("ARG", llil_inst, mapped_il, llil_inst.operation)
                                #     #     logger.debug(llil_inst.ssa_form)
                                #     #     # Determine how many arguments is for a call; Upon reaching call instruction
                                #     #     # this both arg_idx and call_args should reset
                                #     #     call_fun = llil_fun.get_ssa_reg_uses(llil_inst.ssa_form.dest)
                                #     #     call_args = len(llil_fun.high_level_il.params)
                                #     #     # print(call_fun)
                                #     #     arg_idx += 1
                                #     None
                                # except: 
                                    # Else here
                                if len(mapped_il.vars_read) > 0:
                                    print("NON ARG", llil_inst, mapped_il, llil_inst.operation)
                                    var_idx = None
                                    result = any("var" in var.name for var in mapped_il.vars_read)
                                    if result:
                                        for idx, var in enumerate(mapped_il.vars_read):
                                            if "var" in var.name:
                                                var_idx = idx
                                    if var_idx != None:
                                        # temp_var = mapped_il.vars_read[0]
                                        temp_var = mapped_il.vars_read[var_idx]
                                        var_name = temp_var.name
                                        dest_reg = llil_inst.ssa_form.dest
                                        # Avoid RSP registers
                                        try:
                                            if type(dest_reg) == binaryninja.lowlevelil.ILRegister:
                                                reg_name = dest_reg.name
                                            elif type(dest_reg) == binaryninja.lowlevelil.SSARegister:
                                                reg_name = dest_reg.reg.name
                                                
                                            if (temp_var.core_variable.source_type == VariableSourceType.StackVariableSourceType and "var" in var_name 
                                                and reg_name in gen_regs):
                                                bn_var = asm_lex_analysis(self, var_name, llil_fun, llil_inst)
                                                # print(bn_var)
                                                if bn_var is not None:  # fix: asm_lex_analysis returns None for unmodelled instructions
                                                    self.bn_var_list.append(bn_var)
                                            # elif (temp_var.core_variable.source_type == VariableSourceType.StackVariableSourceType and "var" in var_name 
                                            #     and reg_name in gen_regs):
                                            #     # For the case of 16-bit reg like %al
                                            #     bn_var = asm_lex_analysis(var_name, llil_fun, llil_inst)
                                            #     self.bn_var_list.append(bn_var)
                                        except Exception as err:
                                            # print(type(dest_reg))
                                            # print(err)
                                            logger.error(err)
                                            logger.warning("Not the target")
                            # If store -> vars written
                            elif llil_inst.operation == LowLevelILOperation.LLIL_STORE:
                                # if hex(llil_inst.address) == "0xbe27": For debugging
                                #     print(llil_inst, llil_inst.operation)
                                #     logger.error("%s | %s", llil_inst, mapped_il)
                                if len(mapped_il.vars_written) > 0:
                                    # print(llil_inst)
                                    result = any("var" in var.name for var in mapped_il.vars_written)
                                    temp_var = mapped_il.vars_written[0]
                                    var_name = temp_var.name
                                    # Avoid RSP registers
                                    if (temp_var.core_variable.source_type == VariableSourceType.StackVariableSourceType and "var" in var_name):
                                        bn_var = asm_lex_analysis(self, var_name, llil_fun, llil_inst)
                                        if bn_var is not None:  # fix: asm_lex_analysis returns None for unmodelled instructions
                                            self.bn_var_list.append(bn_var)
                                else:
                                    None
                                    # print(llil_inst, llil_inst.operation)
                            elif llil_inst.operation == LowLevelILOperation.LLIL_CALL:
                                # print(llil_inst)
                                call_ops = llil_inst.medium_level_il.operands[2]
                                # Try to implement using llil_inst.medium_level_il.low_level_il.operands[3].operands[0]
                                # <binaryninja.lowlevelil.LowLevelILCallParam object at 0x7fae2098e710>
                                if (llil_inst.address == int(0x56e)):

                                    logger.error("Here")
                                logger.warning("Handling call instruction %s", llil_inst.medium_level_il)
                                print(call_ops)
                                if type(llil_inst.medium_level_il) == binaryninja.mediumlevelil.MediumLevelILCallUntyped:
                                    # Callee without a known signature (cp: do_copy -> copy(..., &copy_into_self)):
                                    # the parameters are the bare argument registers, Variables rather than
                                    # expressions. Mark through the instruction that set each register, which
                                    # is what op.llils[-1] gives for a typed call's MediumLevelILVar below.
                                    mlil_ssa = llil_fun.mlil.ssa_form
                                    for ssa_var in llil_inst.medium_level_il.ssa_form.operands[2]:
                                        def_mlil_inst = mlil_ssa.get_ssa_var_definition(ssa_var)
                                        # None: never set in this function (e.g. %r9#0)
                                        if def_mlil_inst is not None and def_mlil_inst.llil is not None:
                                            self.mark_arg_def(llil_fun, def_mlil_inst.llil.ssa_form)
                                    call_ops = []
                                for op in call_ops:
                                    print(hex(op.address), type(op), op.ssa_form)
                                    if (type(op) == binaryninja.mediumlevelil.MediumLevelILConst or
                                        type(op) == binaryninja.mediumlevelil.MediumLevelILConstPtr):
                                        # %rsi = -1
                                        continue
                                    elif type(op) != binaryninja.mediumlevelil.MediumLevelILVar:
                                        arg_llil_inst = self.addr_to_llil[op.address]
                                        print(arg_llil_inst)
                                        if (arg_llil_inst.operation == LowLevelILOperation.LLIL_CALL and
                                            type(op) == binaryninja.mediumlevelil.MediumLevelILVarField and
                                            op.size < self.bv.arch.address_size):
                                            # Part of an argument register read at the call itself (wc: to_uchar(*p)
                                            # passes %dil), so no instruction of its own: narrower than a pointer,
                                            # it cannot pass a stack variable's address.
                                            continue
                                        ssa_reg = self.get_ssa_reg(arg_llil_inst.src.ssa_form)
                                        logger.debug(ssa_reg)
                                        if type(ssa_reg) != binaryninja.lowlevelil.LowLevelILLoadSsa:
                                            def_llil_inst = llil_fun.get_ssa_reg_definition(ssa_reg).ssa_form
                                            for var in self.bn_var_list:
                                                # print(var.llil_inst.ssa_form)
                                                if def_llil_inst == var.llil_inst.ssa_form:
                                                    var.arg = True
                                        else:
                                            def_llil_inst = arg_llil_inst.ssa_form
                                            for var in self.bn_var_list:
                                                # print(var.llil_inst.ssa_form)
                                                if def_llil_inst == var.llil_inst.ssa_form:
                                                    var.arg = True
                                    elif (type(op) == binaryninja.mediumlevelil.MediumLevelILVar and
                                          len(op.llils) < 1):
                                        # arg4 - ngx_hash_init
                                        ssa_reg = self.find_ssa_reg(op, self.addr_to_llil, llil_fun.mlil)
                                        # inst_var = llil_fun.mlil.get_ssa_var_uses(op.ssa_form.src)
                                        # logger.debug(inst_var)
                                        # exit()
                                    else:
                                        arg_llil_inst = op.llils[len(op.llils)-1].ssa_form
                                        # , self.addr_to_llil
                                        self.mark_arg_def(llil_fun, arg_llil_inst)
                                # exit()
                            else:
                                logger.error("%s, %s", llil_inst, llil_inst.operation)
                                None
                #Control transfer instructions (e.g., cmp) cannot be referenced using the SSA form 
                # due to theta function; hence we use dis_inst for these.
                for bb in func:
                    if True:
                    # if self.fun == debug_fun:
                        dis_bb = bb.get_disassembly_text()
                        for dis_inst in dis_bb:
                            # Check tokens for cmp instruction
                            if dis_inst.tokens[0].text == "cmp":
                                # print("cmp", dis_inst)
                                target = "var"
                                indices = [index for index, token in enumerate(dis_inst.tokens) if target in token.text]
                                if indices:
                                    var_name = dis_inst.tokens[indices[0]]
                                    bn_var = asm_lex_analysis(self, var_name, None, None, self.bv.get_disassembly(dis_inst.address), func)
                                    if bn_var is not None:  # fix: asm_lex_analysis returns None for unmodelled instructions
                                        self.bn_var_list.append(bn_var)
                    
            # pprint(self.bn_var_list)
            bn_fun_var_info[self.fun] = self.bn_var_list.copy()
            self.bn_var_list.clear()
        return bn_fun_var_info
                        
    def __init__(self, bv):
        self.bv = bv
        self.fun = None