import sys
import logging
import shutil
import sys
import os
import logging
import pprint

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

def offset_analysis(input_item):
    with load(input_item.__str__(), options={"arch.x86.disassembly.syntax": "AT&T"}) as bv:
        arch = Architecture['x86_64']
        bn = BinAnalysis(bv)
        return bn.gen_offset_rel()

# Creating a separate new binary disassembler as the purpose is a bit different (such as we need to analyze all functions)
def process_new_binary(input_item, analysis_list, target_fun_var_info):
    with load(input_item.__str__(), options={"arch.x86.disassembly.syntax": "AT&T"}) as bv:
        arch = Architecture['x86_64']
        bn = BinAnalysis(bv)
        return bn.analyze_new_binary(analysis_list, target_fun_var_info)
    
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
    
    # def check_import_fun(self, func_name):
    #     symbol = self.bv.symbols[func_name]
    #     # print(symbol)
    #     if len(symbol) > 0:
    #         for sym_type in symbol:
    #             if sym_type.type == SymbolType.ImportedFunctionSymbol:
    #                 return True
    #             else:
    #                 return False
    
    # # This is used to generate offset 
    # def gen_offset_rel(self):
    #     logger.info("Generate offset relationship")
    #     calls = {}
    #     for fun in self.bv.functions:
    #         # We want to ignore import fun
    #         if self.check_import_fun(fun.name) == False:
    #             for ref in self.bv.get_code_refs(fun.start):
    #                 caller = ref.function
    #                 calls[fun] = calls.get(fun, set())
    #                 call_il = caller.get_low_level_il_at(ref.address)
    #                 if isinstance(call_il, Call) and isinstance(call_il.dest, Constant):
    #                     calls[fun].add(caller)
                    
    #     for fun in calls:
    #         logger.info("Callee: %s", fun.name)
    #         if len(calls[fun]) > 0:
    #             for caller in calls[fun]:
    #                 logger.debug("Caller %s", caller)
    
    def analyze_new_binary(self, analysis_list, target_fun_var_info):
        columns, rows = shutil.get_terminal_size(fallback=(80, 20))        
        logger.info("Analyzing new binary")
        
        dis_inst_pattern = r"^\s*(\S+)\s+([^,]+)\s*(?:,\s*(.*))?$"
                
        # Regex to match the start and relevant registers
        rdgs_regex = re.compile(r"rdgsbase %r11")
        start_regex = re.compile(r'test\s+%r11,\s*%r11')
        end_regex   = re.compile(r"xor\s+%r11,\s*%r11")
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
            sorted_fun_addr = list()
            
            if self.fun in analysis_list:
            # if self.fun == "url_decode":
                try:
                    pprint.pprint(target_fun_var_info[self.fun])
                except:
                    None
                # exit()
                for block in func:
                    for inst in block.get_disassembly_text():
                        # print(dis_inst, hex(instruction.address))
                        sorted_fun_addr.append(inst.address)
                sorted_fun_addr.sort()
                in_set = False
                mid_set = False
                current_set = []
                instruction_sets = {}
                key_instruction = None

                for i, addr in enumerate(sorted_fun_addr):
                    # Need to sort first due to unordered basic block addresses
                    dis_inst = self.bv.get_disassembly(addr)
                    if start_regex.search(dis_inst):
                        # print(dis_inst)
                        # Mark the start of a new instruction set and prepare to capture the key instruction on the next line
                        in_set = True
                        if i + 2 < len(sorted_fun_addr):
                            key_instruction = self.bv.get_disassembly(sorted_fun_addr[i + 2])
                            # print(key_instruction, in_set)
                        continue  # Skip adding the jz instruction itself to the sequence
                    elif in_set:
                        # print(dis_inst)
                        # Once the key_instruction is set, start adding instructions to the current set
                        if mid_set:
                            current_set.append(dis_inst)
                        if rdgs_regex.search(dis_inst):
                            mid_set = True
                        if end_regex.search(dis_inst):
                            # End of the current instruction set
                            # Map the collected instructions to the dynamically identified key_instruction
                            if key_instruction:
                                instruction_sets[key_instruction] = "\n".join(current_set)
                            in_set = False  # Reset for the next sequence
                            mid_set = False
                            current_set = []  # Clear the current set for the next sequence
                            key_instruction = None  # Reset key_instruction for the next sequence
                        
                for key_instruction, instruction_set in instruction_sets.items():
                    src_register = None
                    offset_decimal = None
                    offset_regex = r"mov\s+(\%\w+),\s+qword\s+ptr\s+\[%rbp-0x([a-fA-F0-9]+)\]"
                    patch_regex = r"mov\s+(\%\w+),\s+qword ptr \[\%r11\]"
                    offset_match = re.search(offset_regex, key_instruction)
                    if offset_match:
                        logger.info(f"Key Instruction: {key_instruction}")
                        src_register = offset_match.group(1)
                        offset_hex = offset_match.group(2)
                        offset_decimal = -int(offset_hex, 16)  # Convert hex to decimal and negate it to match the example
                    else:
                        logger.error("No match found")
                    
                    
                    instruction_list = instruction_set.split('\n')
                    for inst in instruction_list:
                        inst_match = re.search(patch_regex, inst)
                        if inst_match:
                            logger.debug(inst)
                            if inst_match.group(1) == src_register:
                                logger.debug("POST check the offset: %d", offset_decimal)
                                for var in target_fun_var_info[self.fun]:
                                    if var.offset == offset_decimal:
                                        logger.critical("Offset checked")
                                    
                    # # print("Value (Instruction Set):")
                    # print(instruction_set, type(instruction_set))
                    print("-------------------------------------")
            else:
                for block in func:
                    for inst in block.get_disassembly_text():
                        dis_inst = self.bv.get_disassembly(inst.address)
                        if rdgs_regex.search(dis_inst):
                            log.error("Wrong patch found")
        # for i, inst_set in enumerate(instruction_sets, 1):
        #     print(f"Instruction Set {i}:\n{inst_set}\n")
                    
    # Need debug info to handle static functions
    def analyze_binary(self, analysis_list):
        bn_fun_var_info = dict()
        columns, rows = shutil.get_terminal_size(fallback=(80, 20))        
        logger.info("Analyzing binary")
        debug_fun = "parse_request"
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
                                                if bn_var is not None:  # asm_lex_analysis returns None for unmodelled instructions
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
                                        if bn_var is not None:  # asm_lex_analysis returns None for unmodelled instructions
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
                                    if bn_var is not None:  # asm_lex_analysis returns None for unmodelled instructions
                                        self.bn_var_list.append(bn_var)
                    
            # pprint(self.bn_var_list)
            bn_fun_var_info[self.fun] = self.bn_var_list.copy()
            self.bn_var_list.clear()
        return bn_fun_var_info
                        
                        
    def __init__(self, bv):
        self.bv = bv
        self.fun = None