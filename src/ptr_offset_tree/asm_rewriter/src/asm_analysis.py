import sys, os
import logging
import shutil
import pprint
import inspect

# Get the same logger instance. Use __name__ to get a logger with a hierarchical name or a specific string to get the exact same logger.
logger = logging.getLogger('main')

# Add the parent directory to sys.path
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from main import *

from binaryninja import *
from binaryninja.binaryview import BinaryViewType
from binaryninja.architecture import Architecture, ArchitectureHook
from termcolor import colored

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

class PatchingInst:
    def __init__(self, inst_type, suffix, src, dest, ptr_op):#, struct_bool):
        self.inst_type = inst_type
        self.suffix = suffix
        self.src = src
        self.dest = dest
        self.ptr_op = ptr_op # This indicates whether ptr access is either src/dest 
        #self.struct = struct_bool # This indicates whether offset that is being accessed here is struct or not
    
    def inst_print(self):
        info = "Inst type: %s | Suffix: %s | Source: %s | Dest: %s | Ptr: %s" % (self.inst_type, self.suffix, self.src, self.dest, self.ptr_op)
        return info
    
    def inst_check(self, tgt_inst):
        if (self.inst_type == tgt_inst.inst_type):
            if (self.suffix == tgt_inst.suffix):
                if (self.src == tgt_inst.src):
                    if (self.dest == tgt_inst.dest):
                        return True
        else:
            return False

@dataclass(unsafe_hash=True)
class BnVarData:
    name: str = None
    dis_inst: str = None
    patch_inst: PatchingInst = None
    offset_expr: str = None
    asm_syntax_tree: BnSSAOp = None
    llil_inst: LowLevelILInstruction = None
    arg: bool = None # Whether this bn_var is used for argument or not
    
def conv_expr(expr):
    print("Converting expression", expr)
    expr_pattern = r"(\b[a-z]+\b)([-|+])(.*)"
    fs_pattern = r"(\b[a-z]+\b):(.*)"
    expr_regex = re.search(expr_pattern, expr)
    fs_regex = re.search(fs_pattern, expr)
    new_expr = str()
    if expr_regex:
        new_expr = expr_regex.group(1) + expr_regex.group(2) + str(int(expr_regex.group(3), 16))
    elif fs_regex:
        new_expr = fs_regex.group(1) + ":" + str(int(fs_regex.group(2), 16))
    print("New expression: ", new_expr)
    return new_expr

def conv_suffix(suffix):
    print("Converting suffix %s", suffix)
    match suffix:
        case "byte ptr":
            return "b" # 8-bit
        case "word ptr":
            return "w" #16-bit
        case "dword ptr":
            return "l" # 32-bit
        case "qword ptr":
            return "q" # 64-bit
    
        
def conv_imm(imm):
    logger.debug("Converting: %s", imm)
    arr_pattern = r"(-\d+)\((%\w+)(?:,(%\w+))?\)"
    arr_regex = re.search(arr_pattern, str(imm))
    imm_pattern = r"(\$)(0x.*)"
    imm_regex = re.search(imm_pattern, imm)
    new_imm = str()
    if imm_regex:
        offset = int(imm_regex.group(2), 16)
        # Binary Ninja prints an immediate unsigned (0xfffffffffffffffe); gcc prints it signed
        # ($-2) for a 32- and 64-bit operand (before: only a few such values were mapped).
        if offset >= 1 << 63:
            offset -= 1 << 64
        elif (1 << 31) <= offset < (1 << 32):
            offset -= 1 << 32
        # print(imm_regex.group(1))
        new_imm = imm_regex.group(1) + str(offset)
        return new_imm
    else:
        return imm
    
 
def parse_ast(ast, depth=0):
    if repr(ast) == 'BnSSAOp':
        parse_ast(ast.left)
        print(ast.op)
        parse_ast(ast.right)
    elif repr(ast) == 'RegNode':
        print(ast.value)

def gen_ast(llil_fun, llil_inst, asm_inst = None):
    if asm_inst == None:
        if type(llil_inst) == binaryninja.lowlevelil.SSARegister:
            # Register
            reg_def = llil_fun.get_ssa_reg_definition(llil_inst)
            if reg_def != None:
                try:
                    # Try to find whether we are dealing with global variable
                    if type(reg_def.src) == binaryninja.lowlevelil.LowLevelILConstPtr:
                        logger.error("Global")
                        return None
                    else:
                        node = RegNode(llil_inst)
                        return node
                except:
                    # If not successful, just create a node based on the instruction
                    node = RegNode(llil_inst)
                    return node    
            else:
                node = RegNode(llil_inst)
                return node
        elif type(llil_inst) == binaryninja.lowlevelil.ILRegister:
            node = RegNode(llil_inst)
            return node
        elif type(llil_inst) == binaryninja.lowlevelil.LowLevelILConst:
            # Const value
            node = RegNode(llil_inst.constant)
            return node
        elif type(llil_inst) == binaryninja.lowlevelil.LowLevelILRegSsa:
            # Register SSA expr
            node = gen_ast(llil_fun, llil_inst.src)
            return node
        elif type(llil_inst) == binaryninja.lowlevelil.LowLevelILRegSsaPartial:
            logger.debug("RegisterSSAPartial")
            reg_def = llil_fun.get_ssa_reg_definition(llil_inst.full_reg)
            if reg_def != None:
                try:
                    # Try to find whether we are dealing with global variable
                    # logger.debug("Reg ref %s", reg_def)
                    if type(reg_def.src) == binaryninja.lowlevelil.LowLevelILConstPtr:
                        logger.error("Global")
                        return None
                    else:
                        # for the case of %rcx#1.%ecx, we just return rcx#1 
                        node = RegNode(llil_inst.full_reg)
                        return node   
                except:
                    # If not successful, just create a node based on the instruction
                    node = RegNode(llil_inst)
                    return node    
        elif type(llil_inst) == binaryninja.lowlevelil.LowLevelILLoadSsa:
            # [%rbp#1 - 0x210 {var_218}].q @ mem#5
            right = gen_ast(llil_fun, llil_inst.src)
            sub_node = BnSSAOp(None, llil_inst.operation, right)
            return sub_node
        elif type(llil_inst) == binaryninja.lowlevelil.LowLevelILZx:
            # zx.q([%rbp#1 - 8 {var_10}].d @ mem#5)
            right = gen_ast(llil_fun, llil_inst.src)
            sub_node = BnSSAOp(None, llil_inst.operation, right)
            return sub_node
        elif type(llil_inst) == binaryninja.lowlevelil.LowLevelILLowPart:
            right = gen_ast(llil_fun, llil_inst.src)
            sub_node = BnSSAOp(None, llil_inst.operation, right)
            return sub_node
        elif isinstance(llil_inst, binaryninja.commonil.Arithmetic) and not hasattr(llil_inst, "left"):
            # Unary arithmetic (neg, not, sx, the float conversions) has one operand, src: a
            # (None, op, src) node like Zx/LowPart, e.g. "negq -24(%rbp)" stores
            # neg.q([%rbp - 0x18].q), "addsd -1064(%rbp), %xmm0" adds fconvert.t([...].q)
            right = gen_ast(llil_fun, llil_inst.src)
            sub_node = BnSSAOp(None, llil_inst.operation, right)
            return sub_node
        elif isinstance(llil_inst, binaryninja.commonil.Arithmetic):
            # Arithmetic operation (also adc/sbb, whose carry flag operand is not a location)
            logger.debug("%s Arithmetic",  llil_inst)
            # .src is used to get SSARegister
            left = gen_ast(llil_fun, llil_inst.left) 
            right = gen_ast(llil_fun, llil_inst.right)
            sub_node = BnSSAOp(left, llil_inst.operation, right)
            return sub_node
        elif isinstance(llil_inst, (binaryninja.lowlevelil.LowLevelILRegStackRelSsa,
                                    binaryninja.lowlevelil.LowLevelILRegStackAbsSsa)):
            # x87 register-stack slot (fstp/fistp store x87#1[0 + %top#1]): a register leaf
            return RegNode(llil_inst)
        elif not isinstance(llil_inst, (binaryninja.lowlevelil.LowLevelILSetReg,
                                        binaryninja.lowlevelil.LowLevelILStore)):
            # Any other operand (flags, intrinsics, ...) is no stack-variable location. Only the
            # instruction itself goes on to its SSA form below: an operand is already SSA.
            logger.debug("%s not modelled: %s", type(llil_inst).__name__, llil_inst)
            return None
        inst_ssa = llil_inst.ssa_form
        logger.debug(inst_ssa)
        if inst_ssa.operation == LowLevelILOperation.LLIL_SET_REG_SSA:
            # SET_REG_SSA means setting up the reg value, create a first tree based on this info
            left = gen_ast(llil_fun, inst_ssa.dest) 
            right = gen_ast(llil_fun, inst_ssa.src)
            root_node = BnSSAOp(left, "=", right)
            # self.parse_ast(root_node)
            # logger.debug("%s %s %s", self.parse_nodes(root_node.left), root_node.op, root_node.right)
            return root_node
        if inst_ssa.operation == LowLevelILOperation.LLIL_SET_REG_SSA_PARTIAL:
            # <llil: %rax#9.%ax = %rax#8.%ax - [%rbp#1 - 0xc {var_14}].w @ mem#9>
            left = gen_ast(llil_fun, inst_ssa.dest) 
            right = gen_ast(llil_fun, inst_ssa.src)
            root_node = BnSSAOp(left, "=", right)
            print(root_node)
            parse_ast(root_node)
            # exit()
            # logger.debug("%s %s %s", self.parse_nodes(root_node.left), root_node.op, root_node.right)
            return root_node
        if inst_ssa.operation == LowLevelILOperation.LLIL_STORE_SSA:
            left = gen_ast(llil_fun, inst_ssa.dest) 
            right = gen_ast(llil_fun, inst_ssa.src)
            root_node = BnSSAOp(left, "=", right)
            return root_node
    else:
        # cmp     $0x2, dword ptr [%rbp-0x144] 
        logger.debug(asm_inst.inst_print())
        left = RegNode(asm_inst.dest)
        right = RegNode(asm_inst.src)
        root_node = BnSSAOp(left, asm_inst.inst_type, right)
        return root_node
    
def calc_ssa_off_expr(self, inst_ssa):
        # This is for binary ninja diassembly
        arrow = 'U+21B3'
        logger.info("Calculating the offset of %s %s", inst_ssa, type(inst_ssa)) 
        offset_expr_regex = r'(\-[0-9].*)\((.*)\)'
        # try:
        if type(inst_ssa) == binaryninja.lowlevelil.LowLevelILLoadSsa:
            logger.debug("%s LoadReg", chr(int(arrow[2:], 16)))
            mapped_MLLIL = inst_ssa.mapped_medium_level_il # This is done to get the var (or find if not)
            if mapped_MLLIL != None:
                result = calc_ssa_off_expr(self, inst_ssa.src)
                if result != None:
                    return result
            else:
                logger.error("No variable assigned, skip")
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILStoreSsa:
            logger.debug("%s StoreSSA",  chr(int(arrow[2:], 16)))
            result = calc_ssa_off_expr(self, inst_ssa.dest)
            if result != None:
                return result
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILSetRegSsa:
            logger.debug("%s SetRegSSA",  chr(int(arrow[2:], 16)))
            result = calc_ssa_off_expr(self, inst_ssa.src)
            if result != None:
                return result
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILSetRegSsaPartial:
            logger.debug("%s SetRegSSAPartial",  chr(int(arrow[2:], 16)))
            # reg_def = llil_fun.get_ssa_reg_definition(llil_inst.full_reg)
            result = calc_ssa_off_expr(self, inst_ssa.src)
            if result != None:
                return result
        elif type(inst_ssa) == binaryninja.lowlevelil.LowLevelILZx:
            logger.debug("%s ZeroExtendSSA",  chr(int(arrow[2:], 16)))
            result = calc_ssa_off_expr(self, inst_ssa.src)
            if result != None:
                return result
        elif binaryninja.commonil.Arithmetic in inst_ssa.__class__.__bases__:
            logger.debug("%s Arithmetic",  chr(int(arrow[2:], 16)))
            try:
                # Expression
                reg = inst_ssa.left.src
            except:
                # Single register
                reg = inst_ssa.left
            
            base_offset = 0
            base_reg = None
            for bn_var in self.bn_var_list:
                ast = bn_var.asm_syntax_tree
                # print(ast, bn_var.patch_inst.inst_print())
                if ast != None:
                    # If AST is none, this means that SSA register is not yet available
                    if repr(ast.left) == 'RegNode':
                        # If this is just a register node (e.g., rcx#3)
                        if reg == ast.left.value:
                            # base_offset = int(bn_var.offset)
                            offset_reg = re.search(offset_expr_regex, bn_var.offset_expr)
                            if offset_reg:
                                base_offset = offset_reg.group(1)
                                base_reg = offset_reg.group(2)
            # print(type(inst_ssa.right) )
            # addsd/divsd read their memory operand through a conversion, %xmm0 f+ fconvert.t([%rbp - 0x428].q):
            # the operand is the load inside it
            right_load = inst_ssa.right
            while isinstance(right_load, binaryninja.commonil.Arithmetic) and not hasattr(right_load, "left"):
                right_load = right_load.src
            if type(right_load) != binaryninja.lowlevelil.LowLevelILLoadSsa:
                right_load = inst_ssa.right
            if base_reg is not None and type(right_load) == binaryninja.lowlevelil.LowLevelILLoadSsa:
                offset = calc_ssa_off_expr(self, right_load)
                expr = offset
            elif base_reg is not None:
                # print("Here 2")
                try:
                    offset = str(int(inst_ssa.right.__str__(), base=16) + int(base_offset))
                    expr = offset + "(" + base_reg + ")"
                except:
                    # %rdx#9 + %rax#12
                    expr = "(" + inst_ssa.left.__str__() + "," + inst_ssa.right.__str__() + ")"
            # need to hanlde %rax#33.%eax - [%rbp#1 - 4 {var_c_1}].d case
            elif type(right_load) == binaryninja.lowlevelil.LowLevelILLoadSsa:
                # print("Here 3")
                offset = calc_ssa_off_expr(self, right_load)
                expr = offset
            elif (binaryninja.commonil.Arithmetic in inst_ssa.left.__class__.__bases__ and 
                  type(inst_ssa.right) == binaryninja.lowlevelil.LowLevelILConst):
                print("Array access found")
                base_reg    = inst_ssa.left.left.src.reg.__str__()
                array_reg   = inst_ssa.left.right.src.reg.__str__()
                offset      = inst_ssa.right.constant
                expr = str(offset) + "(" + base_reg + "," + array_reg + ")"
            else:
                # print(inst_ssa.right, type(inst_ssa.right))
                offset = str(int(inst_ssa.right.__str__(), base=16))
                expr = offset + "(" + reg.reg.__str__() + ")"
            
            logger.debug(expr)
            return expr
         
def asm_lex_analysis(self, var_name, llil_fun, llil_inst, dis_inst = None, fun = None):
    print("")
    arrow = 'U+21B3'
    if llil_inst is not None and llil_fun is not None:
        dis_inst = self.bv.get_disassembly(llil_inst.address)
        fun_name = llil_fun.medium_level_il.source_function.name
        logger.warning("ASM Lexical Analysis: %s | Fun: %s", llil_inst, fun_name)
        logger.warning("\t%s %s", chr(int(arrow[2:], 16)), dis_inst)
    else:
        logger.warning("ASM Lexical Analysis: %s | Fun: %s", dis_inst, fun.name)
    # Example: mov     qword [rbp-0x8], rax 
    dis_inst_pattern    = re.search(r"(\b[a-z]+\b)\s*(.*),\s(.*)", dis_inst)
    # Example: qword ptr [%rbp-0x410]
    reg_offset_pattern = r'(\b[qword ptr|dword ptr|byte ptr|word ptr]+\b)\s\[(%.*)([*+\/-]0x[a-z,0-9].*)\]'
    # Example: qword ptr [%rdx+%rax]
    reg_reg_pattern = r'(\b[qword ptr|dword ptr|byte ptr|word ptr]+\b)\s\[(%.*)\+(%.*)\]'
    reg_64_pattern = r'%r[a-z]x'
    reg_32_pattern = r'%e[a-z]x'
    inst_type           = str()
    src                 = str()
    dest                = str()
    if dis_inst_pattern != None:
        inst_type   = dis_inst_pattern.group(1)
        src         = dis_inst_pattern.group(2)
        dest        = dis_inst_pattern.group(3)
    else:
        logger.error("Regex failed %s", dis_inst)

    offset_src_dest = None
    patch_inst = None
    if re.search(r'(qword ptr|dword ptr|byte ptr|word ptr)', src):
        logger.debug("ptr Source")
        offset_src_dest = "src" # Used for dis_inst
        suffix_regex = re.search(r'(qword ptr|dword ptr|byte ptr|word ptr)', src)
        if suffix_regex != None:
            suffix = suffix_regex.group(1)
            # conv_inst_type = conv_instr(inst_type, suffix)
            # logger.debug("%s %s %s %s", inst_type, src, dest, suffix)
            offset_regex = re.search(reg_offset_pattern, src)
            reg_regex = re.search(reg_reg_pattern, src)
            if offset_regex:
                expr = str(int(offset_regex.group(3),base=16)) + "(" + offset_regex.group(2) + ")"
                # if inst_type != "movzx":
                #     patch_inst = PatchingInst(inst_type, conv_suffix(suffix), conv_imm(expr), conv_imm(dest), offset_src_dest)
                # else:
                patch_inst = PatchingInst(inst_type, conv_suffix(suffix), conv_imm(expr), conv_imm(dest), offset_src_dest)
                # print("Here") # conv_suffix(None, inst_type, dest)
            elif reg_regex:
                expr = str("("+reg_regex.group(2)+","+reg_regex.group(3)+")")
                # if inst_type != "movzx":
                #     patch_inst = PatchingInst(inst_type, conv_suffix(suffix), conv_imm(expr), conv_imm(dest), offset_src_dest)
                # else:
                patch_inst = PatchingInst(inst_type, conv_suffix(suffix), conv_imm(expr), conv_imm(dest), offset_src_dest)
    elif re.search(r'(qword ptr|dword ptr|byte ptr|word ptr)', dest):
        logger.debug("ptr Dest")
        offset_src_dest = "dest" # Used for dis_inst
        suffix_regex = re.search(r'(qword ptr|dword ptr|byte ptr|word ptr)', dest)
        if suffix_regex != None:
            suffix = suffix_regex.group(1)
            # conv_inst_type = conv_instr(inst_type, suffix)
            logger.debug("%s %s %s %s", inst_type, src, dest, suffix)
            offset_regex = re.search(reg_offset_pattern, dest)
            reg_regex = re.search(reg_reg_pattern, src)
            if offset_regex:
                expr = str(int(offset_regex.group(3),base=16)) + "(" + offset_regex.group(2) + ")"
                # if inst_type != "movzx":
                patch_inst = PatchingInst(inst_type, suffix=conv_suffix(suffix), src=conv_imm(src), dest=conv_imm(expr), ptr_op=offset_src_dest)
                # else:
                #     patch_inst = PatchingInst(inst_type, suffix=conv_suffix(None, inst_type, src), src=conv_imm(src), dest=conv_imm(expr), ptr_op=offset_src_dest)
            elif reg_regex:
                expr = str("("+reg_regex.group(2)+","+reg_regex.group(3)+")")
                # if inst_type != "movzx":
                patch_inst = PatchingInst(inst_type, suffix=conv_suffix(suffix), src=conv_imm(src), dest=conv_imm(expr), ptr_op=offset_src_dest)
                # else:
                #     patch_inst = PatchingInst(inst_type, suffix=conv_suffix(None, inst_type, src), src=conv_imm(src), dest=conv_imm(expr), ptr_op=offset_src_dest)
    else:
        # logger.debug("Neither")
        suffix = None
        if re.search(reg_64_pattern, src) or re.search(reg_64_pattern, dest):
            # 64-bit register
            suffix = "q"
        elif re.search(reg_32_pattern, src) or re.search(reg_32_pattern, dest):
            # 32-bit register
            suffix = "l"
        else: 
            # Byte
            suffix = "b"
        
        patch_inst = PatchingInst(inst_type=inst_type, suffix=suffix,
                                        dest=conv_imm(dest), src=conv_imm(src), ptr_op="")
        
    # logger.debug(patch_inst)
    if patch_inst != None:
        logger.debug(patch_inst.inst_print())
    else:
        # An instruction shape the lexer does not model (e.g. the stack-clash probe
        # "or $0x0, (%rsp)" gcc emits in frames over 4 KiB); it touches no program variable.
        logger.warning("Unsupported instruction shape, not rewritten: %s", dis_inst)
        return None
    logger.debug("%s", dis_inst)
    # if (hex(llil_inst.address) == "0x11b7"):
    #         print("Here")
    # If LLIL is provided
    if llil_inst != None:
        logger.debug("\t%s %s", chr(int(arrow[2:], 16)), llil_inst)
        asm_syntax_tree = gen_ast(llil_fun, llil_inst)
        # print("Here", asm_syntax_tree)
        parse_ast(asm_syntax_tree)
        
        print(llil_inst, type(llil_inst))
        offset_expr = calc_ssa_off_expr(self, llil_inst.ssa_form)

        # src_offset_expr [0] | dest_offset_expr [1]
        bn_var = BnVarData(var_name, dis_inst, patch_inst, 
                        offset_expr, asm_syntax_tree, llil_inst, False)
        # bn_var.patch_inst.inst_print()
        if bn_var.patch_inst.inst_type in ("movss", "movsd"):   # (the rewriter's movss/movsd carry no suffix)
            bn_var.patch_inst.suffix = ""
        # custom_pprint(bn_var)
        logger.debug(bn_var.patch_inst.inst_print())
        # print(bn_var)
        # print(bn_var.patch_inst.inst_print())
        return bn_var
    # If ASM is directly provided for cmp or such
    else:
        asm_syntax_tree = gen_ast(None, None, patch_inst)
        offset_expr = None
        if offset_src_dest == "dest":
            offset_expr = patch_inst.dest
        elif offset_src_dest == "src":
            offset_expr = patch_inst.src
        bn_var = BnVarData(var_name, dis_inst, patch_inst, 
                        offset_expr, asm_syntax_tree, llil_inst, False)
        if bn_var.patch_inst.inst_type in ("movss", "movsd"):   # (the rewriter's movss/movsd carry no suffix)
            bn_var.patch_inst.suffix = ""
        # parse_ast(asm_syntax_tree)
        # print(bn_var)
        return bn_var