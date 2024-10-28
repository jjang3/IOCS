import logging
import sys
import fileinput
import inspect
import argparse
import shutil
import pprint 
import os
import re
from typing import List, Optional

# Get the same logger instance. Use __name__ to get a logger with a hierarchical name or a specific string to get the exact same logger.
logger = logging.getLogger('custom_logger')

class PatchingInst:
    def __init__(self, opcode, prefix, operand_1, operand_2, assembly_code = None):
        # This is based on AT&T syntax, where it is opcode, src, dest ->
        self.opcode = opcode
        self.prefix = prefix
        self.src = operand_1
        self.dest = operand_2
        self.patch = None
        self.assembly_code = assembly_code
    
    def inst_print(self):
        logger.debug(
            f"Instruction Details:\n"
            f"  - Opcode      : {self.opcode}\n"
            f"  - Prefix      : {self.prefix}\n"
            f"  - Source      : {self.src}\n"
            f"  - Destination : {self.dest}\n"
            f"  - Assembly    : {self.assembly_code if self.assembly_code else 'N/A'}\n"
            # f"  - Pointer     : {getattr(self, 'ptr_op', 'N/A')}\n" # Need to be added later
        )


from binaryninja import *
from binaryninja.binaryview import BinaryViewType
from binaryninja.architecture import Architecture, ArchitectureHook
from binaryninja.enums import LowLevelILOperation

arrow = 'U+21B3'
 # ANSI escape codes for colors
LIGHT_BLUE = "\033[96m"
LIGHT_GREEN = "\033[92m"
RESET = "\033[0m"
PURPLE = "\033[95m"
PINK = "\033[95m"
DARK_GREEN = "\033[32m"  # Darker shade of green
CYAN = "\033[36m"        # Cyan color as a different shade of blue
DARK_RED = "\033[31m"    # Darker red color

gen_regs = {"%rax", "%rbx", "%rcx", "%rdx", "%rdi", "%rsi",
            "%eax", "%ebx", "%ecx", "%edx", "%edi", "%esi",
            "%ax",  "%bx",  "%cx",  "%dx",
            "%xmm0", "%xmm1", "%xmm2", "%xmm3",
            "%xmm4", "%xmm5", "%xmm6", "%xmm7",
            "%xmm8", "%xmm9", "%xmm10", "%xmm11",
            "%xmm12", "%xmm13", "%xmm14", "%xmm15"}

suffix_map = {
        "qword": "q",  # Quadword -> q
        "dword": "l",  # Doubleword -> l
        "word": "w",   # Word -> w
        "byte": "b"    # Byte -> b
}
xfer_insts = {
    'jmp', 'je', 'jz', 'jne', 'jnz', 'jg', 'jnle', 'jge', 'jnl', 'jl', 'jnge',
    'jle', 'jng', 'ja', 'jnbe', 'jae', 'jnb', 'jb', 'jnae', 'jbe', 'jna', 'jc',
    'jnc', 'jo', 'jno', 'js', 'jns', 'jp', 'jpe', 'jnp', 'jpo', 'call', 'ret',
    'loop', 'loope', 'loopz', 'loopne', 'loopnz', 'jmpf', 'int', 'iret', 'syscall',
    'sysenter', 'sysexit'
}

float_conv_ops = {
    LowLevelILOperation.LLIL_FLOAT_TO_INT,   # Convert floating-point to integer
    LowLevelILOperation.LLIL_INT_TO_FLOAT,   # Convert integer to floating-point
    LowLevelILOperation.LLIL_FLOAT_CONV     # Convert between floating-point types
}

float_arith_ops = {
    LowLevelILOperation.LLIL_FADD,        # Floating-point addition
    LowLevelILOperation.LLIL_FSUB,        # Floating-point subtraction
    LowLevelILOperation.LLIL_FMUL,        # Floating-point multiplication
    LowLevelILOperation.LLIL_FDIV,        # Floating-point division
    LowLevelILOperation.LLIL_FNEG,        # Floating-point negation
    LowLevelILOperation.LLIL_FSQRT,       # Floating-point square root
    LowLevelILOperation.LLIL_FABS,        # Floating-point absolute value
    LowLevelILOperation.LLIL_ROUND_TO_INT,   # Round floating-point to integer
    LowLevelILOperation.LLIL_FLOOR,       # Round floating-point down (floor)
    LowLevelILOperation.LLIL_CEIL,        # Round floating-point up (ceil)
    LowLevelILOperation.LLIL_FTRUNC       # Truncate floating-point to integer
}

arith_bitwise_ops = {
    LowLevelILOperation.LLIL_ADD,         # Addition
    LowLevelILOperation.LLIL_SUB,         # Subtraction
    LowLevelILOperation.LLIL_MUL,         # Multiplication
    LowLevelILOperation.LLIL_DIVU,        # Unsigned division
    LowLevelILOperation.LLIL_DIVS,        # Signed division
    LowLevelILOperation.LLIL_MODU,        # Unsigned modulus (remainder)
    LowLevelILOperation.LLIL_MODS,        # Signed modulus (remainder)
    LowLevelILOperation.LLIL_AND,         # Bitwise AND
    LowLevelILOperation.LLIL_OR,          # Bitwise OR
    LowLevelILOperation.LLIL_XOR,         # Bitwise XOR
    LowLevelILOperation.LLIL_LSL,         # Logical shift left
    LowLevelILOperation.LLIL_LSR,         # Logical shift right
    LowLevelILOperation.LLIL_ASR,         # Arithmetic shift right (preserves sign bit)
    LowLevelILOperation.LLIL_ROR,         # Rotate right
    LowLevelILOperation.LLIL_ROL,         # Rotate left
    LowLevelILOperation.LLIL_NEG,         # Negation (arithmetic negation)
    LowLevelILOperation.LLIL_NOT          # Bitwise NOT (complement)
}

ignore_ops = {
    LowLevelILOperation.LLIL_PUSH,            # Pushes a value onto the stack
    LowLevelILOperation.LLIL_CONST_PTR,       # Loads a constant pointer value
    LowLevelILOperation.LLIL_SET_FLAG_SSA,    # Sets a flag in SSA (Static Single Assignment) form
    LowLevelILOperation.LLIL_INTRINSIC_SSA,   # Represents an intrinsic operation in SSA form (e.g., system-specific operations)
    LowLevelILOperation.LLIL_LOW_PART         # Extracts the lower part of a value (e.g., from a larger register or data type)
}

class ASTNode:
    """
    Base class for nodes in the Abstract Syntax Tree (AST).
    """
    def __init__(self, is_root=False):
        self.is_root = is_root
        if is_root == True:
            logger.debug(f"Created {self.__class__.__name__} with is_root={self.is_root}")
            # exit()

    def print_tree(self, prefix="", is_last=True, direction="root"):
        """
        Recursively prints the AST tree with direction indicators.
        """
        if self.is_root:
            connector = "⬤ "  # Symbol for root node
        else:
            connector = "└── " if is_last else "├── "
        direction_indicator = f"({direction})" if direction != "root" else ""
        
        # logger.debug(f"Printing tree for {self.__class__.__name__} {direction_indicator}")
        print(prefix + connector + repr(self) + direction_indicator)
        
        new_prefix = prefix + ("    " if is_last else "│   ")
        
        if hasattr(self, 'left') and self.left:
            self.left.print_tree(new_prefix, is_last=False, direction="left")
        
        if hasattr(self, 'right') and self.right:
            self.right.print_tree(new_prefix, is_last=True, direction="right")


    def __repr__(self):
        return f"{self.__class__.__name__}(is_root={self.is_root})"

    @staticmethod
    def create_node(llil_fun, llil_inst, is_root=False):
        logger.debug(f"Create node called with llil_inst={llil_inst} and is_root={is_root}")

        # Handle SSA Register
        if isinstance(llil_inst, binaryninja.lowlevelil.SSARegister):
            logger.debug(f"{LIGHT_GREEN}Creating SSA Register node.{RESET}")
            return RegisterNode.create_node_from_ssa_reg(llil_fun, llil_inst, is_root)

        # Handle Regular Register
        elif isinstance(llil_inst, binaryninja.lowlevelil.ILRegister):
            logger.debug(f"{LIGHT_GREEN}Creating IL Register node.{RESET}")
            return RegisterNode.create_node_from_register(llil_inst, is_root)

        # Handle Constant Value
        elif isinstance(llil_inst, binaryninja.lowlevelil.LowLevelILConst):
            logger.debug(f"{LIGHT_GREEN}Creating Constant node with value {llil_inst.constant}.{RESET}")
            return RegisterNode.create_node_from_constant(llil_inst.constant, is_root)

        # Handle Operations
        elif isinstance(llil_inst, binaryninja.lowlevelil.LowLevelILInstruction):
            op_name = llil_inst.operation.name
            logger.debug(f"{LIGHT_GREEN}Creating Operation node for op {op_name}.{RESET}")
            
            # Recursively create the left and right nodes
            left = ASTNode.create_node(llil_fun, llil_inst.left) if hasattr(llil_inst, 'left') else None
            right = ASTNode.create_node(llil_fun, llil_inst.right) if hasattr(llil_inst, 'right') else None

            logger.debug(f"Created left node: {left}, right node: {right} for operation: {op_name}")
            return OperationNode(left, op_name, right, is_root=is_root)

        else:
            logger.error(f"Unhandled instruction type: {type(llil_inst)}.")
            raise NotImplementedError(f"Unhandled LLIL instruction type: {type(llil_inst)}")

class RegisterNode(ASTNode):
    """
    AST node representing a register or constant.
    """
    def __init__(self, value, is_root=False):
        super().__init__(is_root)
        self.value = value
        logger.debug(f"{LIGHT_GREEN}Created RegisterNode with value={self.value}{RESET}")

    @staticmethod
    def create_node_from_ssa_reg(llil_fun, llil_inst, is_root=False):
        logger.debug(f"{LIGHT_GREEN}Creating RegisterNode from SSARegister: {llil_inst}{RESET}")
        return RegisterNode(llil_inst, is_root)

    @staticmethod
    def create_node_from_reg(llil_inst, is_root=False):
        logger.debug(f"{LIGHT_GREEN}Creating RegisterNode from ILRegister: {llil_inst}{RESET}")
        return RegisterNode(llil_inst, is_root)

    @staticmethod
    def create_node_from_const(const_value, is_root=False):
        logger.debug(f"{LIGHT_GREEN}Creating RegisterNode from const: {const_value}{RESET}")
        return RegisterNode(const_value, is_root)

    def __repr__(self):
        return f"RegisterNode(value={self.value}, is_root={self.is_root})"

class OperationNode(ASTNode):
    """
    AST node representing an operation involving other nodes.
    """
    def __init__(self, left, op, right, is_root=False, dis_inst=None):
        super().__init__(is_root)
        self.left = left
        self.op = op
        self.right = right
        self.dis_inst = dis_inst
        logger.debug(f"Created OperationNode with operation={self.op}")
        # if self.dis_inst != None:
        #     dis_inst.inst_print()
        if is_root == True:
            logger.debug(f"{DARK_RED}----------------------------------------------{RESET}\n")

    @staticmethod
    def create_from_operation(llil_fun, llil_inst, is_root=False):
        logger.debug(f"Creating OperationNode for instruction: {llil_inst}")
        if isinstance(llil_inst, binaryninja.lowlevelil.LowLevelILLoadSsa):
            right = ASTNode.create_node(llil_fun, llil_inst.src)
            return OperationNode(None, llil_inst.operation, right, is_root=is_root)
        elif isinstance(llil_inst, binaryninja.lowlevelil.LowLevelILZx):
            right = ASTNode.create_node(llil_fun, llil_inst.src)
            return OperationNode(None, llil_inst.operation, right, is_root=is_root)
        elif isinstance(llil_inst, binaryninja.lowlevelil.LowLevelILLowPart):
            right = ASTNode.create_node(llil_fun, llil_inst.src)
            return OperationNode(None, llil_inst.operation, right, is_root=is_root)
        elif isinstance(llil_inst, binaryninja.lowlevelil.LowLevelILStore):
            logger.debug(f"Handling LowLevelILStore operation at address {llil_inst.address}.")
            dest = ASTNode.create_node(llil_fun, llil_inst.dest)
            src = ASTNode.create_node(llil_fun, llil_inst.src)
            return OperationNode(dest, "store", src, is_root=is_root)
        elif binaryninja.commonil.Arithmetic in llil_inst.__class__.__bases__:
            left = ASTNode.create_node(llil_fun, llil_inst.left)
            right = ASTNode.create_node(llil_fun, llil_inst.right)
            return OperationNode(left, llil_inst.operation, right, is_root=is_root)
        return None

    def __repr__(self):
        return f"OperationNode(op={self.op}, is_root={self.is_root})"

    def print_tree(self, prefix="", is_last=True, direction="root"):
        """
        Recursively prints the AST tree with direction indicators.
        """
        if self.is_root:
            connector = "⬤ "  # Symbol for root node
        else:
            connector = "└── " if is_last else "├── "
        direction_indicator = f"({direction})" if direction != "root" else ""
        # logger.debug(f"Printing tree for OperationNode {direction_indicator}")
        print(prefix + connector + f"OperationNode(op={self.op}, is_root={self.is_root}){direction_indicator}")
        
        new_prefix = prefix + ("    " if is_last else "│   ")
        
        if self.left:
            self.left.print_tree(new_prefix, is_last=False, direction="left")
        if self.right:
            self.right.print_tree(new_prefix, is_last=True, direction="right")


class BnVarData:
    def __init__(self, name: Optional[str] = None, dis_inst: Optional[str] = None, patch_inst: Optional['PatchingInst'] = None, offset: Optional[int] = None, llil_inst: Optional['LowLevelILInstruction'] = None, asmst: Optional [ASTNode] = None, arg: Optional[bool] = None):
        self.name = name
        self.dis_inst = dis_inst
        self.patch_inst = patch_inst
        self.offset = offset
        self.llil_inst = llil_inst
        self.asmst = asmst
        self.arg = arg

    def print_info(self):
        """Prints the BnVarData information in an organized format."""
        print("\nBnVarData Information:")
        print(f"  Name          : {self.name}")
        print(f"  Disassembled  : {self.dis_inst}")

        # Print details of the PatchingInst if it exists
        if self.patch_inst:
            self.patch_inst.inst_print()

        print(f"  Offset        : {self.offset}")
        print(f"  LLIL Inst     : {self.llil_inst}")
        print(f"  Is Argument   : {self.arg}")

        # Print the ASM syntax tree if available
        if self.asmst:
            print("  ASM Syntax Tree:")
            self.asmst.print_tree(prefix="    ")  # Indented for better readability
        else:
            print("  ASM Syntax Tree: None")

class BnFunData:
    def __init__(self, name: Optional[str] = None, vars: Optional[List[BnVarData]] = None):
        self.name = name
        self.vars = vars if vars is not None else []


class BinAnalysis:
    bn_fun_var_info     = dict() # Dict for functions which will have variable list
    bn_var_list         = list() # List for BN variables (for argument)
    addr_to_llil        = dict() # Addr to LLIL instruction (for call inst analysis)
    asm_trees           = set()
    dis_inst = None # Current disassembly instruction
    def gen_ast(self, llil_fun, llil_inst, is_root=False):
        """
        Generate an AST node based on a given Low-Level IL instruction or assembly instruction.

        Args:
            llil_fun: The function in which the instruction resides.
            llil_inst: The Low-Level IL instruction or register.
            asm_inst: Optional; the associated assembly instruction (default is None).
            is_root: Boolean flag to indicate whether this node is a root node (default is False).

        Returns:
            A RegNode, BnSSAOp, or None if the instruction cannot be resolved.
        
        Example for handling:
        
        1. Move instruction: 'mov %edi, %rax'
           - SSA form: %rax#1 = %edi#1
           - The function will detect the register assignment (LLIL_SET_REG_SSA)
           - Left operand: %rax#1 (generated using gen_ast)
           - Right operand: %edi#1 (generated using gen_ast)
           - Result: BnSSAOp representing the operation "%rax#1 = %edi#1"
        
        2. Addition instruction: 'addl $512, %rax'
           - SSA form: %rax#2 = %rax#1 + $512
           - The function will detect an arithmetic operation (addition)
           - Left operand: %rax#1 (generated using gen_ast)
           - Right operand: $512 (generated as a constant node)
           - Result: BnSSAOp representing the operation "%rax#2 = %rax#1 + $512"
        """
        """
        Generate an AST node based on a given Low-Level IL instruction.
        """
        # Use ASTNode's factory method to create nodes
        # logger.debug(f"Generating AST for llil_inst: {llil_inst}")

        # Handle SSA Register
        if isinstance(llil_inst, binaryninja.lowlevelil.SSARegister):
            logger.debug(f"Handling SSARegister: {llil_inst}")
            reg_def = llil_fun.get_ssa_reg_definition(llil_inst)
            if reg_def is not None:
                try:
                    if isinstance(reg_def.src, binaryninja.lowlevelil.LowLevelILConstPtr):
                        # If global variable detected, log and skip this instruction
                        logger.error("Global variable detected")
                        return None  # Return None and continue the rest of the analysis
                    return RegisterNode.create_node_from_ssa_reg(llil_fun, llil_inst, is_root)
                except Exception as e:
                    logger.error(f"Error generating node: {e}")
                    return RegisterNode(llil_inst, is_root)
            return RegisterNode.create_node_from_ssa_reg(llil_fun, llil_inst, is_root)

        # Handle Regular Register
        elif isinstance(llil_inst, binaryninja.lowlevelil.ILRegister):
            logger.debug(f"Handling ILRegister: {llil_inst}")
            return RegisterNode.create_node_from_reg(llil_inst, is_root)

        # Handle Constant Value
        elif isinstance(llil_inst, binaryninja.lowlevelil.LowLevelILConst):
            logger.debug(f"Handling Constant Value: {llil_inst.constant}")
            return RegisterNode.create_node_from_const(llil_inst.constant, is_root)
        
        # Handle SSA operations
        if hasattr(llil_inst, 'ssa_form'):
            inst_ssa = llil_inst.ssa_form
            op_name = inst_ssa.operation.name
            logger.debug(f"Generating AST for operation: {op_name}")
            
            if inst_ssa.operation in [LowLevelILOperation.LLIL_REG_SSA]:
                logger.debug(f"{PURPLE}Handling {op_name}: inst_ssa{RESET}")
                return self.gen_ast(llil_fun, inst_ssa.src)
        
            elif inst_ssa.operation in [LowLevelILOperation.LLIL_REG_SSA_PARTIAL]:
                logger.debug(f"{PURPLE}Handling {op_name}: inst_ssa{RESET}")
                # Partial is like of %rax.eax
                return self.gen_ast(llil_fun, inst_ssa.full_reg)
            
            elif inst_ssa.operation in [LowLevelILOperation.LLIL_SET_REG_SSA, LowLevelILOperation.LLIL_SET_REG_SSA_PARTIAL, LowLevelILOperation.LLIL_STORE_SSA]:
                logger.debug(f"{PINK}Handling {op_name}: Assigning {inst_ssa.dest} ({type(inst_ssa.dest)}) from {inst_ssa.src} ({type(inst_ssa.src)}){RESET}")
                left = self.gen_ast(llil_fun, inst_ssa.dest)
                right = self.gen_ast(llil_fun, inst_ssa.src)
                # Only create OperationNode if both left and right are valid
                if left is not None and right is not None:
                    if self.dis_inst == None:
                        logger.error("No disassembly instruction available")
                    return OperationNode(left, "=", right, True, dis_inst=self.dis_inst)
                else:
                    logger.error("Either LR node is None, skipping operation.")
                    return None

            elif inst_ssa.operation in [LowLevelILOperation.LLIL_ZX, LowLevelILOperation.LLIL_LOAD_SSA, LowLevelILOperation.LLIL_SX]:
                logger.debug(f"{DARK_GREEN}Handling {op_name}: {inst_ssa.src}{RESET}")
                right = self.gen_ast(llil_fun, llil_inst.src)

                # Only create OperationNode if the right operand is valid
                if right is not None:
                    return OperationNode(None, op_name, right, is_root)
                else:
                    logger.debug(f"Right node is None for {op_name}, skipping operation.")
                    return None

            elif inst_ssa.operation in arith_bitwise_ops:
                logger.debug(f"{CYAN}Handling {op_name}: {inst_ssa.left}, {inst_ssa.right}{RESET}")
                left = self.gen_ast(llil_fun, inst_ssa.left)
                right = self.gen_ast(llil_fun, inst_ssa.right)
                return OperationNode(left, op_name, right, is_root)

            elif inst_ssa.operation in float_arith_ops:
                logger.debug(f"{CYAN}Handling {op_name}: {inst_ssa.left}, {inst_ssa.right}{RESET}")
                left = self.gen_ast(llil_fun, inst_ssa.left)
                right = self.gen_ast(llil_fun, inst_ssa.right)
                return OperationNode(left, op_name, right, is_root)
            
            elif inst_ssa.operation in float_conv_ops:
                logger.debug(f"{CYAN}Handling {op_name}: {inst_ssa}{RESET}")
                logger.debug(f"{DARK_GREEN}Handling {op_name}: {inst_ssa.src}{RESET}")
                right = self.gen_ast(llil_fun, llil_inst.src)
                # Only create OperationNode if the right operand is valid
                if right is not None:
                    return OperationNode(None, op_name, right, is_root)
                else:
                    logger.debug(f"Right node is None for {op_name}, skipping operation.")
                    return None
            
             # Handle Ignored operations
            elif inst_ssa.operation in ignore_ops:
                logger.error(f"Ignoring instruction type: {llil_inst}, {llil_inst.operation}")
                return None

            # Unhandled instruction
            else:
                logger.error(f"Unhandled instruction type: {llil_inst}, {llil_inst.operation}")
                raise NotImplementedError(f"Unhandled LLIL instruction type: {op_name}")

        # If no SSA form, unhandled instruction
        else:
            logger.error(f"Instruction does not have SSA form: {llil_inst}")
            raise NotImplementedError(f"Unhandled instruction without SSA form: {llil_inst}")

    def get_ssa_reg(self, inst_ssa):
        """Recursively retrieves the SSA register from an instruction, handling various IL instruction types."""
        arrow = 'U+21B3'  # Unicode arrow for debugging output
        logger.info("Getting the SSA register of %s %s", inst_ssa, type(inst_ssa)) 

        # Check if inst_ssa is already an SSARegister
        if isinstance(inst_ssa, binaryninja.lowlevelil.SSARegister):
            return inst_ssa

        # Recursive handling for SSA forms
        elif isinstance(inst_ssa, binaryninja.lowlevelil.LowLevelILRegSsa):
            return self.get_ssa_reg(inst_ssa.src)

        # Recursive handling for partially defined SSA registers
        elif isinstance(inst_ssa, binaryninja.lowlevelil.LowLevelILRegSsaPartial):
            return self.get_ssa_reg(inst_ssa.full_reg)

        # Handle SSA load operations (e.g., loading from memory)
        elif isinstance(inst_ssa, binaryninja.lowlevelil.LowLevelILLoadSsa):
            logger.debug("%s LoadReg", chr(int(arrow[2:], 16)))  # Logs with an arrow for visual clarity
            return inst_ssa

        # Handle zero-extension (LowLevelILZx) cases by continuing to the full register
        elif isinstance(inst_ssa, binaryninja.lowlevelil.LowLevelILZx):
            return self.get_ssa_reg(inst_ssa.src.full_reg)

        # Handle arithmetic expressions involving SSA registers
        elif binaryninja.commonil.Arithmetic in inst_ssa.__class__.__bases__:
            # This specifically handles cases like "%rax#3 + 4"
            return self.get_ssa_reg(inst_ssa.left.src)

        # Fallback for unhandled cases, print parent classes for debugging
        else:
            logger.warning("Unhandled instruction type: %s", inst_ssa.__class__.__bases__)

    def determine_prefix_from_registers(self, reg1, reg2):
        if reg1 and reg2:
            if reg1.startswith("%r") and reg2.startswith("%r"):  # 64-bit registers
                return "q"
            elif reg1.startswith("%e") and reg2.startswith("%e"):  # 32-bit registers
                return "l"
            elif len(reg1) == 3 and len(reg2) == 3:  # For 16-bit registers (e.g., %ax, %di)
                return "w"
            elif len(reg1) == 2 and len(reg2) == 2:  # For 8-bit registers (e.g., %al, %bl)
                return "b"
        elif reg1:
            if reg1.startswith("%r"):  # 64-bit register
                return "q"
            elif reg1.startswith("%e"):  # 32-bit register
                return "l"
            elif len(reg1) == 3:  # 16-bit register
                return "w"
            elif len(reg1) == 2:  # 8-bit register
                return "b"
        elif reg2:
            if reg2.startswith("%r"):  # 64-bit register
                return "q"
            elif reg2.startswith("%e"):  # 32-bit register
                return "l"
            elif len(reg2) == 3:  # 16-bit register
                return "w"
            elif len(reg2) == 2:  # 8-bit register
                return "b"
        return ""

    def process_dis_inst(self, dis_inst):
        dis_line_regex = r"""
        (?P<opcode>\w+(?:dqa|aps)?)\s+
        (?P<operand1>
            (?P<memsize1>(xmmword|qword|dword|word|byte)\s+ptr\s*)?  # Memory size specifier (optional)
            (
                \[(?P<register1>%\w+)?(?P<offset1>[+\-*\/]?\s*0x[\da-fA-F]+)?\]  # Memory reference (e.g., [%rbp-0x8])
                |
                (?P<imm1>\$0x[\da-fA-F]+)               # Immediate value (e.g., $0x0)
                |
                (?P<reg1>%\w+)                 # Register (e.g., %rax)
            )
        )\s*,?\s*
        (?P<operand2>
            (?P<memsize2>(xmmword|qword|dword|word|byte)\s+ptr\s*)?  # Memory size specifier for second operand (optional)
            (
                \[(?P<register2>%\w+)?(?P<offset2>[+\-*\/]?\s*0x[\da-fA-F]+)?\]  # Memory reference (e.g., [%rbp-0x8])
                |
                (?P<imm2>\$0x[\da-fA-F]+)               # Immediate value (e.g., $0x0)
                |
                (?P<reg2>%\w+)                 # Register (e.g., %rax)
            )
        )?
        """

        dis_pattern = re.compile(dis_line_regex, re.VERBOSE)
        match = dis_pattern.match(dis_inst.strip())

        if match:
            opcode = match.group('opcode')

            # Operand 1
            memsize1 = match.group('memsize1')
            reg1 = match.group('reg1')
            register1 = match.group('register1') if match.group('register1') else reg1
            offset1 = match.group('offset1')
            imm1 = match.group('imm1')

            # Operand 2 - Initialize operand2 early
            operand2 = None
            memsize2 = match.group('memsize2')
            reg2 = match.group('reg2')
            register2 = match.group('register2') if match.group('register2') else reg2
            offset2 = match.group('offset2')
            imm2 = match.group('imm2')

            # Handle immediate values (properly set them to actual values)
            if imm1:
                operand1 = int(imm1.replace('$0x', '0x'), 16)  # Convert immediate value to int
            else:
                if offset1 and not register1:
                    # Only offset, convert to plain int (no register, no brackets)
                    operand1 = str(int(offset1, 16))  # Convert offset from hex to integer
                elif register1 and offset1:
                    # Both register and offset exist
                    operand1 = f"{int(offset1, 16)}({register1})"
                else:
                    operand1 = register1 if register1 else None

            if imm2:
                operand2 = int(imm2.replace('$0x', '0x'), 16)  # Convert immediate value to int
            else:
                if offset2 and not register2:
                    # Only offset, convert to plain int (no register, no brackets)
                    operand2 = str(int(offset2, 16))
                elif register2 and offset2:
                    # Both register and offset exist
                    operand2 = f"{int(offset2, 16)}({register2})"
                else:
                    operand2 = register2 if register2 else None

            # Determine the appropriate prefix based on memory size or register type
            prefix = ""
            if memsize1:
                memsize1 = memsize1.strip()  # Remove extra spaces
                prefix = suffix_map.get(memsize1.split()[0], "")  # Get the prefix without "ptr"
            elif memsize2:
                memsize2 = memsize2.strip()  # Remove extra spaces
                prefix = suffix_map.get(memsize2.split()[0], "")  # Get the prefix without "ptr"
            else:
                # Determine prefix based on registers and immediate values
                if imm1 and register2:  # If operand1 is an immediate and operand2 is a register
                    prefix = self.determine_prefix_from_registers(None, register2)
                elif imm2 and register1:  # If operand2 is an immediate and operand1 is a register
                    prefix = self.determine_prefix_from_registers(register1, None)
                else:
                    prefix = self.determine_prefix_from_registers(register1, register2)

            # Ensure prefix is applied correctly for immediate and register cases
            if imm1 and register2:  # Immediate + Register case
                prefix = self.determine_prefix_from_registers(None, register2)
            elif imm2 and register1:  # Register + Immediate case
                prefix = self.determine_prefix_from_registers(register1, None)

            # Construct the patching instruction using PatchingInst class
            patching_inst = PatchingInst(
                opcode=opcode,
                prefix=prefix,
                operand_1=operand1,
                operand_2=operand2,
                assembly_code=dis_inst  # The full instruction text in the Intel syntax
            )

            # Use the PatchingInst's inst_print method to display the patching details
            patching_inst.inst_print()
            
            # Log the results with the debug logger
            # logger.debug(f"{LIGHT_BLUE}Opcode: {opcode} with prefix: {prefix}{RESET}")
            # logger.debug(f"{LIGHT_BLUE}Operand 1: {operand1} (Memory size: {memsize1}, Register: {register1}, Offset: {offset1}, Immediate: {imm1}){RESET}")
            # logger.debug(f"{LIGHT_BLUE}Operand 2: {operand2} (Memory size: {memsize2}, Register: {register2}, Offset: {offset2}, Immediate: {imm2}){RESET}")
            
            if opcode in xfer_insts:
                return None
            else:
                return patching_inst
        else:
            return None

    def analyze_call_inst(self, inst, fun):
        """Analyzes call instruction operands and marks relevant variables as arguments."""
        
        # Get the operands of the call instruction from medium-level IL
        call_ops = inst.medium_level_il.operands[2]
        logger.info("Handling call instruction %s", inst.medium_level_il)
        logger.debug("Call operands: %s", call_ops)

        # Process each operand in the call instruction
        for op in call_ops:
            logger.debug("Operand address: %s, Type: %s, SSA form: %s", hex(op.address), type(op), op.ssa_form)

            # Skip constant and constant pointer operands, as they don't represent variables
            if isinstance(op, (binaryninja.mediumlevelil.MediumLevelILConst, binaryninja.mediumlevelil.MediumLevelILConstPtr)):
                continue  # e.g., operand might be an immediate like %rsi = -1

            # Process non-variable operands (e.g., registers or temporary values)
            elif not isinstance(op, binaryninja.mediumlevelil.MediumLevelILVar):
                arg_llil_inst = self.addr_to_llil[op.address]  # Look up the corresponding LLIL instruction
                logger.debug("LLIL instruction for operand: %s", arg_llil_inst)

                # Retrieve SSA register from the source of the LLIL instruction
                ssa_reg = self.get_ssa_reg(arg_llil_inst.src.ssa_form)
                logger.debug("SSA register: %s", ssa_reg)

                # Determine if the SSA register is a load operation
                if not isinstance(ssa_reg, binaryninja.lowlevelil.LowLevelILLoadSsa):
                    # If not a load operation, get SSA definition instruction from the function context
                    def_llil_inst = fun.get_ssa_reg_definition(ssa_reg).ssa_form
                    # Check if the definition matches any variable in bn_var_list
                    for var in self.bn_var_list:
                        if def_llil_inst == var.llil_inst.ssa_form:
                            var.arg = True  # Mark the variable as an argument
                else:
                    # If it is a load operation, directly use the LLIL instruction SSA form for comparison
                    def_llil_inst = arg_llil_inst.ssa_form
                    # Mark the variable as an argument if the SSA form matches any variable's LLIL instruction
                    for var in self.bn_var_list:
                        if def_llil_inst == var.llil_inst.ssa_form:
                            var.arg = True

            # Handle MediumLevelILVar operands with no associated LLIL instructions
            elif isinstance(op, binaryninja.mediumlevelil.MediumLevelILVar) and len(op.llils) < 1:
                # Log SSA var uses if LLIL is absent (e.g., might be an argument variable)
                inst_var = fun.mlil.get_ssa_var_uses(op.ssa_form.src)
                logger.debug("No LLIL for operand. SSA var uses: %s", inst_var)

            # Process remaining cases for MediumLevelILVar operands with associated LLIL instructions
            else:
                # Get the last LLIL instruction SSA form associated with the variable
                arg_llil_inst = op.llils[-1].ssa_form
                try:
                    logger.debug("Last LLIL instruction for var operand: %s", arg_llil_inst)

                    # Retrieve the SSA register from the LLIL source
                    ssa_reg = self.get_ssa_reg(arg_llil_inst.src.ssa_form)
                    logger.debug("SSA register: %s", ssa_reg)

                    # Retrieve SSA definition or load SSA form
                    def_llil_inst = fun.get_ssa_reg_definition(ssa_reg).ssa_form
                    # Mark matching variables as arguments based on the SSA form
                    for var in self.bn_var_list:
                        if arg_llil_inst == var.llil_inst.ssa_form:
                            logger.critical("Matching argument: %s", var.llil_inst.ssa_form)
                            var.arg = True
                        if def_llil_inst == var.llil_inst.ssa_form:
                            logger.critical("Matching argument: %s", var.llil_inst.ssa_form)                            
                            var.arg = True

                # Fallback handling for any issues encountered while accessing arg_llil_inst
                except Exception as e:
                    logger.error("Error processing operand: %s, Exception: %s", op, e)
                    def_llil_inst = arg_llil_inst.ssa_form
                    for var in self.bn_var_list:
                        if def_llil_inst == var.llil_inst.ssa_form:
                            logger.critical("Matching argument on exception: %s", var.llil_inst.ssa_form)
                            var.arg = True

    def gen_bn_var(self, inst):
        """Generates a BnVarData instance based on the instruction's variable usage, filtering for stack variables."""
        
        bn_var = None
        var_name = None
        mapped_il = inst.mapped_medium_level_il  # Get the mapped medium-level IL for the instruction

        # Check if the instruction is setting a register
        if inst.operation == LowLevelILOperation.LLIL_SET_REG:
            # Verify if there are any variables being read in the instruction
            if len(mapped_il.vars_read) > 0:
                var_idx = None

                # Check if any variable names contain "var" in vars_read
                result = any("var" in var.name for var in mapped_il.vars_read)
                if result:
                    # Locate the first variable in vars_read with "var" in the name
                    for idx, var in enumerate(mapped_il.vars_read):
                        if "var" in var.name:
                            var_idx = idx
                            break  # Exit loop after finding the first matching variable
                
                # If a variable with "var" in the name was found, extract its details
                if var_idx is not None:
                    temp_var = mapped_il.vars_read[var_idx]
                    var_name = temp_var.name
                    dest_reg = inst.ssa_form.dest  # Get the destination register from SSA form

                    # Avoid processing stack pointer registers
                    try:
                        # Determine the register name based on type
                        if isinstance(dest_reg, binaryninja.lowlevelil.ILRegister):
                            reg_name = dest_reg.name
                        elif isinstance(dest_reg, binaryninja.lowlevelil.SSARegister):
                            reg_name = dest_reg.reg.name
                        
                        # Check if the variable is a stack variable and has a matching register name
                        if (temp_var.core_variable.source_type == VariableSourceType.StackVariableSourceType and 
                            "var" in var_name and reg_name in gen_regs):
                            # Create a new BnVarData instance for a matching stack variable
                            bn_var = BnVarData(name=var_name)
                    
                    except Exception as err:
                        # Log any exceptions that occur during processing
                        logger.error("Error in processing destination register: %s", err)
                        logger.warning("Not the target")
                    
                    logger.debug("Processed variable name: %s", var_name)

        # Check if the instruction is a store operation, handling written variables
        elif inst.operation == LowLevelILOperation.LLIL_STORE:
            
            # Verify if there are any variables being written in the instruction
            if len(mapped_il.vars_written) > 0:
                # Check if any written variable name contains "var"
                result = any("var" in var.name for var in mapped_il.vars_written)
                temp_var = mapped_il.vars_written[0]
                var_name = temp_var.name

                # Confirm the variable is a stack variable and contains "var" in its name
                if (temp_var.core_variable.source_type == VariableSourceType.StackVariableSourceType and 
                    "var" in var_name):
                    # Create a new BnVarData instance for the stack variable
                    bn_var = BnVarData(name=var_name)

        # Return the created BnVarData instance if applicable
        if bn_var is not None:
            return bn_var

    def analyze_inst(self, inst, fun):
        transfer_ILs = (
            binaryninja.commonil.ControlFlow,
            binaryninja.commonil.Call,
            binaryninja.commonil.Return,
            binaryninja.commonil.BranchType
        )
        
        if isinstance(inst, transfer_ILs):
            return
            
        if isinstance(inst, LowLevelILInstruction):
            logger.info(f"Analyzing the instruction: {inst}")
            bn_var = BnVarData()
            bn_var = self.gen_bn_var(inst)
            if bn_var != None:
                bn_var.llil_inst = inst
                addr = inst.address
                dis_inst = self.bv.get_disassembly(addr)
                logger.debug(dis_inst)
                pro_inst: PatchingInst
                pro_inst = self.process_dis_inst(dis_inst)
                if pro_inst != None:
                    self.dis_inst = pro_inst
                    # pro_inst.inst_print()
                    bn_var.patch_inst = pro_inst
                else:
                    # If for a diassembly instruction which is not parsed (e.g., push %rbp)
                    self.dis_inst = dis_inst
                    logger.error(f"No disassembly instruction for {inst}")
                    bn_var.dis_inst = dis_inst

                asm_syntax_tree = self.gen_ast(fun, inst)
                # Print the AST in a binary tree-like structure
                if asm_syntax_tree:
                    bn_var.asmst = asm_syntax_tree
                    asm_syntax_tree.print_tree()
                    self.asm_trees.add(asm_syntax_tree)
                    
                self.bn_var_list.append(bn_var)
                print()
            
        elif isinstance(inst, MediumLevelILInstruction):
            logger.debug(inst)
            print()
        else:
            logger.warning(f"Skipping instruction of unexpected type: {inst}")
            print()

    def analyze_bb(self, bb, fun):
        for inst in bb:
            if isinstance(inst, LowLevelILInstruction):
                self.addr_to_llil[inst.address] = inst
                if inst.operation != LowLevelILOperation.LLIL_CALL:
                # Ensure the correct type before proceeding
                    self.analyze_inst(inst, fun)
                else:
                    self.analyze_call_inst(inst, fun)

    def analyze_fun(self):
        llil_fun = self.fun.low_level_il
        self.addr_to_llil.clear()
        for llil_bb in llil_fun:
            self.analyze_bb(llil_bb, llil_fun)
        
        self.bn_fun_var_info[self.fun.name] = self.bn_var_list.copy()  
        self.bn_var_list.clear()

    def asm_lex_analysis(self, analysis_list):
        print("")
        columns, rows = shutil.get_terminal_size(fallback=(80, 20))
        logger.info("Binary analysis (Binary Ninja)")
        fun_asm_trees = dict() # This will contain the asm trees per function
        for func in self.bv.functions:
            func: Function 
            if func.name in analysis_list:
                self.fun = func
                addr_range = func.address_ranges[0]
                self.begin   = addr_range.start
                self.end     = addr_range.end
                # Format the log message to span across the width of the terminal

                self.analyze_fun()
                log_message = f"Function: {self.fun}\t| begin: {self.begin} | end: {self.end}"
               
                if len(log_message) > columns:
                    log_message = log_message[:columns-3] + "..."
                logger.info(log_message)

        return self.bn_fun_var_info # fun_asm_trees
      
    def __init__(self, bv):
        self.bv = bv
        self.fun: Optional[Function] = None
        self.fun_begin = None
        self.fun_end = None
    
def process_binary(input_binary, analysis_list):
    input_binary_path = str(input_binary)
    
    # Define the cache file (Binary Ninja Database file)
    bndb_file = input_binary_path + ".bndb"
    
    # Load the cache file if it exists
    if os.path.exists(bndb_file):
        logger.warning(f"Loading cached analysis from {bndb_file}")
        bv = BinaryViewType.get_view_of_file(bndb_file)
    else:
        # Load and analyze the binary with options that prioritize speed
        bv = BinaryViewType.get_view_of_file_with_options(input_binary_path, options={
            "arch.x86.disassembly.syntax": "AT&T"
        })
        logger.info(f"Loaded binary and starting analysis for {input_binary_path}")
        # Perform background analysis and wait for it to finish
        bv.update_analysis_and_wait()
        logger.warning(f"Saving analysis to {bndb_file}")
        bv.create_database(bndb_file)

    # Create a BinAnalysis object and run the analysis
    bn = BinAnalysis(bv)
    return bn.asm_lex_analysis(analysis_list)

   