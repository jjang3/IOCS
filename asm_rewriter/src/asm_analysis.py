import logging
import sys
import fileinput
import inspect
import argparse
import shutil
import pprint 
import os
import re

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

arith_bitwise_ops = {
    LowLevelILOperation.LLIL_ADD, LowLevelILOperation.LLIL_SUB, LowLevelILOperation.LLIL_MUL,
    LowLevelILOperation.LLIL_DIVU, LowLevelILOperation.LLIL_DIVS, LowLevelILOperation.LLIL_MODU,
    LowLevelILOperation.LLIL_MODS, LowLevelILOperation.LLIL_AND, LowLevelILOperation.LLIL_OR,
    LowLevelILOperation.LLIL_XOR, LowLevelILOperation.LLIL_LSL, LowLevelILOperation.LLIL_LSR,
    LowLevelILOperation.LLIL_ASR, LowLevelILOperation.LLIL_ROR, LowLevelILOperation.LLIL_ROL,
    LowLevelILOperation.LLIL_NEG, LowLevelILOperation.LLIL_NOT
}

ignore_ops = {
    LowLevelILOperation.LLIL_PUSH, LowLevelILOperation.LLIL_CONST_PTR
}


class ASTNode:
    """
    Base class for nodes in the Abstract Syntax Tree (AST).
    """
    def __init__(self, is_root=False):
        self.is_root = is_root
        if is_root == True:
            logger.debug(f"Created {self.__class__.__name__} with is_root={self.is_root}")

    def print_tree(self, prefix="", is_last=True, direction="root"):
        """
        Recursively prints the AST tree with direction indicators.
        """
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
    def __init__(self, left, op, right, is_root=False):
        super().__init__(is_root)
        self.left = left
        self.op = op
        self.right = right
        logger.debug(f"Created OperationNode with operation={self.op}")

    @staticmethod
    def create_from_operation(llil_fun, llil_inst, is_root=False):
        logger.debug(f"Creating OperationNode for instruction: {llil_inst}")
        if isinstance(llil_inst, binaryninja.lowlevelil.LowLevelILLoadSsa):
            right = ASTNode.create_node(llil_fun, llil_inst.src)
            return OperationNode(None, llil_inst.operation, right, is_root)
        elif isinstance(llil_inst, binaryninja.lowlevelil.LowLevelILZx):
            right = ASTNode.create_node(llil_fun, llil_inst.src)
            return OperationNode(None, llil_inst.operation, right, is_root)
        elif isinstance(llil_inst, binaryninja.lowlevelil.LowLevelILLowPart):
            right = ASTNode.create_node(llil_fun, llil_inst.src)
            return OperationNode(None, llil_inst.operation, right, is_root)
        elif isinstance(llil_inst, binaryninja.lowlevelil.LowLevelILStore):
            logger.debug(f"Handling LowLevelILStore operation at address {llil_inst.address}.")
            dest = ASTNode.create_node(llil_fun, llil_inst.dest)
            src = ASTNode.create_node(llil_fun, llil_inst.src)
            return OperationNode(dest, "store", src, is_root=is_root)
        elif binaryninja.commonil.Arithmetic in llil_inst.__class__.__bases__:
            left = ASTNode.create_node(llil_fun, llil_inst.left)
            right = ASTNode.create_node(llil_fun, llil_inst.right)
            return OperationNode(left, llil_inst.operation, right, is_root)
        return None

    def __repr__(self):
        return f"OperationNode(op={self.op}, is_root={self.is_root})"

    def print_tree(self, prefix="", is_last=True, direction="root"):
        """
        Recursively prints the AST tree with direction indicators.
        """
        connector = "└── " if is_last else "├── "
        direction_indicator = f"({direction})" if direction != "root" else ""
        # logger.debug(f"Printing tree for OperationNode {direction_indicator}")
        print(prefix + connector + f"OperationNode(op={self.op}, is_root={self.is_root}){direction_indicator}")
        
        new_prefix = prefix + ("    " if is_last else "│   ")
        
        if self.left:
            self.left.print_tree(new_prefix, is_last=False, direction="left")
        if self.right:
            self.right.print_tree(new_prefix, is_last=True, direction="right")

class BinAnalysis:
    asm_trees = set()
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
                    return OperationNode(left, "=", right, True)
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
        (?P<opcode>\w+)\s+
        (?P<operand1>
            (?P<memsize1>(qword|dword|word|byte)\s+ptr\s*)?  # Memory size specifier (optional)
            (
                \[(?P<register1>%\w+)?(?P<offset1>[+\-*\/]?\s*0x[\da-fA-F]+)?\]  # Memory reference (e.g., [%rbp-0x8])
                |
                (?P<imm1>\$0x[\da-fA-F]+)               # Immediate value (e.g., $0x0)
                |
                (?P<reg1>%\w+)                 # Register (e.g., %rax)
            )
        )\s*,?\s*
        (?P<operand2>
            (?P<memsize2>(qword|dword|word|byte)\s+ptr\s*)?  # Memory size specifier for second operand (optional)
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
            # patching_inst.inst_print()

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
            addr = inst.address
            dis_inst = self.bv.get_disassembly(addr)
            pro_inst: PatchingInst
            pro_inst = self.process_dis_inst(dis_inst)
            # if pro_inst != None:
            #     pro_inst.inst_print()
            
            asm_syntax_tree = self.gen_ast(fun, inst)
            # Print the AST in a binary tree-like structure
            if asm_syntax_tree:
                asm_syntax_tree.print_tree()
                self.asm_trees.add(asm_syntax_tree)
            print()
            
        elif isinstance(inst, MediumLevelILInstruction):
            logger.debug(inst)
            print()
        else:
            logger.warning(f"Skipping instruction of unexpected type: {inst}")
            print()

    def analyze_bb(self, bb, fun):
        for inst in bb:
            # Ensure the correct type before proceeding
            self.analyze_inst(inst, fun)

    def analyze_fun(self):
        llil_fun = self.fun.low_level_il
        for llil_bb in llil_fun:
            self.analyze_bb(llil_bb, llil_fun)

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
                for tree in self.asm_trees:
                    tree: ASTNode
                    tree.print_tree()
                    print()
                fun_asm_trees[func.name] = self.asm_trees.copy()  # Store set in dict
                self.asm_trees.clear()  # Clear the set for the next function

      
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

   