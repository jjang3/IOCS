import fileinput
import time
import os, sys
import logging
import re

# Get the same logger instance. Use __name__ to get a logger with a hierarchical name or a specific string to get the exact same logger.
logger = logging.getLogger('main')

# Add the parent directory to sys.path
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

import main

from asm_analysis import *

asm_macros = """# var_c14n macros
# Load effective address macro
.macro lea_gs dest, offset
\trdgsbase %r11
\tmov   \offset(%r11), %r11
\tlea   (%r11), \dest
\tmovq  $0, %r11   # flag-neutral (xor would clobber the flags of cmp/and/add)
.endm

.macro lea_store_gs src, offset
\tleaq  \src, %r11
\tmovq  (%r11), %r10
\trdgsbase %r11
\tmovq  \offset(%r11), %r11
\tmovq  %r10, (%r11)
\tmovq  $0, %r10
\tmovq  $0, %r11   # flag-neutral (xor would clobber the flags of cmp/and/add)
.endm

# Data movement macros
.macro mov_store_gs src, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tmovb \src, (%r11)  # 8-bit 
\t.elseif \\value == 16
\t\tmovw \src, (%r11)  # 16-bit
\t.elseif \\value == 32
\t\tmovl \src, (%r11)  # 32-bit
\t.elseif \\value == 64
\t\tmovq \src, (%r11)  # 64-bit
\t.endif
\tmovq  $0, %r11   # flag-neutral (xor would clobber the flags of cmp/and/add)
.endm

.macro mov_load_gs dest, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tmovb (%r11), \dest  # 8-bit 
\t.elseif \\value == 16
\t\tmovw (%r11), \dest  # 16-bit
\t.elseif \\value == 32
\t\tmovl (%r11), \dest  # 32-bit
\t.elseif \\value == 64
\t\tmovq (%r11), \dest  # 64-bit
\t.endif
\tmovq  $0, %r11   # flag-neutral (xor would clobber the flags of cmp/and/add)
.endm

.macro mov_arr_store_gs src, offset, disp, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\tadd \disp, %r11
\t.if \\value == 8
\t\tmovb \src, (%r11)  # 8-bit 
\t.elseif \\value == 16
\t\tmovw \src, (%r11)  # 16-bit 
\t.elseif \\value == 32
\t\tmovl \src, (%r11)  # 32-bit 
\t.elseif \\value == 64
\t\tmovq \src, (%r11)  # 64-bit 
\t.endif
\tmovq  $0, %r11   # flag-neutral (xor would clobber the flags of cmp/and/add)
.endm

.macro mov_arr_load_gs dest, offset, disp, value   # (parameter was misnamed src while the body uses \dest)
\trdgsbase %r11
\tmov \offset(%r11), %r11
\tadd \disp, %r11
\t.if \\value == 8
\t\tmovb (%r11), \dest  # 8-bit
\t.elseif \\value == 16
\t\tmovw (%r11), \dest  # 16-bit
\t.elseif \\value == 32
\t\tmovl (%r11), \dest  # 32-bit
\t.elseif \\value == 64
\t\tmovq (%r11), \dest  # 64-bit
\t.endif
\tmovq  $0, %r11   # flag-neutral (xor would clobber the flags of cmp/and/add)
.endm

.macro movss_store_gs src, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t\tmovss \src, (%r11)  # 64-bit
\tmovq  $0, %r11   # flag-neutral (xor would clobber the flags of cmp/and/add)
.endm

.macro movsd_store_gs src, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\tmovsd \src, (%r11)
\tmovq  $0, %r11
.endm

.macro movsd_load_gs dest, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\tmovsd (%r11), \dest
\tmovq  $0, %r11
.endm

.macro movss_load_gs dest, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\tmovss (%r11), \dest  # 64-bit
\tmovq  $0, %r11   # flag-neutral (xor would clobber the flags of cmp/and/add)
.endm

.macro movzx_load_gs dest, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tmovzbl (%r11), \dest  # 8-bit 
\t.elseif \\value == 16
\t\tmovzw (%r11), \dest  # 16-bit (a bare movzx is assembled as movzbl: one byte)
\t.endif
\tmovq  $0, %r11   # flag-neutral (xor would clobber the flags of cmp/and/add)
.endm

# An access at a displacement inside a slot (a struct member, an array element at a constant
# index); lea adds it without touching the flags (add would clobber them)
.macro mov_mem_store_gs src, offset, disp, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\tlea \disp(%r11), %r11
\t.if \\value == 8
\t\tmovb \src, (%r11)
\t.elseif \\value == 16
\t\tmovw \src, (%r11)
\t.elseif \\value == 32
\t\tmovl \src, (%r11)
\t.elseif \\value == 64
\t\tmovq \src, (%r11)
\t.endif
\tmovq  $0, %r11
.endm

.macro mov_mem_load_gs dest, offset, disp, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\tlea \disp(%r11), %r11
\t.if \\value == 8
\t\tmovb (%r11), \dest
\t.elseif \\value == 16
\t\tmovw (%r11), \dest
\t.elseif \\value == 32
\t\tmovl (%r11), \dest
\t.elseif \\value == 64
\t\tmovq (%r11), \dest
\t.endif
\tmovq  $0, %r11
.endm

.macro movzx_mem_load_gs dest, offset, disp, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\tlea \disp(%r11), %r11
\t.if \\value == 8
\t\tmovzbl (%r11), \dest
\t.elseif \\value == 16
\t\tmovzw (%r11), \dest
\t.endif
\tmovq  $0, %r11
.endm

.macro cmp_mem_store_gs operand, offset, disp, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\tlea \disp(%r11), %r11
\t.if \\value == 8
\t\tcmpb \operand, (%r11)
\t.elseif \\value == 16
\t\tcmpw \operand, (%r11)
\t.elseif \\value == 32
\t\tcmpl \operand, (%r11)
\t.elseif \\value == 64
\t\tcmpq \operand, (%r11)
\t.endif
\tmovq  $0, %r11
.endm

.macro cmp_mem_load_gs operand, offset, disp, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\tlea \disp(%r11), %r11
\t.if \\value == 8
\t\tcmpb (%r11), \operand
\t.elseif \\value == 16
\t\tcmpw (%r11), \operand
\t.elseif \\value == 32
\t\tcmpl (%r11), \operand
\t.elseif \\value == 64
\t\tcmpq (%r11), \operand
\t.endif
\tmovq  $0, %r11
.endm

.macro lea_mem_gs dest, offset, disp
\trdgsbase %r11
\tmov \offset(%r11), %r11
\tlea \disp(%r11), \dest
\tmovq  $0, %r11
.endm

# Comparison / Shift macros
# ---- Comparison ---- #
.macro cmp_store_gs operand, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tcmpb \operand, (%r11)  # 8-bit 
\t.elseif \\value == 16
\t\tcmpw \operand, (%r11)  # 16-bit
\t.elseif \\value == 32
\t\tcmpl \operand, (%r11)  # 32-bit
\t.elseif \\value == 64
\t\tcmpq \operand, (%r11)  # 64-bit
\t.endif
\tmovq  $0, %r11   # flag-neutral (xor would clobber the flags of cmp/and/add)
.endm

.macro cmp_load_gs operand, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tcmpb (%r11), \operand  # 8-bit 
\t.elseif \\value == 16
\t\tcmpw (%r11), \operand  # 16-bit
\t.elseif \\value == 32
\t\tcmpl (%r11), \operand  # 32-bit
\t.elseif \\value == 64
\t\tcmpq (%r11), \operand  # 64-bit
\t.endif
\tmovq  $0, %r11   # flag-neutral (xor would clobber the flags of cmp/and/add)
.endm

.macro and_store_gs operand, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tandb \operand, (%r11)  # 8-bit 
\t.elseif \\value == 16
\t\tandw \operand, (%r11)  # 16-bit
\t.elseif \\value == 32
\t\tandl \operand, (%r11)  # 32-bit
\t.elseif \\value == 64
\t\tandq \operand, (%r11)  # 64-bit
\t.endif
\tmovq  $0, %r11   # flag-neutral (xor would clobber the flags of cmp/and/add)
.endm

.macro and_load_gs operand, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tandb (%r11), \operand  # 8-bit 
\t.elseif \\value == 16
\t\tandw (%r11), \operand  # 16-bit
\t.elseif \\value == 32
\t\tandl (%r11), \operand  # 32-bit
\t.elseif \\value == 64
\t\tandq (%r11), \operand  # 64-bit
\t.endif
\tmovq  $0, %r11   # flag-neutral (xor would clobber the flags of cmp/and/add)
.endm

# Arithmetic macros
# ---- Addition ---- #
.macro add_store_gs operand, offset, value
\trdgsbase %r10
\tmov	\offset(%r10), %r10 
\trdgsbase %r11
\tmov	\offset(%r11), %r11
\tmov (%r11), %r11
\t.if \\value == 8
\tadd \\operand, %r11b  # 8-bit 
\tmov %r11b, (%r10)
\t.elseif \\value == 16
\tadd \\operand, %r11w  # 16-bit 
\tmov %r11w, (%r10)
\t.elseif \\value == 32
\tadd \\operand, %r11d  # 32-bit 
\tmov %r11d, (%r10)
\t.elseif \\value == 64
\tadd \\operand, %r11   # 64-bit 
\tmov %r11, (%r10)
\t.endif
\tmovq  $0, %r10
\tmovq  $0, %r11   # flag-neutral (xor would clobber the flags of cmp/and/add)
.endm

.macro add_load_gs dest, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\tmov (%r11), %r11b
\tadd %r11b, \dest  # 8-bit 
\t.elseif \\value == 16
\tmov (%r11), %r11w
\tadd %r11w, \dest  # 16-bit 
\t.elseif \\value == 32
\tmov (%r11), %r11d
\tadd %r11d, \dest  # 32-bit 
\t.elseif \\value == 64
\tmov (%r11), %r11
\tadd %r11, \dest   # 64-bit 
\t.endif
\tmovq  $0, %r11   # flag-neutral (xor would clobber the flags of cmp/and/add)
.endm

# ---- Subtraction ---- #
.macro sub_store_gs operand, offset, value
\trdgsbase %r10
\tmov	\offset(%r10), %r10 
\trdgsbase %r11
\tmov	\offset(%r11), %r11
\tmov (%r11), %r11
\t.if \\value == 8
\tsub \\operand, %r11b  # 8-bit 
\tmov %r11b, (%r10)
\t.elseif \\value == 16
\tsub \\operand, %r11w  # 16-bit 
\tmov %r11w, (%r10)
\t.elseif \\value == 32
\tsub \\operand, %r11d  # 32-bit 
\tmov %r11d, (%r10)
\t.elseif \\value == 64
\tsub \\operand, %r11   # 64-bit 
\tmov %r11, (%r10)
\t.endif
\tmovq  $0, %r10
\tmovq  $0, %r11   # flag-neutral (xor would clobber the flags of cmp/and/add)
.endm

.macro sub_load_gs dest, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\tmov (%r11), %r11b
\tsub %r11b, \dest  # 8-bit 
\t.elseif \\value == 16
\tmov (%r11), %r11w
\tsub %r11w, \dest  # 16-bit 
\t.elseif \\value == 32
\tmov (%r11), %r11d
\tsub %r11d, \dest  # 32-bit 
\t.elseif \\value == 64
\tmov (%r11), %r11
\tsub %r11, \dest   # 64-bit 
\t.endif
\tmovq  $0, %r11   # flag-neutral (xor would clobber the flags of cmp/and/add)
.endm

# ---- Multiplication ---- #
.macro imul_store_gs operand, offset, value
\trdgsbase %r10
\tmov	\offset(%r10), %r10 
\trdgsbase %r11
\tmov	\offset(%r11), %r11
\t.if \\value == 8
\tmov (%r11), %r11b   # (multiply the page's value, in %r11, not the 6th-argument register %r9)
\timul \\operand, %r11b  # 8-bit 
\tmov %r11b, (%r10)
\t.elseif \\value == 16
\tmov (%r11), %r11w
\timul \\operand, %r11w  # 16-bit 
\tmov %r11w, (%r10)
\t.elseif \\value == 32
\tmov (%r11), %r11d
\timul \\operand, %r11d  # 32-bit 
\tmov %r11d, (%r10)
\t.elseif \\value == 64
\tmov (%r11), %r11
\timul \\operand, %r11   # 64-bit 
\tmov %r11, (%r10)
\t.endif
\tmovq  $0, %r10
\tmovq  $0, %r11   # flag-neutral (xor would clobber the flags of cmp/and/add)
.endm

.macro imul_load_gs dest, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\tmov (%r11), %r10b
\timul %r10b, \dest  # 8-bit 
\t.elseif \\value == 16
\tmov (%r11), %r10w
\timul %r10w, \dest  # 16-bit 
\t.elseif \\value == 32
\tmov (%r11), %r10d
\timul %r10d, \dest  # 32-bit 
\t.elseif \\value == 64
\tmov (%r11), %r10
\timul %r10, \dest   # 64-bit 
\t.endif
\tmovq  $0, %r10
\tmovq  $0, %r11   # flag-neutral (xor would clobber the flags of cmp/and/add)
.endm

.macro shl_store_gs operand, offset, value
\trdgsbase %r10
\tmov	\offset(%r10), %r10 
\trdgsbase %r11
\tmov	\offset(%r11), %r11
\tmov (%r11), %r11
\t.if \\value == 8
\tshl \\operand, %r11b  # 8-bit 
\tmov %r11b, (%r10)
\t.elseif \\value == 16
\tshl \\operand, %r11w  # 16-bit 
\tmov %r11w, (%r10)
\t.elseif \\value == 32
\tshl \\operand, %r11d  # 32-bit 
\tmov %r11d, (%r10)
\t.elseif \\value == 64
\tshl \\operand, %r11   # 64-bit 
\tmov %r11, (%r10)
\t.endif
\tmovq  $0, %r10
\tmovq  $0, %r11   # flag-neutral (xor would clobber the flags of cmp/and/add)
.endm
"""

def traverse_ast(tgt_ast, bn_var_info, depth):
    # logger.debug("Traversing the AST to patch")
    # parse_ast(tgt_ast)
    # print("Depth = ", depth)
    
    if repr(tgt_ast.right) == 'BnSSAOp':
        return traverse_ast(tgt_ast.right, bn_var_info, depth+1)
                        
    if repr(tgt_ast.left) == 'RegNode' and depth != 0:
        for var in bn_var_info:
            var_ast = var.asm_syntax_tree
            try:
                if var_ast.left.value == tgt_ast.left.value:
                    # print("Found", tgt_ast.left.value)
                    return var
            except Exception as err:
                None
    else:
        return None
    
# This list will contain lea_store_gs insts that will be used to update the value after reference returns
lea_list = list()
patch_inst_list = list()
arg_reg = list() # This is used as a stack to keep track of what prev instruction register was.

def check_arg_reg(input_reg):
    # If empty, just return false
    if len(arg_reg) < 1:
        return False
    
    arg_reg_regex   = r"\b(e(di|si)|r(di|si|dx|cx|8|9))\b"
    entire_reg = None
    suffix_reg = None

    matches = re.findall(arg_reg_regex, input_reg)
    for match in matches:
        entire_reg = match[0]
        suffix_reg = match[2]
        
    logger.info("Checking arg reg: %s | %s - %s | %s", input_reg, entire_reg, suffix_reg, arg_reg[-1])
    if suffix_reg == "di":
        return True
    elif suffix_reg == "si":
        if arg_reg[-1] == "%rdi" or arg_reg[-1] == "%edi":
            return True
        else:
            return False
    elif suffix_reg == "dx":
        if arg_reg[-1] == "%rsi" or arg_reg[-1] == "%esi":
            return True
        else:
            return False
    elif suffix_reg == "cx":
        if arg_reg[-1] == "%rdx" or arg_reg[-1] == "%edx":
            return True
        else:
            return False
    elif entire_reg == "r8":
        if arg_reg[-1] == "%rcx" or arg_reg[-1] == "%ecx":
            return True
        else:
            return False
    elif entire_reg == "r9":
        if arg_reg[-1] == "%r8":
            return True
        else:
            return False

metadata_number = 0

def struct_member_target(offset_expr, offset_targets, dwarf_var_info):
    """If offset_expr (e.g. -24(%rbp)) lies strictly inside an aggregate variable (struct, array,
    union) that has a table slot, return (slot, displacement from its base, variable name), else
    None."""
    m = re.match(r"(-?\d+)\(%rbp\)$", str(offset_expr))
    if not m or not dwarf_var_info:
        return None
    acc = int(m.group(1))
    for var in dwarf_var_info:
        if var.offset_expr is None:
            continue
        if getattr(var, "struct", None) is not None:
            size = struct_size(var.struct)
        elif getattr(var, "kind", None) in ("array", "union", "struct"):
            size = var.size
        else:
            continue
        for target_expr, slot in offset_targets:
            if target_expr != var.offset_expr:
                continue
            base = int(var.offset)
            if size and base < acc < base + int(size):
                return slot, acc - base, var.name
    return None

def struct_size(st):
    if getattr(st, "size", None):
        return int(st.size)
    try:   # StructBegin/StructEnd are "-0x220"-style strings
        return int(str(st.end), 0) - int(str(st.begin), 0)
    except Exception:
        return None

def patch_member_inst(dis_inst, temp_inst, bn_var, slot, disp):
    """Rewrite a mov to/from, or a lea of, an address inside an aggregate's slot (a struct member,
    a constant-index element) as mov_mem_{store,load}_gs reg, slot, disp, width or
    lea_mem_gs reg, slot, disp (the slot's page address plus the displacement). Other forms are
    left unchanged and reported (tree_uncovered then keeps the variable on the stack)."""
    off_regex = r"(-|\$|)(-?[0-9].*\(%r..*\))"
    if bn_var.patch_inst.inst_type == "lea":
        if bn_var.patch_inst.suffix not in ("q", "") or not re.match(r"%r\w+$", str(temp_inst.dest)):
            logger.error("Member address not rewritten (not a 64-bit lea): %s", dis_inst.strip())
            return None
        return re.sub(r"(\b[a-z]+\b).*", "# %s\tlea_mem_gs\t%s, %d, %d" %
                      (dis_inst, temp_inst.dest, slot, disp), dis_inst)
    kind = bn_var.patch_inst.inst_type
    if kind not in ("mov", "movzx", "cmp"):
        logger.error("Struct member access not rewritten (unsupported form): %s", dis_inst.strip())
        return None
    value = {"b": 8, "w": 16, "l": 32, "q": 64}.get(bn_var.patch_inst.suffix, 0)
    if value == 0 or (kind == "movzx" and value > 16):
        logger.error("Struct member access not rewritten (unknown width): %s", dis_inst.strip())
        return None
    if kind == "movzx":
        if not re.search(off_regex, bn_var.patch_inst.src):
            return None
        return re.sub(r"(\b[a-z]+\b).*", "# %s\tmovzx_mem_load_gs\t%s, %d, %d, %d" %
                      (dis_inst, temp_inst.dest, slot, disp, value), dis_inst)
    if kind == "cmp":      # (both read the member; the original is replaced)
        if re.search(off_regex, bn_var.patch_inst.dest):
            return re.sub(r"(\b[a-z]+\b).*", "# %s\tcmp_mem_store_gs\t%s, %d, %d, %d" %
                          (dis_inst, temp_inst.src, slot, disp, value), dis_inst)
        if re.search(off_regex, bn_var.patch_inst.src):
            return re.sub(r"(\b[a-z]+\b).*", "# %s\tcmp_mem_load_gs\t%s, %d, %d, %d" %
                          (dis_inst, temp_inst.dest, slot, disp, value), dis_inst)
        return None
    if re.search(off_regex, bn_var.patch_inst.dest):      # store: replace the stack write (tree mode)
        return re.sub(r"(\b[a-z]+\b).*", "# %s\tmov_mem_store_gs\t%s, %d, %d, %d" %
                      (dis_inst, temp_inst.src, slot, disp, value), dis_inst)
    if re.search(off_regex, bn_var.patch_inst.src):       # load: replace the original
        return re.sub(r"(\b[a-z]+\b).*", "# %s\tmov_mem_load_gs\t%s, %d, %d, %d" %
                      (dis_inst, temp_inst.dest, slot, disp, value), dis_inst)
    return None

def patch_inst(dis_inst, temp_inst: PatchingInst, bn_var, bn_var_info: list, tgt_offset, dwarf_var_info, offset_targets: set):
    logger.critical("Patch the instruction %s | Offset: %d", dis_inst, tgt_offset)
    # parse_ast(bn_var.asm_syntax_tree)
    global metadata_number
    off_regex       = r"(-|\$|)(-?[0-9].*\(%r..*\))"
    array_regex = r"(-\d+)\((%\w+)(?:\+(%\w+))?\)"
    #offset_expr_regex = r'(\-[0-9].*)\((.*)\)'
    offset_expr_regex = r'(-[0-9]+)\((%rbp)(,%r[a-d]x)?\)'
    store_or_load   = str()
    if re.search(off_regex, bn_var.patch_inst.src):
        store_or_load = "load"
    elif re.search(off_regex, bn_var.patch_inst.dest):
        store_or_load = "store"

    arr_regex = None
    # print(bn_var.patch_inst.dest)
    if store_or_load == "load":
        arr_regex = re.search(array_regex, bn_var.patch_inst.src)
    elif store_or_load == "store":
        arr_regex = re.search(array_regex, bn_var.patch_inst.dest)
        
    tgt_ast = bn_var.asm_syntax_tree
    # print(bn_var, store_or_load)
    line = None
    patch_inst_line = None
    # print(bn_var.patch_inst.inst_print())
    
                
    # (an unconditional jmp: "test %r11, %r11; jz" clobbered the flags a later jcc/setcc reads)
    metadata_template = """jmp\tverifier_metadata_{0}
    # The replaced instruction (for metadata purposes only)
{1}verifier_metadata_{0}:
"""
    verifier_metadata = metadata_template.format(metadata_number, dis_inst)

    ssa_var = traverse_ast(tgt_ast, bn_var_info, 0)
    if ssa_var != None:
        # Found SSA register    
        if ssa_var.patch_inst.inst_type == "lea":
            new_inst_type = "lea_gs"
            logger.info("Patching with lea_gs w/ base obj")
            # line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d" % 
            #             (dis_inst, new_inst_type, temp_inst.dest, tgt_offset), dis_inst)
            line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d" % 
                        (verifier_metadata, new_inst_type, temp_inst.dest, tgt_offset), dis_inst)
            patch_inst_line = "\t%s\t%s, %d" % (new_inst_type, temp_inst.dest, tgt_offset)
            # logger.debug(temp_inst.inst_print())
            # logger.debug(bn_var)
    else:
        if bn_var.patch_inst.inst_type == "lea":
            new_inst_type = "lea_gs"
            logger.info("Patching with lea_gs w/o base obj")
            # If there is no stack offset being set as a value, we cannot use the LEA_GS for such case
            for var_item in bn_var_info:
                # print(bn_var)
                if var_item.offset_expr == temp_inst.dest:
                    if repr(var_item.asm_syntax_tree.left) == 'BnSSAOp':
                        # If left is a stack offset, extract the offset value and check whether it is being set
                        offset_num = var_item.asm_syntax_tree.left.right.value
                        offset_reg = re.search(offset_expr_regex, var_item.offset_expr)
                        base_offset = offset_reg.group(1)
                        array_indx  = offset_reg.group(3)
                        if array_indx != None:
                            logger.critical("Array found")
                        if offset_num == base_offset:
                            # If stack offset is set before, then it is safe to use the new macro
                            line = re.sub(r"(\b[a-z]+\b).*", "# %s\t%s\t%s, %d" % 
                            (dis_inst, new_inst_type, temp_inst.dest, tgt_offset), dis_inst)
                            patch_inst_line = "\t%s\t%s, %d" % (new_inst_type, temp_inst.dest, tgt_offset)
                else:
                    # Else, we need to use the original stack offset.
                    # line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d" % 
                    #         (dis_inst, new_inst_type, temp_inst.dest, tgt_offset), dis_inst)
                    line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d" % 
                            (verifier_metadata, new_inst_type, temp_inst.dest, tgt_offset), dis_inst)
                    patch_inst_line = "\t%s\t%s, %d" % (new_inst_type, temp_inst.dest, tgt_offset)
                    
    if line == None:
        # If line is None by now, it means patching without any context register
        value = 0
        if bn_var.patch_inst.suffix == "b":
            value = 8
        elif bn_var.patch_inst.suffix == "w":
            value = 16
        elif bn_var.patch_inst.suffix == "l":
            value = 32
        elif bn_var.patch_inst.suffix == "q":
            value = 64
        # Only store should comment out macro to update value, loading value should be from the page
        if bn_var.patch_inst.inst_type == "mov":
            logger.debug(store_or_load)
            # if arr_regex != None and arr_regex.group(3) == None: # Disabling array support due to challenge of not being able to update specific array value
            logger.info("Patching with mov_gs")
            if arr_regex != None and arr_regex.group(3) != None:
                logger.info("Patching with mov_arr_gs")
                if store_or_load == "store":
                    new_inst_type = "mov_arr_store_gs"
                    line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %s, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, arr_regex.group(3), value), dis_inst)
                    patch_inst_line = "\t%s\t%s, %d, %s, %d" % (new_inst_type, temp_inst.src, tgt_offset, arr_regex.group(3), value)
                elif store_or_load == "load":
                    new_inst_type = "mov_arr_load_gs"
                    line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %s, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, arr_regex.group(3), value), dis_inst)
                    patch_inst_line = "\t%s\t%s, %d, %s, %d" % (new_inst_type, temp_inst.dest, tgt_offset, arr_regex.group(3), value)
            else:
                # We only need to check store instructions as that is the one deals with register offset at the beginning
                if store_or_load == "store":
                        new_inst_type = "mov_store_gs" # Need to think about how to make this work for NGINX
                        # line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t#%s\t%s, %d, %d" % 
                        #                 (dis_inst, verifier_metadata, new_inst_type, 
                        #                 temp_inst.src, tgt_offset, value), dis_inst)
                        line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % 
                                        (verifier_metadata, new_inst_type, 
                                        temp_inst.src, tgt_offset, value), dis_inst)
                        patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
                elif store_or_load == "load":
                    new_inst_type = "mov_load_gs"
                    logger.debug(bn_var)
                    for var in dwarf_var_info:
                        if var.offset_expr == bn_var.offset_expr:
                            # Found that base struct object is being copied into a value, then, just load stack offset
                            if var.struct != None:
                                logger.error("Found struct object")
                                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
                            else:
                                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
                    if line == None:
                        line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                        patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type in ("movss", "movsd"):
            if store_or_load == "store":
                new_inst_type = bn_var.patch_inst.inst_type + "_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = bn_var.patch_inst.inst_type + "_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "movzx":
            logger.info("Patching with movzx_gs")
            if store_or_load == "store":
                new_inst_type = "movzx_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "movzx_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "add":
            logger.info("Patching with add_gs")
            if store_or_load == "store":
                new_inst_type = "add_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "add_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "sub":
            logger.info("Patching with sub_gs")
            if store_or_load == "store":
                new_inst_type = "sub_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "sub_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "imul": # Signed multiply (two's comp arith)
            logger.info("Patching with imul_gs")
            if store_or_load == "store":
                new_inst_type = "imul_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "imul_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "shl": # shift left
            logger.info("Patching with shl_gs")
            if store_or_load == "store":
                new_inst_type = "shl_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "shl_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "cmp":
            logger.info("Patching with cmp_gs")
            if store_or_load == "store":
                new_inst_type = "cmp_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "cmp_load_gs"
                # (replaces the stack read: in tree mode the stack copy is not kept current)
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "and":
            logger.info("Patching with and_gs")
            if store_or_load == "store":
                new_inst_type = "and_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "and_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
            
    if line != None:
        metadata_number += 1
        patch_inst_list.append(patch_inst_line)
        return line
    
def remove_duplicate_lines(lines):
    """
    Remove duplicate lines from a list while preserving the order.
    
    :param lines: List of lines (strings)
    :return: List of lines with duplicates removed
    """
    seen = set()
    result = []
    for line in lines:
        if line not in seen:
            result.append(line)
            seen.add(line)
    return result
  

# ---- Variables this design cannot keep consistent ----
# Here a rewritten store replaces the stack write and a slot's lea is redirected to its page, so a
# variable lives only in its page, and an access that is not rewritten reads or writes a stack
# copy that nothing keeps current. Such a variable stays on the stack (not compartmentalised):
#   - every variable of a recursive function: a page is per variable, not per activation, so an
#     inner activation would overwrite the caller's values (Reentry);
#   - a variable with an access the rewriter does not redirect: an indexed element
#     (-144(%rbp,%rax,8)), an instruction outside the rewritten forms (shr, xor, movsd, push, ...),
#     an interior offset of an array or union, or anything but a mov at a struct member's offset.
# Security: such a variable has no compartment, as if it had not been selected.

inst_prefixes = {"lock", "notrack", "rep", "repe", "repz", "repne", "repnz", "data16"}
mem_operand_regex = re.compile(r'^\*?(?:%[a-z]s:)?([-\w.+$]*)\((%\w+)?(?:,(%\w+))?(?:,(\d+))?\)$')
def split_operands(text):
    """AT&T operands of an instruction (commas inside parentheses are not separators)."""
    text = text.strip()
    return [op.strip() for op in re.split(r',(?![^(]*\))', text)] if text else []

def parse_inst(line):
    """(mnemonic, operands) of an instruction line; None for a label, a directive or a comment."""
    text = line.split('#', 1)[0].strip()
    if text == "" or text.startswith('.') or text.endswith(':'):
        return None
    parts = text.split(None, 1)
    mnem, rest = parts[0], (parts[1] if len(parts) > 1 else "")
    while mnem in inst_prefixes and rest:
        if mnem.startswith("rep"):
            # rep stos/movs write through %rdi
            return ("rep_" + rest.split()[0], [])
        parts = rest.split(None, 1)
        mnem, rest = parts[0], (parts[1] if len(parts) > 1 else "")
    return (mnem, split_operands(rest))

def mem_operand(op):
    """('frame', disp) for -N(%rbp), ('indexed', disp) for -N(%rbp,%reg,s), ('pointer', None) for
    any other register base, (None, None) for a register, an immediate, a global (%rip), TLS or
    an outgoing argument (%rsp)."""
    m = mem_operand_regex.match(op.strip())
    if m is None:
        return (None, None)
    disp, base, index = m.group(1), m.group(2), m.group(3)
    if base in ("%rip", "%rsp", "%esp"):
        return (None, None)
    if base == "%rbp":
        try:
            d = int(disp, 0) if disp else 0
        except ValueError:
            return ("pointer", None)
        return ("indexed" if index else "frame", d)
    return ("pointer", None)

def frame_disp(offset_expr):
    m = re.match(r'(-?\d+)\(%rbp\)$', str(offset_expr))
    return int(m.group(1)) if m else None

def tarjan_scc(nodes, edges):
    """Strongly connected components (iterative Tarjan), as node -> frozenset."""
    index, low, on_stack, stack, scc_of = {}, {}, set(), [], {}
    counter = 0
    for root in nodes:
        if root in index:
            continue
        work = [(root, iter(sorted(edges.get(root, ()))))]
        index[root] = low[root] = counter; counter += 1
        stack.append(root); on_stack.add(root)
        while work:
            node, it = work[-1]
            advanced = False
            for nxt in it:
                if nxt not in index:
                    index[nxt] = low[nxt] = counter; counter += 1
                    stack.append(nxt); on_stack.add(nxt)
                    work.append((nxt, iter(sorted(edges.get(nxt, ())))))
                    advanced = True
                    break
                elif nxt in on_stack:
                    low[node] = min(low[node], index[nxt])
            if advanced:
                continue
            work.pop()
            if work:
                low[work[-1][0]] = min(low[work[-1][0]], low[node])
            if low[node] == index[node]:
                comp = set()
                while True:
                    member = stack.pop(); on_stack.discard(member); comp.add(member)
                    if member == node:
                        break
                comp = frozenset(comp)
                for member in comp:
                    scc_of[member] = comp
    return scc_of

class Reentry:
    """Which calls can re-enter the calling function, from the call graph of a program's assembly
    (every .s of its objects). Edges: a direct call; a reference to a function's address (passing
    a callback to qsort, signal or atexit: whoever gets it can call it); an indirect call reaches
    every function whose address is taken. External code (libc, gnulib archives) is not in the
    graph: it is assumed to enter the program only through a function whose address was taken.
    Only re-entry on the same thread and outside a signal handler shares pages: table.c gives
    every thread and every handler nesting level a page set of its own (gen_table.py)."""
    def __init__(self, asm_paths):
        type_regex = re.compile(r'^\s*\.type\s+([\w.$]+),\s*@function')
        ident_regex = re.compile(r'(?<![%\w.])([A-Za-z_][\w.$]*)')
        data_regex = re.compile(r'\.(quad|long|8byte|4byte|int|set|equ|weakref|value|word)\b')
        texts = []
        for path in asm_paths:
            path = str(path)
            # The rewriter starts from the .bak copy when there is one (an earlier run's input)
            src = path + ".bak" if os.path.isfile(path + ".bak") else path
            with open(src, encoding="utf-8", errors="replace") as f:
                texts.append(f.read().splitlines())
        self.defined = set()
        for lines in texts:
            for line in lines:
                m = type_regex.match(line)
                if m:
                    self.defined.add(m.group(1))
        self.edges = {f: set() for f in self.defined}
        self.addr_taken = set()
        indirect = set()
        for lines in texts:
            cur = None
            for line in lines:
                text = line.split('#', 1)[0].strip()
                if text == "":
                    continue
                if text.endswith(':') and text[:-1] in self.defined:
                    cur = text[:-1]
                    continue
                if text.startswith(".cfi_endproc"):
                    cur = None
                    continue
                if text.startswith('.'):
                    # Function addresses in data (tables of handlers, .set aliases)
                    if data_regex.match(text):
                        for name in ident_regex.findall(text.split(None, 1)[-1]):
                            if name in self.defined:
                                self.addr_taken.add(name)
                                if cur:
                                    self.edges[cur].add(name)
                    continue
                inst = parse_inst(text)
                if inst is None:
                    continue
                mnem, ops = inst
                if mnem.startswith("call") and ops:
                    if ops[0].startswith('*'):
                        if cur:
                            indirect.add(cur)
                    else:
                        name = ops[0].split('@')[0]
                        if cur and name in self.defined:
                            self.edges[cur].add(name)
                    continue
                for name in ident_regex.findall(",".join(ops)):
                    if name in self.defined:
                        self.addr_taken.add(name)
                        if cur:
                            self.edges[cur].add(name)
        for f in indirect:
            self.edges[f] |= self.addr_taken
        self.scc_of = tarjan_scc(sorted(self.defined), self.edges)
        self.recursive = {f for f in self.defined if len(self.scc_of[f]) > 1 or f in self.edges[f]}
        logger.warning("consistency: recursive functions (activations on one thread share pages): %s",
                       ", ".join(sorted(self.recursive)) or "none")

    def reenters(self, fun, target):
        """Whether `call target` in fun can run fun again before it returns."""
        if fun not in self.recursive:
            return False
        scc = self.scc_of[fun]
        target = target.strip()
        if target.startswith('*'):
            return len(scc & self.addr_taken) > 0
        name = target.split('@')[0]
        if name in self.defined:
            return name in scc
        return len(scc & self.addr_taken) > 0


# Instruction forms the loop below rewrites (its dis_line_regex; a call through a slot is not)
tree_rewritten_regex = re.compile(r'(mov|movz|lea|sub|add|cmp|sal|and|imul|movss|movsd)([l|b|w|q|bl|xw|wl]*)$')

gpr_bytes_regex = re.compile(r'%(r\d+[dwb]?|[re]?[abcd]x|[abcd]l|[re]?(si|di|sp|bp)l?)$')
extend_regex = re.compile(r'movs?z?([bwl])[wlq]$')
def access_bytes(mnem, ops):
    """Bytes a memory operand of the instruction covers (8 when it cannot be told)."""
    if re.match(r'lea[wlq]?$', mnem):
        return 1           # (an address, not an access: it names the variable that starts there)
    if mnem in ("fnstcw", "fstcw", "fldcw", "fnstsw", "fstsw"):
        return 2
    if mnem.startswith("fi"):                          # fild/fist(p)/fisttp: s, l, ll/q
        return {"s": 2, "l": 4, "q": 8}.get(mnem[-1:], 8)
    if mnem.startswith("f"):                           # fld/fst(p): s, l, t
        return {"s": 4, "l": 8, "t": 10}.get(mnem[-1:], 10)
    m = extend_regex.match(mnem)
    if m and mnem not in ("movsl", "movsw", "movsq"):    # movzbl, movswl, movslq: the source's width
        return {"b": 1, "w": 2, "l": 4}[m.group(1)]
    for op in ops:
        if gpr_bytes_regex.match(op):
            r = op[1:]
            if r[0] == "r" and r[-1] in "dwb" and r[1:-1].isdigit():
                return {"d": 4, "w": 2, "b": 1}[r[-1]]
            if r.startswith("r"):
                return 8
            if r.startswith("e"):
                return 4
            return 1 if r.endswith("l") else 2
    if mnem in ("movq", "movd"):        # (to or from an %xmm register)
        return 8 if mnem == "movq" else 4
    if mnem.endswith("ss") or re.match(r'cvt.*l$', mnem):
        return 4
    if mnem.endswith("sd") or re.match(r'cvt.*q$', mnem):
        return 8
    if "%xmm" in " ".join(ops):
        return 16
    return {"b": 1, "w": 2, "l": 4, "q": 8, "t": 10}.get(mnem[-1:], 8)

def slot_ranges(dwarf_var_info, exprs):
    """slot expr -> (start, end, struct, aggregate): the frame bytes each slot's page holds."""
    ranges = dict()
    for var in dwarf_var_info or []:
        start = frame_disp(var.offset_expr)
        if var.offset_expr in exprs and start is not None:
            size = struct_size(var.struct) if var.struct is not None else var.size
            aggregate = var.struct is not None or getattr(var, "kind", None) in ("array", "union", "struct")
            old = ranges.get(var.offset_expr)
            end = start + int(size or 8)
            ranges[var.offset_expr] = (start, max(end, old[1]) if old else end, var.struct is not None, aggregate)
    return ranges

def slots_touched(mnem, ops, ranges, starts=()):
    """[(slot expr, kind, disp)] of the slots an instruction's frame operands reach; a lea of an
    aggregate's one-past-the-end address (buf + sizeof buf) counts as reaching it, unless another
    variable starts there (then it is that variable's address)."""
    hit = []
    w = access_bytes(mnem, ops)
    for op in ops:
        kind, disp = mem_operand(op)
        if kind not in ("frame", "indexed"):
            continue
        for expr, (start, end, is_struct, aggregate) in ranges.items():
            if disp < end and disp + w > start:
                hit.append((expr, kind, disp))
            elif aggregate and disp == end and disp not in starts and re.match(r'lea[wlq]?$', mnem):
                hit.append((expr, kind, disp))
    return hit


jump_regex = re.compile(r'^j[a-z]+$')
def macro_reg_live(body, reg):
    """(first, last) line index between which the function may hold a value of its own in reg
    (%r10 or %r11; (1, 0) if it never uses it): from the first to the last line naming it,
    extended to a later jump back into that span (a loop that carries the value around)."""
    named_regex = re.compile(r'%' + reg + r'[dwb]?\b')
    named = [i for i, l in enumerate(body) if named_regex.search(l.split('#', 1)[0])]
    if not named:
        return (1, 0)
    first, last = named[0], named[-1]
    labels = {l.strip()[:-1]: i for i, l in enumerate(body) if l.strip().endswith(':')}
    changed = True
    while changed:
        changed = False
        for i in range(last + 1, len(body)):
            inst = parse_inst(body[i])
            if inst and jump_regex.match(inst[0]) and inst[1]:
                t = labels.get(inst[1][0])
                if t is not None and first <= t <= last:
                    last, changed = i, True
    return (first, last)

# The macros for these forms also use %r10 (add/sub/imul/shl_store_gs, imul_load_gs); all use %r11
uses_r10_regex = re.compile(r'(add|sub|imul|sal|shl)')

# %rbp itself copied or computed with (not the prologue/epilogue, not a frame operand): the frame's
# address is then in another register, and any slot can be reached through it
frame_regs_ok = {("push", ("%rbp",)), ("pushq", ("%rbp",)), ("pop", ("%rbp",)), ("popq", ("%rbp",)),
                 ("movq", ("%rsp", "%rbp")), ("mov", ("%rsp", "%rbp")), ("movq", ("%rbp", "%rsp")), ("mov", ("%rbp", "%rsp"))}
def var_extents(dwarf_var_info):
    """[(start, end, aggregate)] of every frame variable of a function."""
    out = []
    for var in dwarf_var_info or []:
        start = frame_disp(var.offset_expr)
        if start is not None:
            size = struct_size(var.struct) if var.struct is not None else var.size
            aggregate = var.struct is not None or getattr(var, "kind", None) in ("array", "union", "struct")
            out.append((start, start + int(size or 8), aggregate))
    return out

push_regex = re.compile(r'pushq?$')
xmm0_save_regex = re.compile(r'movaps$')
def frame_anchors(insts, extents):
    """The lea instructions (of insts, [(mnemonic, operands)] in order) that take a frame address
    no variable holds: gcc -O0 indexes a multi-dimensional array from such an "anchor"
    (leaq -16(%rbp),%rsi; addq %rsi,%rax; subq $32,%rax; movl %ecx,(%rax) is alt[i][0]), so any
    slot of the frame can be reached through it. The anchor is the top of the local area, below
    the callee-saved pushes, which may be one past the end of the topmost variable: an address at
    or above it is an anchor even then. Not anchors: the epilogue's leaq -N(%rbp),%rsp, and
    va_start's two addresses (the register save area that gcc's variadic prologue fills, and the
    stack arguments at 16(%rbp) and up) stored straight into the va_list: va_arg reads only
    within those areas, and no variable lies there."""
    pushes, saw_frame = 0, False
    save_area = None
    for mnem, ops in insts:     # (the pushes right after movq %rsp,%rbp)
        if (mnem, tuple(ops)) in (("movq", ("%rsp", "%rbp")), ("mov", ("%rsp", "%rbp"))):
            saw_frame = True
        elif saw_frame and push_regex.match(mnem) and len(ops) == 1 and ops[0].startswith("%"):
            pushes += 1
        elif saw_frame:
            break
    for i, (mnem, ops) in enumerate(insts):
        # gcc's variadic prologue: testb %al,%al; je; movaps %xmm0,B+48(%rbp) .. %xmm7
        if mnem == "testb" and ops == ["%al", "%al"] and i + 2 < len(insts) and xmm0_save_regex.match(insts[i + 2][0]) \
                and insts[i + 2][1][:1] == ["%xmm0"]:
            kind, disp = mem_operand(insts[i + 2][1][1])
            if kind == "frame":
                save_area = (disp - 48, disp - 48 + 176)
            break
    if save_area and any(s < save_area[1] and e > save_area[0] for s, e, _ in extents):
        save_area = None
    top = -8 * pushes
    found = []
    for i, (mnem, ops) in enumerate(insts):
        if not re.match(r'lea[wlq]?$', mnem) or len(ops) != 2:
            continue
        kind, disp = mem_operand(ops[0])
        if kind not in ("frame", "indexed") or ops[1] in ("%rsp", "%esp"):
            continue
        inside = any(s <= disp < e for s, e, _ in extents)
        one_past = any(agg and disp == e for s, e, agg in extents)
        if inside and (disp < top or disp > 0):
            continue        # (a variable's address, or a stack parameter's)
        if one_past and kind == "frame" and disp < top:
            continue
        if save_area and kind == "frame" and (disp == save_area[0] or disp >= 16) and i + 1 < len(insts):
            nm, nops = insts[i + 1]
            if nops[:1] == [ops[1]] and ((nm in ("movq", "mov") and len(nops) == 2 and mem_operand(nops[1])[0] == "frame")
                                         or re.match(r'mov\w*_store_gs$', nm)):
                continue    # (va_start; rewritten, the store into the va_list's page)
        found.append((mnem, ops))
    return found

def tree_stack_only(fun, dwarf_var_info, offset_targets, body, reentry, extra=None, log=True):
    """Slot exprs of fun that must stay on the stack (see above), expr -> (reason, instruction),
    each logged (log) as "consistency: <fun>: <expr> stays on the stack (<reason>: <instruction>)".
    extra: slots an earlier pass found an access to that it did not redirect (tree_uncovered)."""
    exprs = {expr for expr, t in offset_targets}
    drop = dict()
    def keep_on_stack(expr, reason, why):
        if expr not in drop:
            drop[expr] = (reason, why)
    if reentry is not None and fun in reentry.recursive:
        for expr in exprs:
            keep_on_stack(expr, "recursive", "activations on one thread share a page")
    for line in body:
        inst = parse_inst(line)
        if inst and "%rbp" in inst[1] and (inst[0], tuple(inst[1])) not in frame_regs_ok:
            for expr in exprs:
                keep_on_stack(expr, "frame-pointer", line.strip())
            break
    insts = [i for i in map(parse_inst, body) if i is not None]
    for mnem, ops in frame_anchors(insts, var_extents(dwarf_var_info))[:1]:
        for expr in exprs:
            keep_on_stack(expr, "frame-anchor", "%s\t%s" % (mnem, ", ".join(ops)))
    for expr, why in (extra or {}).items():
        if expr in exprs:
            keep_on_stack(expr, "unredirected", why)
    ranges = slot_ranges(dwarf_var_info, exprs)
    starts = var_starts(dwarf_var_info)
    live11, live10 = macro_reg_live(body, "r11"), macro_reg_live(body, "r10")
    for idx, line in enumerate(body):
        inst = parse_inst(line)
        if inst is None:
            continue
        mnem, ops = inst
        hits = slots_touched(mnem, ops, ranges, starts)
        # The macros use %r10/%r11 as scratch and zero them: a slot access where the function
        # keeps a value of its own there (the stack-clash probe, an asm statement) cannot be
        # rewritten.
        if hits and (live11[0] <= idx <= live11[1] or
                     (uses_r10_regex.match(mnem) and live10[0] <= idx <= live10[1])):
            for expr, kind, disp in hits:
                keep_on_stack(expr, "r10/r11", line.strip())
            continue
        # (a three-operand form, imul $3, -8(%rbp), %eax, has no macro)
        form = tree_rewritten_regex.match(mnem) if len(ops) <= 2 else None
        for expr, kind, disp in hits:
            start, end, is_struct, aggregate = ranges[expr]
            if kind == "indexed":
                keep_on_stack(expr, "indexed", line.strip())
            elif form is None:
                keep_on_stack(expr, "form", line.strip())
            elif disp == end:
                keep_on_stack(expr, "one-past", line.strip())
            elif disp < start or (disp != start and not (aggregate and form.group(1) in ("mov", "lea", "movz", "cmp"))):
                keep_on_stack(expr, "interior", line.strip())
    if log:
        for expr, (reason, why) in sorted(drop.items()):
            logger.warning("consistency: %s: %s stays on the stack (%s: %s)", fun, expr, reason, why)
    return drop

metadata_jmp_regex = re.compile(r'^\s*jmp\s+(verifier_metadata_\d+)\s*$')
def var_starts(dwarf_var_info):
    return {d for d in (frame_disp(v.offset_expr) for v in dwarf_var_info or []) if d is not None}

def tree_uncovered(out_lines, ranges, table, starts=(), extents=None):
    """Slot exprs the rewritten function still reaches on the stack: any executed instruction
    other than a page macro whose frame operand touches a slot's bytes, and every slot when an
    executed lea takes a frame anchor (frame_anchors; extents: var_extents of the function). Not
    executed: a comment (the replaced original, "#<instruction>") and the copy kept for the
    verifier after "jmp verifier_metadata_N", unless a label inside it can be jumped to. In tree
    mode the page is the only current copy, so such an access reads or writes a stale value (or
    leaves the value on the stack)."""
    found = dict()
    skip_to = None
    executed = []
    lines = [l for l in "".join(out_lines).split("\n")]
    for text in lines:
        if skip_to is not None:
            if text.strip() == skip_to + ":":
                skip_to = None
                continue
            if not text.strip().endswith(":"):
                continue
            skip_to = None      # (a label: what follows it is reachable)
        m = metadata_jmp_regex.match(text)
        if m:
            skip_to = m.group(1)
            continue
        inst = parse_inst(text)
        if inst is None:
            continue
        executed.append(inst)       # (macros too: va_start's store into a va_list slot is one)
        if inst[0].endswith("_gs"):
            continue
        for expr, kind, disp in slots_touched(inst[0], inst[1], ranges, starts):
            found.setdefault(expr, text.strip())
    if extents is not None:
        for mnem, ops in frame_anchors(executed, extents)[:1]:
            for expr in ranges:
                found.setdefault(expr, "%s\t%s" % (mnem, ", ".join(ops)))
    return found

# Per rewritten file: fun -> {slot expr: the instruction} that still reaches a kept slot on the
# stack (tree_uncovered); the caller rewrites the file again with those slots on the stack.
last_uncovered = dict()

def rewriter(funlist, target_dir, target_file, dwarf_fun_var_info, bn_fun_var_info, fun_table_offsets, reentry=None, extra_stack_only=None):
    patch_count = 0
    kept_slots = dict()   # fun -> (slot_ranges, {expr: table offset}) of the slots it redirects
    last_uncovered.clear()
    file_path = None
    if target_dir != None:
        # This is for a single binary c14n. 
        file_path = os.path.join(target_dir, target_file)
        print(file_path)
        debug_file = target_file + ".bak"
        if os.path.isfile(os.path.join(target_dir, debug_file)):
            print("Copying debug file")
            shutil.copyfile(os.path.join(target_dir, debug_file), os.path.join(target_dir, target_file))
        else:
            print("No debug file exists")
    elif target_dir == None:
        # This is for a binary with multiple object files and they are in their own separate location
        file_path = target_file.asm_path
        file_path_dir = os.path.dirname(file_path)
        debug_file = file_path + ".bak"
        if os.path.isfile(debug_file):
            print("Copying debug file")
            shutil.copyfile(debug_file, file_path)
            time.sleep(2)
        else:
            print("No debug file exists")
        # print(file_path, file_path_dir, debug_file)
        # exit()
        
    
    # Each function's own lines, read before rewriting (tree_stack_only looks at all of them)
    fun_bodies = dict()
    with open(file_path, encoding="utf-8") as f:
        body_fun = None
        for body_line in f:
            begin = re.search(r'(?<=.type\t)(.*)(?=,\s@function)', body_line)
            if begin is not None:
                body_fun = begin.group(1)
                fun_bodies[body_fun] = list()
            elif body_fun is not None:
                fun_bodies[body_fun].append(body_line)
                if re.search(r'(\t.cfi_endproc)', body_line):
                    body_fun = None

    debug = False
    with fileinput.input(file_path, 
                            inplace=(not debug), encoding="utf-8", backup='.bak') as f:
        file_pattern = re.compile(r'\.file\s+"([^"]+)"')
        fun_begin_regex = r'(?<=.type\t)(.*)(?=,\s@function)'
        fun_end_regex   = r'(\t.cfi_endproc)'
        
        # An operand is a run of non-space, non-comma characters or a parenthesised group, so
        # "(%rax,%rdx,8)" stays whole and inline asm's "subq -416(%rbp),%rax" (no space) still splits.
        OPERAND = r'((?:[^\s,(]|\([^)]*\))+)'
        dis_line_regex = r'(mov|movz|lea|sub|add|cmp|sal|and|imul|call|movss|movsd)([l|b|w|q|bl|xw|wl]*)\s+' + OPERAND + r'(?:,\s*' + OPERAND + r')?(?:,\s*' + OPERAND + r')?\n'
        # sing_line_regex = r'\t(div)([a-z]*)\t(.*)'
        check = False
        currFun = str()
        patch_targets = list()
        offset_targets = list()
        struct_targets = set()
        
        for line in f:
            if file_pattern.findall(line): #.startswith('\t.file\t"%s.c"' % target_file.rsplit('.', maxsplit=1)[0]):
                print(asm_macros, end='')
            fun_begin = re.search(fun_begin_regex, line)
            if fun_begin is not None:
                if fun_begin.group(1) in funlist:
                    currFun = fun_begin.group(1)
                    logger.warning(currFun)
                    try:
                        dwarf_var_info   = dwarf_fun_var_info[currFun]
                        bninja_info     = bn_fun_var_info[currFun]
                        offset_targets  = fun_table_offsets[currFun]
                        stack_only = tree_stack_only(currFun, dwarf_var_info, offset_targets, fun_bodies.get(currFun, []), reentry,
                                                     (extra_stack_only or {}).get(currFun))
                        offset_targets  = {o for o in offset_targets if o[0] not in stack_only}
                        if offset_targets:
                            kept_slots[currFun] = (slot_ranges(dwarf_var_info, {o[0] for o in offset_targets}),
                                                   {o[0]: o[1] for o in offset_targets}, var_starts(dwarf_var_info),
                                                   var_extents(dwarf_var_info))
                        check = True
                    except Exception as err:
                        logger.error("Skipping %s: %s", currFun, err)
                        check = False
                        
                    if debug:
                        # if currFun != "sort": # Debug
                        #     check = False
                        # else:
                        #     check = True
                        None
                        main.custom_pprint(dwarf_var_info)
                        main.custom_pprint(bninja_info)
                        main.custom_pprint(offset_targets)
                    else:
                        if offset_targets != None:
                            for tgt in offset_targets:
                                logger.warning(tgt)
            fun_end = re.search(fun_end_regex, line)
            if fun_end is not None:
                lea_list.clear() # Clear the lea_list per function and also after rewriting the call instruction
                check = False
                dwarf_var_info = None
                bninja_info = None
                offset_targets = None
        
            if check == True:
                # dis_line = line.rstrip('\n')
                dis_line = line
                # mnemonic source, destination AT&T
                logger.debug(dis_line)
                dis_regex   = re.search(dis_line_regex, dis_line)
                if dis_regex is not None:
                    inst_type   = dis_regex.group(1)
                    suffix      = dis_regex.group(2)
                    src         = dis_regex.group(3)
                    dest        = dis_regex.group(4)
                    # temp_inst = PatchingInst(conv_instr(inst_type), src, dest, expr, suffix)
                    logger.debug("%s %s %s %s", inst_type, suffix, src, dest)
                    # Need to convert movzbl and movzxw to movzx + suffix (b or w)
                    if inst_type == "movz":
                        inst_type = "movzx"
                    elif inst_type == "call" and len(lea_list) > 0:
                        uniq_lea_list = remove_duplicate_lines(lea_list)
                        logger.critical("Patch the instruction %s", dis_line)
                        lea_set_line = ""
                        for lea_inst in uniq_lea_list:
                            lea_set_line += lea_inst
                            patch_count += 1
                        # print(lea_set_line)
                        new_inst = re.sub(r"(\b[a-z]+\b).*", "%s%s" % (dis_line, lea_set_line), dis_line)
                        # Clear the list once your done patching
                        if new_inst != None:
                            print(new_inst, end='')
                        else:
                            print(line, end='')
                        lea_list.clear()
                        uniq_lea_list.clear()
                        continue
                        
                    if suffix == "bl":
                        suffix = "b"
                    elif suffix == "xw" or suffix == "wl":
                        suffix = "w"
                    
                    if dest != None:
                        temp_inst = PatchingInst(inst_type=inst_type, suffix=suffix,
                                                    dest=conv_imm(dest), src=conv_imm(src), ptr_op="")
                    else:
                        # For a single operand assembly instruction (e.g., salq)
                        if inst_type == "sal":
                            temp_inst = PatchingInst(inst_type="shl", suffix=suffix,
                                                    dest=conv_imm(src), src="$1", ptr_op="")
                        else:
                            # Operands the regex cannot split (inline asm writes "subq -416(%rbp),%rax"
                            # without a space): before, temp_inst was still the previous line's, so
                            # that line's patch was emitted here and this instruction was dropped.
                            temp_inst = None
                        
                    if debug:
                        logger.warning(temp_inst.inst_print())
                        if src != None:
                            for offset in offset_targets:
                                if conv_imm(src) == offset[0]:
                                    # logger.warning(temp_inst.inst_print())
                                    logger.warning("Debug found")
                        if dest != None:
                            for offset in offset_targets:
                                if conv_imm(dest) == offset[0]:
                                    # logger.warning(temp_inst.inst_print())
                                    logger.warning("Debug found")
                    new_inst = None
                    
                    for idx, bn_var in enumerate(bninja_info):
                        # logger.warning(bn_var.patch_inst.inst_print())
                        if debug:
                            logger.warning(temp_inst.inst_print())
                            logger.warning(bn_var.offset_expr)
                            logger.warning(bn_var.patch_inst.inst_print())
                            None
                        if temp_inst is not None and temp_inst.inst_check(bn_var.patch_inst):
                            # print("Found\n", temp_inst.inst_print(), "\n", bn_var.patch_inst.inst_print())
                            offset_expr = bn_var.offset_expr
                            offset_regex = r"(-\d+)\((%\w+)(?:,(%\w+))?\)"
                            offset_search = re.search(offset_regex, str(offset_expr))
                            if offset_search and offset_search.group(3) != None:
                                logger.error("Fix offset")
                                offset = offset_search.group(1)
                                new_offset = str(offset) + "(" + offset_search.group(2) + ")"
                                offset_expr = new_offset
                            for offset in offset_targets:
                                if offset_expr == offset[0]:
                                    # Found the offset target; need to patch this instruction
                                    logger.warning("Offset found")
                                    logger.warning(bn_var)
                                    new_inst = patch_inst(dis_line, temp_inst, bn_var, bninja_info, offset[1], dwarf_var_info, offset_targets)
                                    # bninja_info.pop(idx) # problem: for all patch, i'm popping rdx
                                    if new_inst != None:
                                        # logger.debug("\n%s",new_inst)
                                        break
                                    else:
                                        # Exit out of entire script if we find a missing instruction
                                        import signal
                                        logger.error(temp_inst.inst_print())
                                        os.kill(os.getppid(),signal.SIGTERM)
                                        sys.exit(2)
                            else:
                                # No slot of its own: is it a member of a compartmentalised struct object
                                # (one slot per struct)? Then redirect to that slot plus the displacement.
                                member = struct_member_target(offset_expr, offset_targets, dwarf_var_info)
                                if member is not None:
                                    slot, disp, owner = member
                                    logger.warning("Struct member of %s at +%d", owner, disp)
                                    new_inst = patch_member_inst(dis_line, temp_inst, bn_var, slot, disp)
                                    if new_inst != None:
                                        break
                                continue
                            break
                        # print("Here")
                            # if offset_expr in 
                            # parse_ast(bn_var.asm_syntax_tree)
                    if temp_inst is not None:   # (the previous src stays on top, as before)
                        logger.info("Inserting %s", temp_inst.src)
                        arg_reg.append(temp_inst.src)
                    if new_inst != None:
                        patch_count += 1
                        logger.debug("\n%s",new_inst)
                        print(new_inst, end='')
                    else:
                        if debug != True:
                            print(line, end='')
                        None
                else:
                    if debug != True:
                        print(line, end='')
                    None
            else:
                if debug != True:
                    print(line, end='')
                None

    # Every access to a redirected slot must go through its page (see tree_uncovered)
    if kept_slots:
        out_bodies = dict()
        with open(file_path, encoding="utf-8") as f:
            body_fun = None
            for body_line in f:
                begin = re.search(r'(?<=.type\t)(.*)(?=,\s@function)', body_line)
                if begin is not None:
                    body_fun = begin.group(1)
                    out_bodies[body_fun] = list()
                elif body_fun is not None:
                    out_bodies[body_fun].append(body_line)
                    if re.search(r'(\t.cfi_endproc)', body_line):
                        body_fun = None
        for fun, (ranges, table, starts, extents) in kept_slots.items():
            found = tree_uncovered(out_bodies.get(fun, []), ranges, table, starts, extents)
            if found:
                logger.warning("consistency: %s: not every access redirected, again with %s on the stack",
                               fun, " ".join(sorted(found)))
                last_uncovered[fun] = found
    return patch_count