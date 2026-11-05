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

from main import *

from asm_analysis import *

asm_macros = """# var_c14n macros
# Load effective address macro
.macro lea_gs dest, offset
\trdgsbase %r11
\tmov   \offset(%r11), %r11
\tlea   (%r11), \dest
.endm

.macro lea_store_gs src, offset
\tleaq  \src, %r11
\tmovq  (%r11), %r10
\trdgsbase %r11
\tmovq  \offset(%r11), %r11
\tmovq  %r10, (%r11)
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
.endm

.macro mov_arr_load_gs src, offset, disp, value
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
.endm

.macro movss_store_gs src, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t\tmovss \src, (%r11)  # 64-bit
.endm

.macro movss_load_gs dest, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\tmovss (%r11), \dest  # 64-bit
.endm

.macro movzx_load_gs dest, offset, value
\trdgsbase %r11
\tmov \offset(%r11), %r11
\t.if \\value == 8
\t\tmovzbl (%r11), \dest  # 8-bit 
\t.elseif \\value == 16
\t\tmovzw (%r11), \dest  # 16-bit (a bare movzx is assembled as movzbl: one byte)
\t.endif
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

def patch_inst(dis_inst, temp_inst: PatchingInst, bn_var, bn_var_info: list, tgt_offset, dwarf_var_info, offset_targets: set):
    logger.critical("Patch the instruction %s | Offset: %d", dis_inst, tgt_offset)
    # parse_ast(bn_var.asm_syntax_tree)
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
        
    # An access wider than the slot (a struct copy's movq at a 1-byte member) also covers other
    # slots, which the page does not hold: it stays on the stack, and a store is then copied to
    # the page of every slot it covers (SlotSync)
    if bn_var.patch_inst.inst_type != "lea":
        width = {"b": 1, "w": 2, "l": 4, "q": 8}.get(bn_var.patch_inst.suffix)
        if bn_var.patch_inst.inst_type == "movss":
            width = 4
        size = current_slot_bytes.get(tgt_offset)
        if width != None and size != None and width > size:
            logger.warning("consistency: %d-byte access to a %d-byte slot (%d) left on the stack: %s",
                           width, size, tgt_offset, dis_inst.strip())
            return dis_inst

    tgt_ast = bn_var.asm_syntax_tree
    # print(bn_var, store_or_load)
    line = None
    patch_inst_line = None
    # print(bn_var.patch_inst.inst_print())
    
    ssa_var = traverse_ast(tgt_ast, bn_var_info, 0)
    if ssa_var != None:
        # Found SSA register    
        if ssa_var.patch_inst.inst_type == "lea":
            new_inst_type = "lea_gs"
            logger.info("Patching with lea_gs w/ base obj")
            line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d" % 
                        (dis_inst, new_inst_type, temp_inst.dest, tgt_offset), dis_inst)
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
                            line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d" % 
                            (dis_inst, new_inst_type, temp_inst.dest, tgt_offset), dis_inst)
                            patch_inst_line = "\t%s\t%s, %d" % (new_inst_type, temp_inst.dest, tgt_offset)
                else:
                    # Else, we need to use the original stack offset.
                    line = re.sub(r"(\b[a-z]+\b).*", "%s\t#%s\t%s, %d" % 
                            (dis_inst, new_inst_type, temp_inst.dest, tgt_offset), dis_inst)
                    patch_inst_line = "\t%s\t%s, %d" % (new_inst_type, temp_inst.dest, tgt_offset)
                    
            # line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d" % 
            #             (dis_inst, new_inst_type, temp_inst.dest, tgt_offset), dis_inst)
    # logger.debug(bn_var)
    if bn_var.arg == True and bn_var.patch_inst.inst_type != "lea":
        return dis_inst
    elif bn_var.arg == True and bn_var.patch_inst.inst_type == "lea":
        logger.debug("Here")
        new_inst_type = "lea_store_gs" 
        line = ""
        for var in dwarf_var_info:
            if var.offset_expr == bn_var.offset_expr:
                # Found that base struct object is being passed as an argument, need to lea_store_gs all the members as well
                logger.error("Found struct object")
                if var.struct != None:
                    for member in var.struct.member_list:
                        # logger.debug(offset_targets)
                        offset_value = None   # a member without a compartment has nothing to sync (0 is a real slot)
                        for offset in offset_targets:
                            if offset[0] == member.offset_expr:
                                offset_value = offset[1]
                        if offset_value != None and member.offset_expr != None:
                            line = "\t%s\t%s, %d\n" % (new_inst_type, member.offset_expr, offset_value)
                            patch_inst_line = "\t%s\t%s, %d" % (new_inst_type, member.offset_expr, offset_value)
                        
                        if line != "" and line not in lea_list:
                            lea_list.append(line)
                            patch_inst_list.append(patch_inst_line)
        if line == "" and bn_var.offset_expr != None:
            line = "\t%s\t%s, %d\n" % (new_inst_type, bn_var.offset_expr, tgt_offset)
            patch_inst_line = "\t%s\t%s, %d" % (new_inst_type, bn_var.offset_expr, tgt_offset)
            if line != "" and line not in lea_list:
                lea_list.append(line)
                patch_inst_list.append(patch_inst_line)
        logger.debug(bn_var)
        logger.debug(lea_list)
        return dis_inst

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
                    line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %s, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, arr_regex.group(3), value), dis_inst)
                    patch_inst_line = "\t%s\t%s, %d, %s, %d" % (new_inst_type, temp_inst.src, tgt_offset, arr_regex.group(3), value)
                elif store_or_load == "load":
                    new_inst_type = "mov_arr_load_gs"
                    line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %s, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, arr_regex.group(3), value), dis_inst)
                    patch_inst_line = "\t%s\t%s, %d, %s, %d" % (new_inst_type, temp_inst.dest, tgt_offset, arr_regex.group(3), value)
            else:
                if store_or_load == "store":
                    new_inst_type = "mov_store_gs"
                    line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                    patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
                elif store_or_load == "load":
                    new_inst_type = "mov_load_gs"
                    logger.debug(bn_var)
                    for var in dwarf_var_info:
                        if var.offset_expr == bn_var.offset_expr:
                            # Found that base struct object is being copied into a value, then, just load stack offset
                            if var.struct != None:
                                logger.error("Found struct object")
                                line = re.sub(r"(\b[a-z]+\b).*", "%s\t#%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
                            else:
                                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
                    if line == None:
                        line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                        patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "movss":
            if store_or_load == "store":
                new_inst_type = "movss_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "movss_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "movzx":
            logger.info("Patching with movzx_gs")
            if store_or_load == "store":
                new_inst_type = "movzx_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "movzx_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "add":
            logger.info("Patching with add_gs")
            if store_or_load == "store":
                new_inst_type = "add_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "add_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "sub":
            logger.info("Patching with sub_gs")
            if store_or_load == "store":
                new_inst_type = "sub_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "sub_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "imul": # Signed multiply (two's comp arith)
            logger.info("Patching with imul_gs")
            if store_or_load == "store":
                new_inst_type = "imul_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "imul_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "shl": # shift left
            logger.info("Patching with shl_gs")
            if store_or_load == "store":
                new_inst_type = "shl_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "shl_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "cmp":
            logger.info("Patching with cmp_gs")
            if store_or_load == "store":
                new_inst_type = "cmp_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "cmp_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t#%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
        elif bn_var.patch_inst.inst_type == "and":
            logger.info("Patching with and_gs")
            if store_or_load == "store":
                new_inst_type = "and_store_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.src, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
            elif store_or_load == "load":
                new_inst_type = "and_load_gs"
                line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d, %d" % (dis_inst, new_inst_type, temp_inst.dest, tgt_offset, value), dis_inst)
                patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.dest, tgt_offset, value)
            
    if line != None:
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
  
# ---- Keeping every page equal to its stack copy ----
# Every store keeps its stack write and also writes the page, and loads read the page, so the
# stack copy is the one that every write reaches. A page goes stale wherever the stack is written
# by an instruction that does not name the slot, and the next redirected load then reads an old
# value (often 0). Such writes are:
#   - a write through a pointer to a local whose address was taken (lea of the local; pointers
#     always point at the stack copy), by a callee or by this function itself (od: u.b[j] = ...);
#   - an indexed element write, -144(%rbp,%rax,8) (b2sum: v[i] = S->h[i]);
#   - a store that covers more than one slot (sort: a struct copy's movq over 8 packed bools);
#   - a recursive activation of the same function: the pages are per variable, not per
#     activation, so the inner call leaves its own values there (sort: sequential_sort).
# After each such instruction lea_store_gs copies the slots it may have written from the stack
# to their pages, the way the rewriter already did after a call that is passed a slot's address.
# Security: those copies trust the stack copy at that point, so a stack overwrite that happens
# during such a call (or through such a pointer) reaches the page. Slots outside these rules keep
# their protection, and the copies are emitted only for slots that the function reads from a page.

# Instructions whose memory operand is only read (or that access no memory)
read_only_regex = re.compile(r'(cmp(?!xchg)\w*|test\w*|bt[wlq]?|push\w*|call\w*|j\w+|lea[wlq]?|nop\w*|'
                             r'prefetch\w*|i?mul[bwlq]?|i?div[bwlq]?|v?u?comis[sd]|v?ptest|fi?ld\w*|'
                             r'fi?(add|sub|subr|mul|div|divr|com|comp|ucom|ucomp)[slt]?l?)$')
# Instructions that write each of their memory operands, not only the last one
write_all_regex = re.compile(r'(xchg|xadd|cmpxchg)[bwlq]?$')
inst_prefixes = {"lock", "notrack", "rep", "repe", "repz", "repne", "repnz", "data16"}
mem_operand_regex = re.compile(r'^\*?(?:%[a-z]s:)?([-\w.+$]*)\((%\w+)?(?:,(%\w+))?(?:,(\d+))?\)$')
# Fixed widths of SSE moves (the register is wider than the memory they write)
sse_store_bytes = {"movss": 4, "movd": 4, "movsd": 8, "movlps": 8, "movhps": 8, "movlpd": 8, "movhpd": 8,
                   "vmovss": 4, "vmovd": 4, "vmovsd": 8}

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

def reg_bytes(reg):
    r = reg.lstrip('%')
    for prefix, size in (("zmm", 64), ("ymm", 32), ("xmm", 16), ("st", 10), ("mm", 8)):
        if r.startswith(prefix):
            return size
    m = re.match(r'r\d+([dwb]?)$', r)
    if m:
        return {"": 8, "d": 4, "w": 2, "b": 1}[m.group(1)]
    if len(r) == 3 and r[0] == 'r':
        return 8
    if len(r) == 3 and r[0] == 'e':
        return 4
    if r in ("al", "bl", "cl", "dl", "ah", "bh", "ch", "dh", "sil", "dil", "bpl", "spl"):
        return 1
    return 2

def store_bytes(mnem, ops):
    """Bytes a store writes (an over-estimate is safe: it only adds copies)."""
    if mnem.startswith("set"):
        return 1
    if mnem in sse_store_bytes:
        return sse_store_bytes[mnem]
    if mnem.startswith('f'):   # x87
        if mnem in ("fnstcw", "fstcw", "fnstsw", "fstsw"):
            return 2
        if mnem.endswith('t'):
            return 10
        if mnem.startswith("fi"):
            return 8 if mnem.endswith(("ll", "q")) else 4 if mnem.endswith('l') else 2
        return 8 if mnem.endswith('l') else 4
    width = {"b": 1, "w": 2, "l": 4, "q": 8}.get(mnem[-1], 0)
    for op in ops:
        if op.startswith('%') and ':' not in op:
            width = max(width, reg_bytes(op))
    return width if width else 8

def mem_writes(mnem, ops):
    """[(kind, disp, bytes)] of the memory an instruction writes (kind as mem_operand)."""
    if mnem.startswith("rep_"):
        return [("pointer", None, 0)] if mnem[4:8] in ("stos", "movs") else []
    if re.match(r'(stos|movs)[bwlq]?$', mnem) and not ops:
        return [("pointer", None, 0)]
    if read_only_regex.match(mnem) or not ops:
        return []
    targets = ops if write_all_regex.match(mnem) else ops[-1:]
    writes = []
    for op in targets:
        kind, disp = mem_operand(op)
        if kind is not None:
            writes.append((kind, disp, store_bytes(mnem, ops)))
    return writes

def frame_disp(offset_expr):
    m = re.match(r'(-?\d+)\(%rbp\)$', str(offset_expr))
    return int(m.group(1)) if m else None

# Macros that read their slot's page (all others only write it)
page_write_only = {"mov_store_gs", "movss_store_gs", "movzx_store_gs", "mov_arr_store_gs", "lea_store_gs"}
# Macros that write their own slot's page from the instruction's operand
page_store_regex = re.compile(r'^\s*(mov|movss|movzx|mov_arr|add|sub|imul|shl|and)_store_gs\s+(.*)$')
macro_regex = re.compile(r'^\s*([a-z_]+_gs)\s+([^#\n]*)$')

def macro_slot(operands):
    """The table offset a macro uses (its second operand)."""
    ops = split_operands(operands)
    try:
        return int(ops[1])
    except (IndexError, ValueError):
        return None

def page_reads(texts):
    """Table offsets that some emitted macro reads from its page."""
    read = set()
    for text in texts:
        for out_line in text.split('\n'):
            m = macro_regex.match(out_line)
            if m and m.group(1) not in page_write_only:
                read.add(macro_slot(m.group(2)))
    return read

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

class SlotSync:
    """The slots of one function, and which of them an instruction may write without naming them
    (see above)."""
    def __init__(self, fun, dwarf_var_info, offset_targets, body, reentry):
        self.fun = fun
        self.reentry = reentry
        self.table = {expr: t for expr, t in offset_targets}
        self.span = dict()       # slot expr -> (start, end): the bytes its page mirrors (<= 8)
        self.bytes = dict()      # table offset -> the slot's size (an access wider than that is not its own)
        self.vars = list()       # (start, end, slot exprs, aggregate) of each frame variable
        for var in dwarf_var_info or []:
            start = frame_disp(var.offset_expr)
            if start is None:
                continue
            size = int(var.size) if var.size else 8
            exprs = set()
            if var.struct is not None:
                for member in var.struct.member_list:
                    m_start = frame_disp(member.offset_expr)
                    if m_start is None or member.offset_expr not in self.table:
                        continue
                    m_size = int(member.size) if member.size else 8
                    self.add_slot(member.offset_expr, m_start, m_size)
                    exprs.add(member.offset_expr)
            elif var.offset_expr in self.table:
                self.add_slot(var.offset_expr, start, size)
                exprs.add(var.offset_expr)
            self.vars.append((start, start + size, exprs, var.kind in ("array", "struct", "union")))
        # Escaped: the function computes the address of (a part of) the variable
        self.escaped = set()
        for line in body:
            inst = parse_inst(line)
            if inst is None:
                continue
            mnem, ops = inst
            if re.match(r'lea[wlq]?$', mnem) and ops:
                kind, disp = mem_operand(ops[0])
                if kind in ("frame", "indexed"):
                    self.escaped |= self.var_slots_at(disp, one_past=True) or set()
            elif "%rbp" in ops and not re.match(r'(push|pop)', mnem) and sorted(ops) != ["%rbp", "%rsp"]:
                # The frame address itself is copied: any local can be reached from it
                self.escaped |= set(self.span)
        if self.escaped:
            logger.warning("consistency: %s: address taken, synced after calls and stores through pointers: %s",
                           fun, " ".join(sorted(self.escaped)))
        if reentry is not None and fun in reentry.recursive:
            logger.warning("consistency: %s: recursive, all slots synced after a call that can re-enter it", fun)

    def add_slot(self, expr, start, size):
        old = self.span.get(expr)
        end = start + min(size, 8)
        self.span[expr] = (start, max(end, old[1]) if old else end)
        t = self.table[expr]
        self.bytes[t] = max(size, self.bytes.get(t, 0))

    def var_slots_at(self, disp, one_past=False):
        """Slot exprs of the variables at frame displacement disp (or, for one_past, an aggregate
        that ends there: buf + sizeof buf); None if it lies in none."""
        found = None
        for start, end, exprs, aggregate in self.vars:
            if start <= disp < end or (one_past and aggregate and disp == end):
                found = (found or set()) | exprs
        return found

    def stale_after(self, line):
        """Slot exprs whose page the instruction in line may leave stale."""
        inst = parse_inst(line)
        if inst is None:
            return set()
        mnem, ops = inst
        if mnem.startswith("call"):
            if self.reentry is not None and ops and self.reentry.reenters(self.fun, ops[0]):
                return set(self.span)
            return set(self.escaped)
        stale = set()
        for kind, disp, size in mem_writes(mnem, ops):
            if kind == "frame":
                stale |= {e for e, (s, t) in self.span.items() if s < disp + size and disp < t}
            elif kind == "indexed":
                # An element of the array the displacement lies in (any slot if it lies in none)
                in_var = self.var_slots_at(disp)
                stale |= in_var if in_var is not None else set(self.span)
            elif kind == "pointer":
                stale |= self.escaped
        return stale

    def written_by(self, text):
        """Slot exprs whose page a store macro in the emitted text already wrote."""
        done = set()
        for out_line in text.split('\n'):
            m = page_store_regex.match(out_line)
            if m:
                t = macro_slot(m.group(2))
                done |= {e for e, off in self.table.items() if off == t}
        return done

# Per function: table offset -> the slot's size in bytes (patch_inst leaves a wider access alone)
current_slot_bytes = dict()

def rewriter(funlist, target_dir, target_file, dwarf_fun_var_info, bn_fun_var_info, fun_table_offsets, reentry=None):
    patch_count = 0
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
        
    
    # Each function's own lines, read before rewriting: SlotSync needs every lea of a slot,
    # including one that follows the instruction being rewritten
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
        dis_line_regex = r'(mov|movz|lea|sub|add|cmp|sal|and|imul|call|movss)([l|b|w|q|bl|xw|wl]*)\s+' + OPERAND + r'(?:,\s*' + OPERAND + r')?(?:,\s*' + OPERAND + r')?\n'
        # sing_line_regex = r'\t(div)([a-z]*)\t(.*)'
        check = False
        currFun = str()
        patch_targets = list()
        offset_targets = list()
        struct_targets = set()
        # A rewritten function is written out at its end, so that its stack-to-page copies can be
        # dropped for the slots it never reads from a page: (text, table offset of a copy or None)
        fun_out = list()
        sync = None
        in_app = False
        app_syncs = list()

        def flush_fun():
            read = page_reads(text for text, t in fun_out)
            kept = 0
            for text, t in fun_out:
                if t is not None and t not in read:
                    continue
                kept += 1 if t is not None else 0
                print(text, end='')
            fun_out.clear()
            return kept

        def emit(text):
            """Write the (rewritten) instruction, then copy each slot it may have written without
            naming it from the stack to its page."""
            nonlocal in_app
            fun_out.append((text, None))
            if line.strip() == "#APP":
                in_app = True
            if sync is not None:
                stale = sync.stale_after(line) - sync.written_by(text)
                for expr in sorted(stale, key=lambda e: sync.table[e]):
                    copy = "\tlea_store_gs\t%s, %d\n" % (expr, sync.table[expr])
                    if copy in text:
                        continue
                    # (not between the instructions of an asm statement, whose operands may be in %r10/%r11)
                    (app_syncs if in_app else fun_out).append((copy, sync.table[expr]))
            if line.strip() == "#NO_APP":
                in_app = False
                fun_out.extend(app_syncs)
                app_syncs.clear()

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
                        sync = SlotSync(currFun, dwarf_var_info, offset_targets, fun_bodies.get(currFun, []), reentry)
                        current_slot_bytes.clear()
                        current_slot_bytes.update(sync.bytes)
                        check = True
                    except Exception as err:
                        logger.error("Skipping", type(err))
                        check = False
                        
                    if debug:
                        # if currFun != "sort": # Debug
                        #     check = False
                        # else:
                        #     check = True
                        None
                        custom_pprint(dwarf_var_info)
                        custom_pprint(bninja_info)
                        custom_pprint(offset_targets)
                    else:
                        if offset_targets != None:
                            for tgt in offset_targets:
                                logger.warning(tgt)
            fun_end = re.search(fun_end_regex, line)
            if fun_end is not None:
                lea_list.clear() # Clear the lea_list per function and also after rewriting the call instruction
                fun_out.extend(app_syncs)
                app_syncs.clear()
                in_app = False
                patch_count += flush_fun()
                sync = None
                current_slot_bytes.clear()
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
                            emit(new_inst)
                        else:
                            emit(line)
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
                    if mem_operand(str(src))[0] == "indexed" or mem_operand(str(dest))[0] == "indexed":
                        # An indexed access is to some element, not to the slot at its displacement
                        temp_inst = None
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
                                continue
                            break
                        # print("Here")
                            # if offset_expr in 
                            # parse_ast(bn_var.asm_syntax_tree)
                    if new_inst != None:
                        patch_count += 1
                        logger.debug("\n%s",new_inst)
                        emit(new_inst)
                    else:
                        if debug != True:
                            emit(line)
                        None
                else:
                    if debug != True:
                        emit(line)
                    None
            else:
                if debug != True:
                    print(line, end='')
                None
        patch_count += flush_fun()
    
    return patch_count