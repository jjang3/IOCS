import sys, getopt
import logging, os
import re
import pprint
import copy
from tkinter import FALSE
from binaryninja.types import MemberName

from elftools.dwarf.die import DIE
from elftools.elf.elffile import DWARFInfo, ELFFile
from elftools.dwarf.dwarf_expr import DWARFExprParser, DWARFExprOp
from elftools.dwarf.descriptions import (
    describe_DWARF_expr, set_global_machine_arch)
from elftools.dwarf.locationlists import (
    LocationEntry, LocationExpr, LocationParser)
from elftools.dwarf.descriptions import describe_form_class
from elftools.dwarf.callframe import (
    CallFrameInfo, CIE, FDE, instruction_name, CallFrameInstruction,
    RegisterRule, DecodedCallFrameTable, CFARule)
from elftools.dwarf.structs import DWARFStructs
from elftools.dwarf.descriptions import (describe_CFI_instructions,
    set_global_machine_arch)
from elftools.dwarf.enums import DW_EH_encoding_flags
from pathlib import Path
from typing import Optional
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

union_list = list()
@dataclass(unsafe_hash = True)
class UnionData:
    name: Optional[str] = None
    offset: str = None
    size: int = None
    line: int = None
    member_list: Optional[list] = None

typedef_struct_list = list()
struct_list = list()
@dataclass(unsafe_hash = True)
class StructData:
    name: Optional[str] = None
    offset: str = None
    size: int = None
    line: int = None
    member_list: Optional[list] = None
    fun_name: str = None
    begin: Optional[str] = None
    end: Optional[str] = None
    offset_expr: str = None
    ptr: bool = False

@dataclass(unsafe_hash = True)
class StructMember:
    name: str = None
    offset: str = None
    var_type: str = None
    base_type: Optional[str] = None
    begin: Optional[str] = None
    end: Optional[str] = None
    offset_expr: str = None
    size: Optional[int] = None
    kind: Optional[str] = None

typedef_list = list()
@dataclass(unsafe_hash = True)
class TypedefData:
    name: Optional[str] = None
    line: int = None
    base_type: str = None
    struct: Optional[StructData] = None


var_list = list()
@dataclass(unsafe_hash=True)
class VarData:
    name: Optional[str] = None
    offset: str = None
    var_type: str = None    
    base_type: Optional[str] = None
    fun_name: str = None
    offset_expr: str = None
    struct: Optional[StructData] = None
    vuln: bool = False
    tag: str = None
    ptr: bool = False
    # What the variable's type resolves to (typedefs and qualifiers stripped): base, enum, pointer,
    # array, struct or union (None: void or unknown), and its byte size (None: unknown)
    kind: Optional[str] = None
    size: Optional[int] = None

fun_list = list()
@dataclass(unsafe_hash=True)
class FunData:
    name: str = None
    var_list: list[VarData] = None
    struct_list: list[StructData] = None
    var_count: Optional[int] = None
    begin: Optional[str] = None
    end: Optional[str] = None
    # The variables declared in this function's own DIE (another object may define a static
    # function of the same name)
    own_var_list: Optional[list] = None
    # Returns a struct or union in memory (more than 16 bytes, SysV x86-64): the caller passes a
    # hidden pointer to the result in %rdi, before the parameters DWARF lists
    ret_memory: bool = False
    # Where each DW_TAG_formal_parameter (in DIE order) is passed (abi_param_locations), or None
    param_locs: Optional[list] = None

def get_base_type(dwarfinfo: DWARFInfo, dwarf_die_atts, dwarf_die_cu, dwarf_die_cu_offset):
    # print(dwarf_die_atts)
    dwarf_name = None
    if 'DW_AT_type' in dwarf_die_atts:
        refaddr = dwarf_die_atts['DW_AT_type'].value + dwarf_die_cu_offset
        type_die = dwarfinfo.get_DIE_from_refaddr(refaddr, dwarf_die_cu)
        # print(type_die)
        dwarf_name = get_base_type(dwarfinfo, type_die.attributes, dwarf_die_cu, dwarf_die_cu_offset)
        if dwarf_name != None:
            return dwarf_name
        else:
            get_base_type(dwarfinfo, type_die.attributes, dwarf_die_cu, dwarf_die_cu_offset)
    # else:
    #     # print(dwarf_die_atts)
    if 'DW_AT_name' in dwarf_die_atts:
        dwarf_name = dwarf_die_atts['DW_AT_name'].value.decode()
        # print("Returning", dwarf_name)
        return dwarf_name

def get_dwarf_type(dwarfinfo: DWARFInfo, dwarf_die_atts, dwarf_die_cu, dwarf_die_cu_offset):
    if 'DW_AT_type' in dwarf_die_atts:
        refaddr = dwarf_die_atts['DW_AT_type'].value + dwarf_die_cu_offset
        type_die = dwarfinfo.get_DIE_from_refaddr(refaddr, dwarf_die_cu)
        if (type_die.tag == "DW_TAG_typedef"):
            type_die = get_dwarf_type(dwarfinfo, type_die.attributes, dwarf_die_cu, dwarf_die_cu_offset)
            # None: the typedef chain ends at void (typedef void _IO_lock_t), like a void pointer
            if type_die == None or type_die.tag != "DW_TAG_typedef":
                return type_die
            else: 
                get_dwarf_type(dwarfinfo, type_die.attributes, dwarf_die_cu, dwarf_die_cu_offset)
        else:
            return type_die

# A variable's layout is read from its own DW_AT_type chain. It used to be matched by (byte size,
# line) against the structs seen so far, with the size and line carried over from whatever DIE set
# them last; a pointer to a declaration-only struct then took the previous struct's layout.
QUALIFIER_TAGS = ("DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type",
                  "DW_TAG_restrict_type", "DW_TAG_atomic_type")
KIND_OF_TAG = {"DW_TAG_base_type": "base", "DW_TAG_enumeration_type": "enum",
               "DW_TAG_pointer_type": "pointer", "DW_TAG_array_type": "array",
               "DW_TAG_structure_type": "struct", "DW_TAG_union_type": "union"}

def type_ref(die):
    # The DIE that die's DW_AT_type names (None: void)
    if 'DW_AT_type' not in die.attributes:
        return None
    return die.get_DIE_from_attribute('DW_AT_type')

def strip_type(die):
    # Through typedefs and qualifiers to the type that has the layout (None: void)
    while die != None and die.tag in QUALIFIER_TAGS:
        die = type_ref(die)
    return die

def type_size(die):
    die = strip_type(die)
    if die == None:
        return None
    if die.tag == "DW_TAG_array_type":
        elem_size = type_size(type_ref(die))
        if elem_size == None:
            return None
        count = 1
        for sub in die.iter_children():
            if sub.tag != "DW_TAG_subrange_type":
                continue
            bound = sub.attributes.get('DW_AT_count', sub.attributes.get('DW_AT_upper_bound'))
            # (no bound or a non-constant one: a flexible or variable-length array)
            if bound == None or describe_form_class(bound.form) != 'constant':
                return None
            count *= bound.value + (1 if bound.name == 'DW_AT_upper_bound' else 0)
        return elem_size * count
    if 'DW_AT_byte_size' in die.attributes:
        return die.attributes['DW_AT_byte_size'].value
    if die.tag == "DW_TAG_pointer_type":
        return 8
    # (a declaration-only struct or union has no size)
    return None

# SysV x86-64 argument passing (psABI 3.2.3), for matching a call's arguments to the callee's
# DWARF parameters by where they are passed: a float, a long double or a by-value struct before a
# pointer moves the pointer to another register or to the stack.
INT_ARG_REGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
DW_ATE_COMPLEX_FLOAT, DW_ATE_FLOAT = 0x3, 0x4

def type_align(die):
    die = strip_type(die)
    if die == None:
        return None
    if die.tag == "DW_TAG_array_type":
        return type_align(type_ref(die))
    if die.tag in ("DW_TAG_structure_type", "DW_TAG_union_type"):
        aligns = [type_align(type_ref(m)) for m in die.iter_children() if m.tag == "DW_TAG_member"]
        return None if None in aligns else max(aligns + [1])
    size = type_size(die)
    if die.tag == "DW_TAG_base_type" and die.attributes.get('DW_AT_encoding') != None \
            and die.attributes['DW_AT_encoding'].value == DW_ATE_COMPLEX_FLOAT and size:
        return size // 2
    return size

def scalar_classes(die):
    """Classes of a scalar type's eightbytes: ["INTEGER"], ["SSE"], ["SSE", "SSE"] (complex
    double), "MEMORY" (long double: x87), or None (unknown)."""
    size = type_size(die)
    if die.tag in ("DW_TAG_pointer_type", "DW_TAG_enumeration_type", "DW_TAG_reference_type"):
        return ["INTEGER"]
    if die.tag != "DW_TAG_base_type" or not size:
        return None
    enc = die.attributes['DW_AT_encoding'].value if 'DW_AT_encoding' in die.attributes else None
    name = die.attributes['DW_AT_name'].value.decode() if 'DW_AT_name' in die.attributes else ""
    if enc == DW_ATE_FLOAT:
        if size in (4, 8):
            return ["SSE"]
        return "MEMORY" if size == 16 and "long double" in name else None
    if enc == DW_ATE_COMPLEX_FLOAT:
        return {8: ["SSE"], 16: ["SSE", "SSE"]}.get(size, "MEMORY" if "long double" in name else None)
    return {1: ["INTEGER"], 2: ["INTEGER"], 4: ["INTEGER"], 8: ["INTEGER"], 16: ["INTEGER", "INTEGER"]}.get(size)

def abi_classes(die):
    """SysV classes of an argument of type die: one class per eightbyte ("INTEGER" or "SSE"),
    "MEMORY" (passed on the stack), or None (unknown)."""
    die = strip_type(die)
    if die == None:
        return None
    if die.tag not in ("DW_TAG_structure_type", "DW_TAG_union_type", "DW_TAG_array_type"):
        return scalar_classes(die)
    size = type_size(die)
    if size == None or size == 0:
        return None
    if size > 16:
        return "MEMORY"
    classes = [None] * ((size + 7) // 8)
    def leaf(t, off):
        t = strip_type(t)
        if t == None:
            return False
        if t.tag == "DW_TAG_array_type":
            elem = type_size(type_ref(t))
            n = (type_size(t) or 0) // elem if elem else None
            return n != None and all(leaf(type_ref(t), off + i * elem) for i in range(n))
        if t.tag in ("DW_TAG_structure_type", "DW_TAG_union_type"):
            for m in t.iter_children():
                if m.tag != "DW_TAG_member":
                    continue
                if 'DW_AT_bit_size' in m.attributes or 'DW_AT_data_bit_offset' in m.attributes:
                    return False     # (bit-fields: not classified here)
                moff = member_offset(m, m.dwarfinfo, m.cu.cu_offset)
                if moff == None or not leaf(type_ref(m), off + moff):
                    return False
            return True
        c, sz, al = scalar_classes(t), type_size(t), type_align(t)
        if c == None or c == "MEMORY" or not sz or (al and off % al):
            leaf.memory = True
            return c != None
        for i, cls in enumerate(c):
            k = off // 8 + i
            if k >= len(classes):
                return False
            classes[k] = "INTEGER" if "INTEGER" in (classes[k], cls) else cls
        return True
    leaf.memory = False
    if not leaf(die, 0):
        return None
    if leaf.memory:
        return "MEMORY"
    return None if None in classes else classes

def abi_param_locations(fun_die, ret_memory):
    """Where each formal parameter of a function definition is passed, in DIE order: ("reg", r)
    for one integer register r, ("stack", d) for the stack at d bytes above the callee's entry
    %rsp (8: the first stack argument), ("other",) for SSE registers or two registers; None from
    the first parameter whose type cannot be classified on (where the rest go is unknown)."""
    gp, sse, stack, out = (1 if ret_memory else 0), 0, 8, []
    known = True
    for die in fun_die.iter_children():
        if die.tag != "DW_TAG_formal_parameter":
            continue
        cls = abi_classes(type_ref(die)) if known else None
        if cls == None:
            known = False
            out.append(None)
            continue
        if cls != "MEMORY":
            nint, nsse = cls.count("INTEGER"), cls.count("SSE")
            if gp + nint <= len(INT_ARG_REGS) and sse + nsse <= 8:
                out.append(("reg", INT_ARG_REGS[gp]) if cls == ["INTEGER"] else ("other",))
                gp, sse = gp + nint, sse + nsse
                continue
        size, align = type_size(type_ref(die)), type_align(type_ref(die))
        if not size or not align:
            known = False
            out.append(None)
            continue
        if align > 8:
            stack = (stack + 15) // 16 * 16
        out.append(("stack", stack) if cls == ["INTEGER"] else ("other",))
        stack += (size + 7) // 8 * 8
    return out

def type_name(die):
    # The first named type under pointers, arrays and qualifiers; an anonymous struct goes by its typedef
    typedef_name = None
    while die != None:
        if die.tag == "DW_TAG_subroutine_type":
            return "subroutine"
        if die.tag in QUALIFIER_TAGS or die.tag in ("DW_TAG_pointer_type", "DW_TAG_array_type"):
            if die.tag == "DW_TAG_typedef" and typedef_name == None:
                typedef_name = die.attributes['DW_AT_name'].value.decode()
            die = type_ref(die)
            continue
        if 'DW_AT_name' in die.attributes:
            return die.attributes['DW_AT_name'].value.decode()
        break
    return typedef_name if typedef_name != None else "null"

def member_offset(member_die, dwarfinfo, cu_offset):
    attr = member_die.attributes.get('DW_AT_data_member_location')
    if attr == None:
        return 0
    if describe_form_class(attr.form) == 'constant':
        return attr.value
    off_regex = r"(?<=\(DW_OP_plus_uconst:\s)(.*)(?=\))"
    offset = re.search(off_regex, describe_DWARF_expr(attr.value, dwarfinfo.structs, cu_offset))
    return int(offset.group(1)) if offset != None else None

def struct_layout(dwarfinfo, struct_die, name):
    """StructData of a struct type DIE with its members as the DIE lists them. A member that is
    itself a struct, union or array stays one member (its inside is that type's layout), and
    bit-fields keep their storage unit's offset and size, so several can share one."""
    temp_struct = StructData(name, None, type_size(struct_die),
                             struct_die.attributes['DW_AT_decl_line'].value if 'DW_AT_decl_line' in struct_die.attributes else None,
                             list(), None, None, None, None)
    for member_die in struct_die.iter_children():
        if member_die.tag != "DW_TAG_member":
            continue
        member_type = type_ref(member_die)
        temp_member = StructMember(None, None, None, None)
        if 'DW_AT_name' in member_die.attributes:
            temp_member.name = member_die.attributes['DW_AT_name'].value.decode()
        offset = member_offset(member_die, dwarfinfo, member_die.cu.cu_offset)
        temp_member.offset = str(offset) if offset != None else None
        base_type_name = get_base_type(dwarfinfo, member_die.attributes, member_die.cu, member_die.cu.cu_offset)
        if base_type_name != None:
            temp_member.var_type = base_type_name
        temp_member.base_type = member_type.tag if member_type != None else None
        temp_member.kind = KIND_OF_TAG.get(strip_type(member_type).tag) if strip_type(member_type) != None else None
        if 'DW_AT_bit_size' in member_die.attributes and 'DW_AT_byte_size' in member_die.attributes:
            temp_member.size = member_die.attributes['DW_AT_byte_size'].value
        else:
            temp_member.size = type_size(member_type)
        temp_struct.member_list.append(temp_member)
    return temp_struct

def enclosing_subprogram(die):
    # The function a variable is declared in (None: file scope)
    parent = die.get_parent()
    while parent != None and parent.tag != "DW_TAG_subprogram":
        parent = parent.get_parent()
    return parent

def show_loclist(loclist, dwarfinfo, indent, cu_offset):
    """ Display a location list nicely, decoding the DWARF expressions
        contained within.
    """
    d = []
    for loc_entity in loclist:
        if isinstance(loc_entity, LocationEntry):
            offset = describe_DWARF_expr(loc_entity.loc_expr, dwarfinfo.structs, cu_offset)
            print(offset)
            d.append('%s <<%s>>' % (
                loc_entity,
                describe_DWARF_expr(loc_entity.loc_expr, dwarfinfo.structs, cu_offset)))
        else:
            d.append(str(loc_entity))
    return '\n'.join(indent + s for s in d)

def dwarf_analysis(input_binary):
    target_dir = Path(os.path.abspath(input_binary))
    c14n_regex = r"(fun\_c14n|var\_c14n)"
    c14n_type = re.search(c14n_regex, target_dir.__str__())
    if c14n_type != None:
        if c14n_type.group(1) == "fun_c14n":
            log.info("fun_c14n input\n")
        elif c14n_type.group(1) == "var_c14n":
            log.info("var_c14n input\n")
        else:
            log.error("c14n type unknown")
            exit()    
    log.info(target_dir.parent)
    file_name = os.path.splitext(os.path.basename(input_binary))[0]

    dwarf_outfile = target_dir.parent.joinpath("%s.dwarf" % file_name)
    fp = open(dwarf_outfile, "w") 
    
    with open(input_binary, 'rb') as f:
        elffile = ELFFile(f)
        if not elffile.has_dwarf_info():
            print('  file has no DWARF info')
            return
        
        # get_dwarf_info returns a DWARFInfo context object, which is the
        # starting point for all DWARF-based processing in pyelftools.
        dwarfinfo = elffile.get_dwarf_info()
        
        # The location lists are extracted by DWARFInfo from the .debug_loc
        # section, and returned here as a LocationLists object.
        location_lists = dwarfinfo.location_lists()

        # This is required for the descriptions module to correctly decode
        # register names contained in DWARF expressions.
        set_global_machine_arch(elffile.get_machine_arch())
        
        # Create a LocationParser object that parses the DIE attributes and
        # creates objects representing the actual location information.
        loc_parser = LocationParser(location_lists)
        gv_regex  = r"(?<=\(DW_OP_addr:\s)(.*)(?=\))"
        # reg_regex = r"(?<=\(DW_OP_fbreg:\s)(.*)(?=\))"
        reg_regex = r"DW_OP_fbreg:\s*(-?\d+)"
        rbp_regex = r"(?<=\(DW_OP_breg.\s\(rbp\):\s)(.*)(?=\))"
        rsp_regex = r"(?<=\(DW_OP_breg.\s\(rsp\):\s)(.*)(?=\))"
        off_regex = r"(?<=\(DW_OP_plus_uconst:\s)(.*)(?=\))"
        
        for CU in dwarfinfo.iter_CUs():
            # print(DIE_count)
            last_die_tag = []
            fun_name = None
            temp_fun = None
            temp_struct = None
            temp_struct_members = list()
            temp_union = None
            
            loc = None
            offset = None
            byte_size = None
            line_num = None
            type_die = None
            
            # This variable is used to catch typedef struct
            struct_typedef = False
            
            reg_to_use      = None
            fun_frame_base  = None
            # The DIE of temp_fun: a variable belongs to it only if declared inside it
            fun_die_offset  = None
            
            for DIE in CU.iter_DIEs():
                cu_ver = CU['version']
                # Only a definition (it has a frame base) starts a function: after a declaration DIE,
                # which can be nested in a function, temp_fun is still the function being read
                if (DIE.tag == "DW_TAG_subprogram" and 'DW_AT_frame_base' in DIE.attributes):
                    if temp_fun != None:
                        log.warning("Inserting %s", temp_fun.name)
                        fun_list.append(temp_fun)

                    for attr in DIE.attributes.values():
                        if loc_parser.attribute_has_location(attr, CU['version']):
                            lowpc = DIE.attributes['DW_AT_low_pc'].value
                            highpc_attr = DIE.attributes['DW_AT_high_pc']
                            highpc_attr_class = describe_form_class(highpc_attr.form)
                            
                            if highpc_attr_class == 'address':
                                highpc = highpc_attr.value
                            elif highpc_attr_class == 'constant':
                                highpc = lowpc + highpc_attr.value
                            else:
                                print('Error: invalid DW_AT_high_pc class:',
                                    highpc_attr_class)
                                continue
                            
                            fun_name = DIE.attributes["DW_AT_name"].value.decode()
                            log.info("Function name: %s", fun_name)
                            # if (fun_name == "ngx_http_add_variable"):
                            temp_fun = FunData(fun_name, None, None, None, hex(lowpc), hex(highpc))
                            temp_fun.own_var_list = list()
                            ret_die = strip_type(type_ref(DIE))
                            temp_fun.ret_memory = (ret_die != None and ret_die.tag in ("DW_TAG_structure_type", "DW_TAG_union_type")
                                                   and abi_classes(ret_die) == "MEMORY")
                            temp_fun.param_locs = abi_param_locations(DIE, temp_fun.ret_memory)
                            fun_die_offset = DIE.offset
                            # Not the previous function's frame base, if this one has none
                            fun_frame_base = None
                            reg_to_use = None
                            
                            # fp.write("Function name: %s\n" % fun_name)
                            loc = loc_parser.parse_from_attribute(attr, CU['version'])
                            if isinstance(loc, list):
                                idx = 1
                                for loc_entity in loc:
                                    # print(idx)
                                    if isinstance(loc_entity, LocationEntry):
                                        offset = describe_DWARF_expr(loc_entity.loc_expr, dwarfinfo.structs, CU.cu_offset)
                                        # print(offset)
                                        if "rbp" in offset:
                                            if rbp_offset := re.search(rbp_regex, offset):
                                                fun_frame_base = int(rbp_offset.group(1))
                                                reg_to_use = "rbp"
                                        elif idx == 2:
                                            # This is if RBP is not used and RSP is used to access variable
                                            if rsp_offset := re.search(rsp_regex, offset):
                                                fun_frame_base = int(rsp_offset.group(1))
                                                reg_to_use = "rsp"
                                    idx += 1
                
                if (DIE.tag == "DW_TAG_variable" or DIE.tag == "DW_TAG_formal_parameter"): # 
                    # This is used for variable that is declared within the function. Everything about
                    # it comes from its own attributes: nothing is carried over from earlier DIEs.
                    var_name        = None
                    # An inlined function's variable has its name and type on the abstract origin
                    name_die        = DIE
                    if 'DW_AT_abstract_origin' in DIE.attributes:
                        name_die    = DIE.get_DIE_from_attribute('DW_AT_abstract_origin')
                    reg_offset      = None
                    var_offset      = None
                    hex_var_offset  = None
                    loc             = None
                    gv_var          = False
                    in_memory       = False
                    if 'DW_AT_name' in name_die.attributes:
                        var_name = name_die.attributes["DW_AT_name"].value.decode()
                        log.debug("\tVar name: %s", var_name)
                    for var_attr in DIE.attributes.values():
                        if (loc_parser.attribute_has_location(var_attr, CU['version'])):
                            loc = loc_parser.parse_from_attribute(var_attr,
                                                                CU['version'])
                            if isinstance(loc, LocationExpr):
                                in_memory = True
                                offset = describe_DWARF_expr(loc.loc_expr, dwarfinfo.structs, CU.cu_offset)
                                if (offset_regex := re.search(reg_regex, offset)) and fun_frame_base != None:
                                    var_offset = int(offset_regex.group(1))
                                    var_offset += fun_frame_base
                                    hex_var_offset = hex(var_offset)
                                    reg_offset = str(var_offset) + "(%" + str(reg_to_use) + ")" 
                                    log.debug("\tOffset:\t%s (hex: %s)", reg_offset, hex_var_offset)
                                elif global_regex := re.search(gv_regex, offset):
                                    gv_var = True
                                    in_memory = False
                                    var_offset = global_regex.group(1)
                                else:
                                    # A register variable (DW_OP_reg*: `register` locals) has no stack slot.
                                    in_memory = False
                            elif isinstance(loc, list):
                                # If variableis directly accessed by the register itself without offset.
                                print(show_loclist(loc,
                                                dwarfinfo,
                                                '      ', CU.cu_offset))
                    # (a declaration has no location: the defining DIE is recorded)
                    if isinstance(loc, LocationExpr) and (var_name != None or not gv_var):
                        # A file-scope variable that follows a function is not that function's
                        owner = enclosing_subprogram(DIE)
                        var_fun = fun_name if temp_fun != None and owner != None and owner.offset == fun_die_offset else None
                        var_type_die = type_ref(name_die)
                        layout_die = strip_type(var_type_die)
                        temp_var = VarData(var_name, var_offset if (in_memory or gv_var) else None,
                                           type_name(var_type_die),
                                           var_type_die.tag if var_type_die != None else None,
                                           var_fun, reg_offset)
                        temp_var.kind = KIND_OF_TAG.get(layout_die.tag) if layout_die != None else None
                        temp_var.tag = str(DIE.tag)
                        temp_var.ptr = temp_var.kind == "pointer"
                        temp_var.size = type_size(var_type_die)
                        if temp_var.kind == "struct" and in_memory and temp_var.size != None:
                            # A struct object in the frame: each member at the variable's slot plus the
                            # member's offset. (A pointer to a struct is a pointer: its pointee is not
                            # in the frame.)
                            working_var = struct_layout(dwarfinfo, layout_die, temp_var.var_type)
                            working_var.fun_name = var_fun
                            working_var.offset = hex_var_offset
                            working_var.offset_expr = reg_offset
                            working_var.begin = hex(var_offset)
                            working_var.end = hex(var_offset + int(working_var.size))
                            for member in working_var.member_list:
                                if member.offset != None:
                                    begin   = var_offset + int(member.offset)
                                    # A trailing flexible array member has no size: it ends with the struct
                                    end     = begin + member.size if member.size != None else var_offset + int(working_var.size)
                                    member.begin    = hex(begin)
                                    member.end      = hex(end)
                                    member.offset_expr = str(begin) + "(%" + reg_to_use + ")" 
                            temp_var.base_type = "DW_TAG_structure_type"
                            temp_var.struct = working_var
                            log.critical("Inserting struct var %s", temp_var.name)
                        elif gv_var:
                            log.critical("Inserting global var %s", temp_var.name)
                        else:
                            log.critical("Inserting base var %s", temp_var.name)
                        var_list.append(temp_var)
                        if var_fun != None:
                            temp_fun.own_var_list.append(temp_var)
                    print()
                            
                if (DIE.tag == "DW_TAG_union_type"):
                    if 'DW_AT_byte_size' in DIE.attributes:
                        byte_size   = DIE.attributes['DW_AT_byte_size'].value
                    if 'DW_AT_decl_line' in DIE.attributes:
                        line_num    = DIE.attributes['DW_AT_decl_line'].value
                    log.warning("Creating temp_union: %s %s", byte_size, line_num)
                    temp_union = UnionData(None, None, byte_size, line_num, None)
                
                if (DIE.tag == "DW_TAG_structure_type"):
                    struct_name = None
                    if 'DW_AT_name' in DIE.attributes:
                        struct_name = DIE.attributes['DW_AT_name'].value
                        try:
                            struct_name = struct_name.decode('utf-8')
                        except:
                            None
                    if 'DW_AT_byte_size' in DIE.attributes:
                        byte_size   = DIE.attributes['DW_AT_byte_size'].value
                    else:
                        byte_size   = None
                        
                    if 'DW_AT_decl_line' in DIE.attributes:
                        line_num    = DIE.attributes['DW_AT_decl_line'].value
                    else:
                        line_num    = None
                    log.warning("Creating temp_struct: %s %s %s", struct_name, byte_size, line_num)
                    temp_struct = StructData(struct_name, None, byte_size, 
                                             line_num, None, None, None, None, None)
                    
                    if 'DW_AT_declaration' in DIE.attributes:
                        log.critical("Inserting temp_struct (decl): %s", struct_name)
                        struct_list.append(temp_struct)
                        temp_struct = None
                    
                if (DIE.tag == "DW_TAG_member"):
                    member_name = None
                    member_type = None
                    temp_member = StructMember(None, None, None, None)
                    for mem_attr in DIE.attributes.values():
                        if(mem_attr.name == "DW_AT_name"):
                            member_name = DIE.attributes["DW_AT_name"].value.decode()
                            try:
                                member_name = member_name.decode('utf-8')
                            except:
                                None
                            # log.debug("\tStruct member found: %s", attr_name)
                            temp_member.name = member_name
                        if loc_parser.attribute_has_location(mem_attr, CU['version']):
                            loc = loc_parser.parse_from_attribute(mem_attr,
                                                                CU['version'])
                            if(mem_attr.name == "DW_AT_data_member_location"):
                                if isinstance(loc, LocationExpr):
                                    offset = re.search(off_regex, 
                                                       describe_DWARF_expr(loc.loc_expr, dwarfinfo.structs, CU.cu_offset))
                                    # temp_member.offset = str(int(offset.group(1)))
                                    temp_member.offset = str(int(offset.group(1)) - int(byte_size))
                                    log.debug(offset.group(1))
                                    # exit()
                        if (mem_attr.name == "DW_AT_type"):
                            refaddr = DIE.attributes['DW_AT_type'].value + DIE.cu.cu_offset
                            type_die = dwarfinfo.get_DIE_from_refaddr(refaddr, DIE.cu)
                            # Tries to find the base type of variable recursively (e.g., long unsigned int, char)
                            base_type_name = get_base_type(dwarfinfo, DIE.attributes, DIE.cu, DIE.cu.cu_offset)
                            # print(mem_attr.name, base_type_name)
                            if base_type_name != None:
                                temp_member.var_type = ''.join(map(str, base_type_name))
                                # Base type such as whether it is an array (e.g., DW_TAG_array_type)
                                temp_member.base_type = type_die.tag
                            else:
                                print("None", type_die)
                    # pprint.pprint(temp_member,width=1)
                    temp_struct_members.append(temp_member)
                  
                if (DIE.tag == "DW_TAG_typedef"):
                    typedef_name = None
                    typedef_type = None
                    last_tag = last_die_tag.pop()
                    
                    if last_tag == None:
                        # If last tag is None, then struct_typedef is not true, now it is separate typedef
                        struct_typedef = False
                    
                    # This is for typedef struct
                    if len(typedef_struct_list) > 0:
                        last_struct = typedef_struct_list.pop()
                        if temp_struct == last_struct and temp_struct.name == None:
                            log.warning("Found typedef struct")
                            if 'DW_AT_name' in DIE.attributes:
                                typedef_name = DIE.attributes['DW_AT_name'].value
                                try:
                                    typedef_name = typedef_name.decode('utf-8')
                                except:
                                    None
                            temp_struct.name = typedef_name
                            log.critical("Inserting typedef_temp_struct %s", temp_struct.name)
                            struct_list.append(temp_struct)
                            temp_struct_members.clear()
                            temp_struct = None
                            struct_typedef = True
                    elif (last_tag == "DW_TAG_typedef" and struct_typedef or
                          last_tag == "DW_TAG_const_type" and struct_typedef) :
                        # If typedef of struct, last item of struct_list should be the struct
                        if 'DW_AT_name' in DIE.attributes:
                            typedef_name = DIE.attributes['DW_AT_name'].value
                            try:
                                typedef_name = typedef_name.decode('utf-8')
                            except:
                                None
                        copy_struct = copy.deepcopy(struct_list[len(struct_list)-1])
                        copy_struct.name = typedef_name
                        if 'DW_AT_decl_line' in DIE.attributes:
                            line_num    = DIE.attributes['DW_AT_decl_line'].value
                        if 'DW_AT_type' in DIE.attributes:
                            refaddr = DIE.attributes['DW_AT_type'].value + DIE.cu.cu_offset
                            type_die = dwarfinfo.get_DIE_from_refaddr(refaddr, DIE.cu)
                        else:
                            # typedef void (_IO_lock_t): not the type of the DIE before it
                            type_die = None
                        if type_die != None and type_die.tag == "DW_TAG_base_type":
                            typedef_type = get_base_type(dwarfinfo, DIE.attributes, DIE.cu, DIE.cu.cu_offset)
                        # log.debug("%s %s %s", typedef_name, line_num, typedef_type)
                        temp_typedef = TypedefData(typedef_name, line_num, typedef_type)
                        log.critical("Inserting temp_typedef (struct) %s", typedef_name)
                        typedef_list.append(temp_typedef)
                        temp_typedef = None
                    else:
                        if 'DW_AT_name' in DIE.attributes:
                            typedef_name = DIE.attributes['DW_AT_name'].value
                            try:
                                typedef_name = typedef_name.decode('utf-8')
                            except:
                                None
                        if 'DW_AT_decl_line' in DIE.attributes:
                            line_num    = DIE.attributes['DW_AT_decl_line'].value
                        if 'DW_AT_type' in DIE.attributes:
                            refaddr = DIE.attributes['DW_AT_type'].value + DIE.cu.cu_offset
                            type_die = dwarfinfo.get_DIE_from_refaddr(refaddr, DIE.cu)
                        else:
                            # typedef void (_IO_lock_t): not the type of the DIE before it
                            type_die = None
                        # print(type_die)
                        if type_die == None:
                            None
                        elif type_die.tag == "DW_TAG_base_type":
                            typedef_type = get_base_type(dwarfinfo, DIE.attributes, DIE.cu, DIE.cu.cu_offset)
                        elif type_die.tag == "DW_TAG_array_type":
                            arr_type_die = get_dwarf_type(dwarfinfo, DIE.attributes,
                                                            DIE.cu, DIE.cu.cu_offset)
                            
                            if arr_type_die.tag == "DW_TAG_base_type":
                                typedef_type = arr_type_die.attributes['DW_AT_name'].value.decode()
                            elif arr_type_die.tag == "DW_TAG_array_type":
                                
                                dbl_arr_type_die = get_dwarf_type(dwarfinfo, arr_type_die.attributes, arr_type_die.cu, arr_type_die.cu.cu_offset)
                                if 'DW_AT_name' in dbl_arr_type_die.attributes:
                                    typedef_type = dbl_arr_type_die.attributes['DW_AT_name'].value.decode()
                                else: 
                                    trip_arr_type_die = get_dwarf_type(dwarfinfo, dbl_arr_type_die.attributes, dbl_arr_type_die.cu, dbl_arr_type_die.cu.cu_offset)
                                    # (None: an array of void pointers)
                                    if trip_arr_type_die != None and 'DW_AT_name' in trip_arr_type_die.attributes:
                                        typedef_type = trip_arr_type_die.attributes['DW_AT_name'].value.decode()
                        elif type_die.tag == "DW_TAG_typedef":
                            # uintmax_t => __uintmax_t
                            typedef_type = get_base_type(dwarfinfo, DIE.attributes, DIE.cu, DIE.cu.cu_offset)
                        # log.debug("%s %s %s", typedef_name, line_num, typedef_type)
                        temp_typedef = TypedefData(typedef_name, line_num, typedef_type)
                        log.critical("Inserting temp_typedef (base) %s", typedef_name)
                        typedef_list.append(temp_typedef)
                        temp_typedef = None
                
                if (DIE.tag == None):
                    # This is used for single function application (disable it for larger app)
                    if temp_fun != None:
                        # if temp_fun not in fun_list:
                        log.warning("Inserting %s", temp_fun.name)
                        fun_list.append(temp_fun)
                    last_tag = last_die_tag.pop()
                    if (last_tag == "DW_TAG_member"):
                        if temp_struct != None and temp_struct.name != None:
                            temp_struct.member_list = temp_struct_members.copy()
                            log.critical("Inserting temp_struct (0) %s", temp_struct.name)
                            struct_list.append(temp_struct)
                            temp_struct_members.clear()
                            temp_struct = None
                        elif temp_union != None:
                            # Not too sure what to do with union, it is not commonly used
                            # (DW_TAG_member collects every member in temp_struct_members: they are the
                            # union's, and must not stay there for the next struct)
                            temp_union.member_list = temp_struct_members.copy()
                            log.critical("Inserting temp_union (0)")
                            union_list.append(temp_union)
                            temp_struct_members.clear()
                            temp_union = None
                        else:
                            temp_struct.member_list = temp_struct_members.copy()
                            log.warning("Inserting typedef struct (0)")
                            typedef_struct_list.append(temp_struct)
                            # An anonymous struct's members are its own (nested ones get no typedef)
                            temp_struct_members.clear()
                            continue
                    
                last_die_tag.append(DIE.tag)

                    
                
    # log.info("Struct list")
    # fp.write("Structs:\n")
    # pprint.pprint(struct_list, width=100, depth=4, compact=True)
    # for item in struct_list:
    #     print(item.name)
    # print(vars(struct_list))
    # pprint.pprint(fun_list, width=1)
    # pprint.pprint(var_list, width=1)
    # exit()

    # Iterate through function list once to populate the list
    temp_var_list = list()
    temp_count = 0
    for fun in fun_list:
        
        temp_struct_list = list()
        # for idx, struct in enumerate(struct_list):
        #     if struct.fun_name == fun.name:
        #         temp_struct_list.append(struct)
        #         temp_count += 1
        # Its own DIE's variables: matching var_list on the name also took those of a static function
        # of the same name in an earlier object
        for idx, var in enumerate(fun.own_var_list):
            if True:
                temp_var_list.append(var)
                if var.struct != None:
                    # temp_count += 1 # This is temporary
                    for member in var.struct.member_list:        
                        # if var.fun_name == "open_listenfd":
                        #     print(member)
                        temp_count += 1
                else:
                    # if var.fun_name == "open_listenfd":
                    #     print(var)
                    temp_count += 1
        fun.struct_list = temp_struct_list.copy()
        fun.var_list = temp_var_list.copy()
        fun.var_count = temp_count
        temp_var_list.clear()
        temp_count = 0
    # exit()
    # pprint.pprint(fun_list, width=1)
    unique_list = []

    for item in fun_list:
        
        if item not in unique_list:

            unique_list.append(item)
    # pprint.pprint(fun_list, width=1)
    # In second iteration, we will write it to the file pointer
    fp.write("FunCount: %s" % len(unique_list))
    for fun in unique_list:
        # print(fun)
        fp.write("\n-------------FunBegin-----------------\nfun_name: %s\nFunBegin: %s\nFunEnd: %s\nVarCount: %s\n" % (fun.name, fun.begin, fun.end, fun.var_count))
        
        for idx, var in enumerate(fun.var_list):
            fp.write("    -------------------------------\n\tVarName: %s\n" % var.name)
            fp.write("\tOffset: %s\n" % var.offset)
            fp.write("\tVarType: %s\n" % var.var_type)
            fp.write("\tBaseType: %s\n" % var.base_type)
            fp.write("\tTag: %s\n" % var.tag)
            if var.struct != None:
                fp.write("\tPointer: %s\n" % var.struct.ptr)    
                fp.write("        --------------------------\n\t\tStructName: %s" % var.struct.name)
                fp.write("                                  \n\t\tStructBegin: %s" % var.struct.begin)
                fp.write("                                  \n\t\tStructEnd: %s" % var.struct.end)
                fp.write("                                  \n\t\tMemCount: %s\n" % len(var.struct.member_list))
                for m_idx, member in enumerate(var.struct.member_list):
                    fp.write("            _____________________\n\t\t\tMemberName: %s\n" % member.name)
                    fp.write("\t\t\tMemVarType: %s\n" % member.var_type)
                    fp.write("\t\t\tMemBaseType: %s\n" % member.base_type)
                    fp.write("\t\t\tMemBegin: %s\n" % member.begin)
                    fp.write("\t\t\tMemEnd: %s\n" % member.end)
                    fp.write("            -------MemberEnd-------\n")
            else:
                fp.write("\tPointer: %s\n" % var.ptr)    
            
            fp.write("    -------------VarEnd------------\n")
        # for idx, struct in enumerate(struct_list):
        #     # print(getattr(struct, "offset"))
        #     fp.write("\n    ------------------------------\n\tName: %s\n" % struct.name)
        #     fp.write("\tOffset: %s\n" % struct.offset)
        #     fp.write("\tMembers:\n")
        #     for m_idx, member in enumerate(struct.member_list):
        #         fp.write("        __________________________\n\t\tName: %s\n" % member.name)
        #         fp.write("\t\tVarType: %s\n" % member.var_type)
        #         fp.write("\t\tBaseType: %s\n" % member.base_type)
        #         fp.write("\t\tBegin: %s\n" % member.begin)
        #         fp.write("\t\tEnd: %s\n" % member.end)
        #     for idx, var in enumerate(var_list):
        #         fp.write("\n    ------------------------------\n\tName: %s\n" % var.name)
        #         fp.write("\tOffset: %s\n" % var.offset)
        #         fp.write("\tVarType: %s\n" % var.var_type)
        #         fp.write("\tBaseType: %s\n" % var.base_type)
        
        fp.write("\n--------------FunEnd------------------\n")
    # test = None
    fp.write("\n")
    # exit()
    fp.close()
    for item in unique_list:
        log.debug(item.name)
    return unique_list

def process_argument(argv):
    inputfile = ''
    try:
        opts, args = getopt.getopt(argv,"hfic:",["binary="])
    except getopt.GetoptError:
        print ('dwarf_analysis.py --binary <binary>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('dwarf_analysis.py --binary <binary>')
            sys.exit()
        elif opt in ("-b", "--binary"):
            inputfile = arg
    dwarf_analysis(inputfile)
    
if __name__ == '__main__':
    process_argument(sys.argv[1:])