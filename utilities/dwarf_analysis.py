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

@dataclass(unsafe_hash = True)
class StructMember:
    name: str = None
    offset: str = None
    var_type: str = None
    base_type: Optional[str] = None
    begin: Optional[str] = None
    end: Optional[str] = None
    offset_expr: str = None

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

fun_list = list()
@dataclass(unsafe_hash=True)
class FunData:
    name: str = None
    var_list: list[VarData] = None
    struct_list: list[StructData] = None
    var_count: Optional[int] = None
    begin: Optional[str] = None
    end: Optional[str] = None

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
            if type_die.tag != "DW_TAG_typedef":
                return type_die
            else: 
                get_dwarf_type(dwarfinfo, type_die.attributes, dwarf_die_cu, dwarf_die_cu_offset)
        else:
            return type_die

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
            last_var = []
            last_die_tag = []
            fun_name = None
            temp_fun = None
            temp_struct = None
            temp_struct_members = list()
            temp_union = None
            temp_union_members = list()
            
            loc = None
            offset = None
            byte_size = None
            line_num = None
            type_die = None
            
            # This variable is used to catch typedef struct
            struct_typedef = False
            
            struct_var      = False
            base_var        = True
            gv_var          = False
            
            reg_to_use      = None
            
            for DIE in CU.iter_DIEs():
                cu_ver = CU['version']
                if (DIE.tag == "DW_TAG_subprogram"):
                    if temp_fun != None:
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
                
                if (DIE.tag == "DW_TAG_variable"):
                    # This is used for variable that is declared within the function
                    var_name        = None
                    reg_offset      = None
                    type_name       = None
                    typedef_tag     = None
                    for var_attr in DIE.attributes.values():
                        # offset = None
                        if (var_attr.name == "DW_AT_name"):
                            var_name = DIE.attributes["DW_AT_name"].value.decode()
                            log.debug("\tVar name: %s", var_name)
                            # Debugging var name
                            # if var_name == "version_etc_copyright":
                            #     None
                        if (loc_parser.attribute_has_location(var_attr, CU['version'])):
                            loc = loc_parser.parse_from_attribute(var_attr,
                                                                CU['version'])
                            if isinstance(loc, LocationExpr):
                                # If offset exists
                                # print('      %s' % (
                                # describe_DWARF_expr(loc.loc_expr,
                                #                     dwarfinfo.structs, CU.cu_offset)))
                                gv_var = False
                                offset = describe_DWARF_expr(loc.loc_expr, dwarfinfo.structs, CU.cu_offset)
                                if offset_regex := re.search(reg_regex, offset):
                                    var_offset = int(offset_regex.group(1))
                                    var_offset += fun_frame_base
                                    # print(offset_regex.group(1))
                                    hex_var_offset = hex(var_offset)
                                    # reg_offset = str(var_offset) + "(%rbp)" 
                                    reg_offset = str(var_offset) + "(%" + str(reg_to_use) + ")" 
                                    log.debug("\tOffset:\t%s (hex: %s)", reg_offset, hex_var_offset)
                                elif global_regex := re.search(gv_regex, offset):
                                    gv_var = True
                                    var_offset = global_regex.group(1)
                                    # log.debug("\tAddr:\t%s", var_offset)
                            
                                if struct_var == True and gv_var == False:
                                    working_var = last_var.pop()
                                    working_var.fun_name = fun_name
                                    working_var.offset = hex_var_offset
                                    working_var.offset_expr = reg_offset
                                    working_var.begin = hex(int(var_offset))
                                    working_var.end = hex(int(var_offset) + int(working_var.size))
                                    for i, member in enumerate(working_var.member_list):
                                        if member.offset != None:
                                            if i+1 < len(working_var.member_list):
                                                # print(working_var.offset, member.offset)    
                                                begin   = hex(int(var_offset) + int(member.offset))
                                                end     = hex(int(var_offset) + int(working_var.member_list[i+1].offset))
                                                # member_var_offset = str(int(begin, base=16)) + "(%rbp)" 
                                                member_var_offset = str(int(begin, base=16)) + "(%" + reg_to_use + ")" 
                                                member.begin    = begin
                                                member.end      = end
                                                member.offset_expr = member_var_offset
                                                # pprint.pprint(var_list, width=1)
                                            else:
                                                begin   = hex(int(var_offset) + int(member.offset))
                                                end     = hex(int(var_offset) + int(working_var.size))
                                                # member_var_offset = str(int(begin, base=16)) + "(%rbp)" 
                                                member_var_offset = str(int(begin, base=16)) + "(%" + reg_to_use + ")" 
                                                member.begin    = begin
                                                member.end      = end
                                                member.offset_expr = member_var_offset
                                    temp_var = VarData(var_name, var_offset, working_var.name, 
                                                       "DW_TAG_structure_type", fun_name, reg_offset, working_var)
                                    log.critical("Inserting struct var %s", temp_var.name)
                                    struct_var = False
                                    base_var = True
                                    var_list.append(temp_var)
                                    # pprint.pprint(working_var)
                                elif base_var == True and gv_var == True:
                                    if var_name != None:
                                        working_var = last_var.pop()
                                        working_var.offset = var_offset
                                        log.critical("Inserting global var %s", working_var.name)
                                        var_list.append(working_var)
                                elif base_var == True:
                                    working_var = last_var.pop()
                                    working_var.offset = var_offset #(var_offset)
                                    working_var.offset_expr = reg_offset
                                    log.critical("Inserting base var %s", working_var.name)
                                    var_list.append(working_var)
                            elif isinstance(loc, list):
                                # If variableis directly accessed by the register itself without offset.
                                print(show_loclist(loc,
                                                dwarfinfo,
                                                '      ', CU.cu_offset))
                        if (var_attr.name == "DW_AT_type"):
                            refaddr = DIE.attributes['DW_AT_type'].value + DIE.cu.cu_offset
                            type_die = dwarfinfo.get_DIE_from_refaddr(refaddr, DIE.cu)
                            # print(type_die.tag)
                            if type_die.tag == "DW_TAG_base_type":
                                type_name = type_die.attributes['DW_AT_name'].value.decode()
                                log.error("base_type: %s ",type_name)
                                struct_var  = False
                                base_var    = True
                                temp_var = VarData(var_name, None, type_name, type_die.tag, fun_name)
                                last_var.append(temp_var)
                            elif (type_die.tag == "DW_TAG_pointer_type" or
                                  type_die.tag == "DW_TAG_array_type"):
                                # This will return dereferenced DIE of a pointer type
                                ptr_type_die = get_dwarf_type(dwarfinfo, type_die.attributes, 
                                                           type_die.cu, type_die.cu.cu_offset)
                                
                                if ptr_type_die != None:
                                    # There are cases where DW_TAG_pointer_type doesn't have type
                                    if 'DW_AT_name' in ptr_type_die.attributes:
                                        # If first deref is success, we can get the type name
                                        type_name = ptr_type_die.attributes['DW_AT_name'].value.decode()
                                    elif ptr_type_die.tag == "DW_TAG_structure_type":
                                        if 'DW_AT_byte_size' in ptr_type_die.attributes:
                                            byte_size   = ptr_type_die.attributes['DW_AT_byte_size'].value
                                        if 'DW_AT_decl_line' in ptr_type_die.attributes:
                                            line_num    = ptr_type_die.attributes['DW_AT_decl_line'].value
                                        for struct_item in struct_list:
                                            # print(struct_item.size, struct_item.line)
                                            if (byte_size == struct_item.size and
                                                line_num == struct_item.line):
                                                type_name = struct_item.name
                                                type_name = struct_item.name
                                                temp_var = copy.deepcopy(struct_item)
                                                struct_var  = True
                                                base_var    = False
                                                last_var.append(temp_var)
                                    elif 'DW_AT_type' in ptr_type_die.attributes:
                                        # If we need to deref again because it is either struct or const
                                        dbl_ptr_type_die = get_dwarf_type(dwarfinfo, ptr_type_die.attributes,
                                                                        ptr_type_die.cu, ptr_type_die.cu.cu_offset)
                                        if 'DW_AT_name' in dbl_ptr_type_die.attributes:
                                            type_name = dbl_ptr_type_die.attributes['DW_AT_name'].value.decode()
                                        elif dbl_ptr_type_die.tag == "DW_TAG_subroutine_type":
                                            type_name = "subroutine"
                                        elif dbl_ptr_type_die.tag == "DW_TAG_structure_type":
                                            if 'DW_AT_byte_size' in dbl_ptr_type_die.attributes:
                                                byte_size   = dbl_ptr_type_die.attributes['DW_AT_byte_size'].value
                                            if 'DW_AT_decl_line' in dbl_ptr_type_die.attributes:
                                                line_num    = dbl_ptr_type_die.attributes['DW_AT_decl_line'].value
                                            # print(byte_size, line_num)
                                            for struct_item in struct_list:
                                                # print(struct_item.size, struct_item.line)
                                                if (byte_size == struct_item.size and
                                                    line_num == struct_item.line):
                                                    type_name = struct_item.name
                                                    temp_var = copy.deepcopy(struct_item)
                                                    struct_var  = True
                                                    base_var    = False
                                                    last_var.append(temp_var)
                                        else:
                                            trip_ptr_type_die = get_dwarf_type(dwarfinfo, dbl_ptr_type_die.attributes, dbl_ptr_type_die.cu, dbl_ptr_type_die.cu.cu_offset)
                                            if trip_ptr_type_die != None:
                                                if 'DW_AT_name' in trip_ptr_type_die.attributes:
                                                    type_name = trip_ptr_type_die.attributes['DW_AT_name'].value.decode()
                                else:
                                    type_name = "null"
                                log.error("ptr_type: %s", type_name)
                            
                                if struct_var == True:
                                    continue
                                struct_var  = False
                                base_var    = True
                                temp_var = VarData(var_name, None, type_name, type_die.tag, fun_name)
                                last_var.append(temp_var)
                            elif type_die.tag == "DW_TAG_typedef":
                                typedef_name = type_die.attributes['DW_AT_name'].value.decode()
                                try:
                                    typedef_name = typedef_name.decode('utf-8')
                                except:
                                    None
                                for typedef_item in typedef_list:
                                    if typedef_name == typedef_item.name:
                                        type_name = typedef_item.base_type
                                # After searching through typedef list, if type_name is None, rec find
                                if type_name == None:
                                    typedef_die = get_dwarf_type(dwarfinfo, type_die.attributes, 
                                                           type_die.cu, type_die.cu.cu_offset)
                                    if (typedef_die.tag == "DW_TAG_array_type" or 
                                        typedef_die.tag == "DW_TAG_pointer_type"):
                                        struct_var  = False
                                        base_var    = True
                                        arr_type_die = get_dwarf_type(dwarfinfo, typedef_die.attributes,
                                                                        typedef_die.cu, typedef_die.cu.cu_offset)
                                        if arr_type_die != None:
                                            if arr_type_die.tag == "DW_TAG_base_type":
                                                type_name = arr_type_die.attributes['DW_AT_name'].value.decode()
                                            elif arr_type_die.tag == "DW_TAG_subroutine_type":
                                                type_name = "subroutine"
                                        temp_var = VarData(var_name, None, type_name, 
                                                           type_die.tag, fun_name)
                                        last_var.append(temp_var)
                                    elif (typedef_die.tag == "DW_TAG_structure_type"):
                                        # If typedef is a struct, then enable struct_var and disable base_var
                                        struct_var  = True
                                        base_var    = False
                                        # print(typedef_die)
                                        if 'DW_AT_name' in typedef_die.attributes:
                                            type_name = typedef_die.attributes['DW_AT_name'].value.decode()
                                        if 'DW_AT_byte_size' in typedef_die.attributes:
                                            byte_size   = typedef_die.attributes['DW_AT_byte_size'].value
                                        if 'DW_AT_decl_line' in typedef_die.attributes:
                                            line_num    = typedef_die.attributes['DW_AT_decl_line'].value
                                        # print(byte_size, line_num)
                                        for struct_item in struct_list:
                                            # print(struct_item.size, struct_item.line)
                                            if (byte_size == struct_item.size and
                                                line_num == struct_item.line):
                                                type_name = struct_item.name
                                                temp_var = copy.deepcopy(struct_item)
                                                last_var.append(temp_var)
                                else:
                                    struct_var  = False
                                    base_var    = True
                                    
                                if struct_var == False:
                                    base_var    = True
                                    temp_var = VarData(var_name, None, type_name, type_die.tag, fun_name)
                                    last_var.append(temp_var)
                                                # print(struct_item.line, struct_item.size)
                                # Debug purpose
                                # if type_name == None:
                                #     print(type_die.tag, type_name, typedef_die.tag)
                                #     exit()
                                log.error("typedef_type: %s", type_name)
                            elif type_die.tag == "DW_TAG_const_type":
                                const_type_die = get_dwarf_type(dwarfinfo, type_die.attributes, 
                                                           type_die.cu, type_die.cu.cu_offset)
                                if const_type_die.tag == "DW_TAG_base_type":
                                    if 'DW_AT_name' in const_type_die.attributes:
                                        type_name = const_type_die.attributes['DW_AT_name'].value.decode()
                                elif const_type_die.tag == "DW_TAG_structure_type":
                                    if 'DW_AT_name' in const_type_die.attributes:
                                        type_name = const_type_die.attributes['DW_AT_name'].value.decode()
                                elif const_type_die.tag == "DW_TAG_array_type":
                                    nested_tag = None
                                    nested_die = None
                                    arr_type_die = get_dwarf_type(dwarfinfo, const_type_die.attributes,
                                                                    const_type_die.cu, const_type_die.cu.cu_offset)
                                    nested_tag = arr_type_die.tag
                                    nested_die = arr_type_die
                                    if arr_type_die.tag == "DW_TAG_base_type":
                                        type_name = arr_type_die.attributes['DW_AT_name'].value.decode()
                                    elif 'DW_AT_type' in arr_type_die.attributes:
                                        # If we need to deref again because it is either struct or const
                                        dbl_const_type_die = get_dwarf_type(dwarfinfo, arr_type_die.attributes,
                                                                        arr_type_die.cu, arr_type_die.cu.cu_offset)
                                        nested_tag = dbl_const_type_die.tag
                                        nested_die = dbl_const_type_die
                                        if 'DW_AT_name' in dbl_const_type_die.attributes:
                                            type_name = dbl_const_type_die.attributes['DW_AT_name'].value.decode()
                                        else:
                                            trip_const_type_die = get_dwarf_type(dwarfinfo, dbl_const_type_die.attributes, dbl_const_type_die.cu, dbl_const_type_die.cu.cu_offset)
                                            nested_tag = trip_const_type_die.tag
                                            nested_die = trip_const_type_die
                                            if 'DW_AT_name' in trip_const_type_die.attributes:
                                                type_name = trip_const_type_die.attributes['DW_AT_name'].value.decode()
                                            else:
                                                quad_const_type_die = get_dwarf_type(dwarfinfo, trip_const_type_die.attributes, trip_const_type_die.cu, trip_const_type_die.cu.cu_offset)
                                                nested_tag = quad_const_type_die.tag
                                                nested_die = quad_const_type_die
                                                if 'DW_AT_name' in quad_const_type_die.attributes:
                                                    type_name = quad_const_type_die.attributes['DW_AT_name'].value.decode()
                                
                                log.error("const_type: %s %s", type_name, nested_tag)
                                if nested_tag == "DW_TAG_structure_type":
                                    struct_var  = True
                                    base_var    = False
                                    if 'DW_AT_byte_size' in nested_die.attributes:
                                        byte_size   = nested_die.attributes['DW_AT_byte_size'].value
                                    if 'DW_AT_decl_line' in nested_die.attributes:
                                        line_num    = nested_die.attributes['DW_AT_decl_line'].value
                                    for struct_item in struct_list:
                                        if (byte_size == struct_item.size and
                                            line_num == struct_item.line):
                                            type_name = struct_item.name
                                            temp_var = copy.deepcopy(struct_item)
                                            last_var.append(temp_var)
                                    # temp_var = VarData(var_name, None, type_name, nested_tag, fun_name)
                                    # last_var.append(temp_var)
                                else:
                                    struct_var  = False
                                    base_var    = True
                                    temp_var = VarData(var_name, None, type_name, nested_tag, fun_name)
                                    last_var.append(temp_var)
                                # Debug purpose
                                # if type_name == None:
                                #     print(type_die.tag, type_name, const_type_die.tag)
                                #     exit()
                            elif type_die.tag == "DW_TAG_structure_type":
                                struct_var  = True
                                base_var    = False
                                # print(type_die)
                                if 'DW_AT_byte_size' in type_die.attributes:
                                    byte_size   = type_die.attributes['DW_AT_byte_size'].value
                                if 'DW_AT_decl_line' in type_die.attributes:
                                    line_num    = type_die.attributes['DW_AT_decl_line'].value

                                for struct_item in struct_list:
                                    if (byte_size == struct_item.size and
                                        line_num == struct_item.line):
                                        type_name = struct_item.name
                                        temp_var = copy.deepcopy(struct_item)
                                        last_var.append(temp_var)
                       
                    # log.warning("DW_TAG_Variable finished\n\t%s", temp_var)
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
                                    temp_member.offset = offset.group(1)
                                    # log.debug(offset.group(1))
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
                        if type_die.tag == "DW_TAG_base_type":
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
                        # print(type_die)
                        if type_die.tag == "DW_TAG_base_type":
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
                                    if 'DW_AT_name' in trip_arr_type_die.attributes:
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
                    # if temp_fun != None:
                    #     if temp_fun not in fun_list:
                    #         fun_list.append(temp_fun)
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
                            temp_union.member_list = temp_union_members.copy()
                            log.critical("Inserting temp_union (0)")
                            union_list.append(temp_union)
                            temp_union_members.clear()
                            temp_union = None
                        else:
                            temp_struct.member_list = temp_struct_members.copy()
                            log.warning("Inserting typedef struct (0)")
                            typedef_struct_list.append(temp_struct)
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
        # print(fun.name)
        temp_struct_list = list()
        # for idx, struct in enumerate(struct_list):
        #     if struct.fun_name == fun.name:
        #         temp_struct_list.append(struct)
        #         temp_count += 1
        for idx, var in enumerate(var_list):
            if var.fun_name == fun.name:
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

    # pprint.pprint(fun_list, width=1)

    # pprint.pprint(fun_list, width=1)
    # In second iteration, we will write it to the file pointer
    fp.write("FunCount: %s" % len(fun_list))
    for fun in fun_list:
        # print(fun)
        fp.write("\n-------------FunBegin-----------------\nfun_name: %s\nFunBegin: %s\nFunEnd: %s\nVarCount: %s\n" % (fun.name, fun.begin, fun.end, fun.var_count))
        
        for idx, var in enumerate(fun.var_list):
            fp.write("    -------------------------------\n\tVarName: %s\n" % var.name)
            fp.write("\tOffset: %s\n" % var.offset)
            fp.write("\tVarType: %s\n" % var.var_type)
            fp.write("\tBaseType: %s\n" % var.base_type)
            if var.base_type == "DW_TAG_structure_type":
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
    return fun_list

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