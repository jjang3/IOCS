import sys, getopt
import logging, os
import re
import pprint
import copy
from tkinter import FALSE
from binaryninja.types import MemberName

from elftools.dwarf.compileunit import CompileUnit
from elftools.dwarf.die import DIE
from elftools.elf.elffile import DWARFInfo, ELFFile
from elftools.dwarf.dwarf_expr import DWARFExprParser, DWARFExprOp
from elftools.dwarf.descriptions import (
    describe_DWARF_expr, set_global_machine_arch)
from elftools.dwarf.locationlists import (
    LocationEntry, LocationExpr, LocationParser, LocationLists)
from elftools.dwarf.descriptions import describe_form_class
from elftools.dwarf.callframe import (
    CallFrameInfo, CIE, FDE, instruction_name, CallFrameInstruction,
    RegisterRule, DecodedCallFrameTable, CFARule)
from elftools.dwarf.structs import DWARFStructs
from elftools.dwarf.descriptions import (describe_CFI_instructions,
    set_global_machine_arch)
from elftools.dwarf.enums import DW_EH_encoding_flags
from pathlib import Path
from typing import Optional, List
from dataclasses import dataclass, field

# Get the same logger instance. Use __name__ to get a logger with a hierarchical name or a specific string to get the exact same logger.
logger = logging.getLogger('custom_logger')

# This list will contain the typedef variable information of this program
typedef_list = list()
@dataclass(unsafe_hash=True)
class TypeDefData:
    typedef_name: Optional[str] = None
    var_type: str = None
    type_name: str = None
    type_size: Optional[int] = None

type_dict = dict()

@dataclass(unsafe_hash=True)
class VarData:
    name: Optional[str] = None
    offset: str = None
    var_type: str = None
    ptr_type: Optional[str] = None # Currently not used, if type_name is not found in the type_dict, then we can safely assume that pointer is to an object we cannot handle (e.g., struct)
    type_name: str = None

fun_list = list()
class FunData:
    def __init__(self, name: str = None, begin: Optional[int] = None, end: Optional[int] = None):
        self.name = name
        self.begin = begin
        self.end = end
        self.reg_to_use = None
        self.fun_frame_base = None
        self.var_list: List[VarData] = []  # List to store VarData instances
    
    def add_var(self, var_data: VarData):
        """Adds a VarData instance to the var_list."""
        self.var_list.append(var_data)
    
    def find_var(self, var_data: VarData):
        """Finds a VarData by the name in the var_list."""
        for var in self.var_list:
            var: VarData
            if var_data.name == var.name:
                return True
        return False

    def print_data(self):
        """Prints the function's data in a readable format."""
        logger.info(f"Function Name: {self.name}")
        logger.debug(f"Begin Address: {hex(self.begin)}")
        logger.debug(f"End Address: {hex(self.end)}")
        if self.fun_frame_base != None:
            logger.debug(f"Frame base: {self.reg_to_use}-{self.fun_frame_base}")
        if self.var_list:
            logger.debug("Variables:")
            for var in self.var_list:
                output = f"  - {var.name}: Offset {var.offset}, Var Type {var.var_type}"
                if hasattr(var, 'pointer_type') and var.ptr_type is not None:
                    output += f", Pointer Type: {var.ptr_type}"
                output += f", Type Name: {var.type_name}"
                logger.debug(output)

    def __repr__(self):
        """Returns a string representation of the object."""
        return f"FunData(name={self.name}, begin={self.begin}, end={self.end})"

def analyze_subprog(CU: CompileUnit, dwarf_info, DIE, attribute_values, loc_parser
                    , base_name):
    frame_base_pattern = r"\(DW_OP_breg\d+\s\((\w+)\):\s(-?\d+)\)"
    for attr in attribute_values:
        if loc_parser.attribute_has_location(attr, CU['version']): 
            print()
            logger.warning("Analyze DW_TAG_subprogram")
            low_pc = DIE.attributes['DW_AT_low_pc'].value
            high_pc_attr = DIE.attributes['DW_AT_high_pc']
            high_pc_form_class = describe_form_class(high_pc_attr.form)
            if high_pc_form_class == 'address':
                high_pc = high_pc_attr.value
            elif high_pc_form_class == 'constant':
                high_pc = low_pc + high_pc_attr.value
            else:
                logger.error("Error: Invalid DW_AT_high_pc form class: %s", high_pc_form_class)
                continue
            
            # Check the source file to see if it belongs to a known library
            parsed_base_name = None
            decl_file_attr = DIE.attributes.get('DW_AT_decl_file')
            if decl_file_attr:
                file_index = decl_file_attr.value

                # Get the line program associated with this compilation unit
                line_prog = dwarf_info.line_program_for_CU(CU)

                # Find the file name using the index
                if file_index > 0 and file_index <= len(line_prog['file_entry']):
                    file_name = line_prog['file_entry'][file_index - 1].name.decode('utf-8')
                    logger.debug(f"Function {DIE.attributes['DW_AT_name'].value.decode('utf-8')} is declared in file: {file_name}")
                    parsed_base_name = os.path.splitext(file_name)[0]
                else:
                    logger.error("File index out of range")
            if parsed_base_name != None and base_name != parsed_base_name:
                logger.error(f"This function is from {parsed_base_name}, not {base_name}")
                # print(len(parsed_base_name), len(base_name))
                return None

            # If there is no location, it means it is an internal functions (e.g., printf)           
            fun_name = DIE.attributes["DW_AT_name"].value.decode()
            # logger.info("Function name: %s", fun_name)
            curr_fun = FunData(name=fun_name, begin=low_pc, end=high_pc)
            loc = loc_parser.parse_from_attribute(attr, CU['version'])
            if isinstance(loc, list):
                for loc_entity in loc:
                    if isinstance(loc_entity, LocationEntry):
                        offset = describe_DWARF_expr(loc_entity.loc_expr, dwarf_info.structs, CU.cu_offset)
                        frame_match = re.search(frame_base_pattern, offset)
                        if "rbp" in offset and frame_match:
                            reg = frame_match.group(1)
                            offset_value = int(frame_match.group(2))
                            curr_fun.reg_to_use = reg
                            curr_fun.fun_frame_base = offset_value
            return curr_fun

def get_type_name(dwarf_info: DWARFInfo, type_die: DIE):
    if type_die.tag == "DW_TAG_typedef":
        # In the case of typedef type, we need to not get the name of it, but the type that the typedef refers to first.
        if 'DW_AT_type' in type_die.attributes:
            ref_addr = type_die.attributes['DW_AT_type'].value + type_die.cu.cu_offset
            type_die = dwarf_info.get_DIE_from_refaddr(ref_addr, type_die.cu)
            return get_type_name(dwarf_info, type_die)
    elif 'DW_AT_name' in type_die.attributes:
        type_name = type_die.attributes['DW_AT_name'].value.decode()
        logger.debug(f"Got the type name: {type_name}")
        return type_name
    else:
        logger.error(f"No name for the type: {type_die.tag} (Recursive analysis needed)")
        if 'DW_AT_type' in type_die.attributes:
            ref_addr = type_die.attributes['DW_AT_type'].value + type_die.cu.cu_offset
            type_die = dwarf_info.get_DIE_from_refaddr(ref_addr, type_die.cu)
            return get_type_name(dwarf_info, type_die)
    return None
        
def parse_dwarf_type(dwarf_info, DIE, curr_var: VarData):
    if 'DW_AT_type' in DIE.attributes:
        ref_addr = DIE.attributes['DW_AT_type'].value + DIE.cu.cu_offset
        type_die = dwarf_info.get_DIE_from_refaddr(ref_addr, DIE.cu)
        logger.debug(type_die.tag)
        if type_die.tag == "DW_TAG_base_type":
            curr_var.var_type = type_die.tag
            type_name = get_type_name(dwarf_info, type_die)
            if type_name != None:
                curr_var.type_name = type_name
            logger.error("base_type: %s ",type_name)
        elif type_die.tag == "DW_TAG_pointer_type" or type_die.tag == "DW_TAG_array_type":
            curr_var.var_type = type_die.tag
            type_name = get_type_name(dwarf_info, type_die)
            if type_name != None:
                curr_var.type_name = type_name
        elif type_die.tag == "DW_TAG_typedef":
            # For the typedef, need to first get the name of the typedef
            # Next, need to check what is the underlying type of the typedef
            type_name = get_type_name(dwarf_info, type_die)
            typedef_ref_addr = type_die.attributes['DW_AT_type'].value + type_die.cu.cu_offset
            typedef_type_die = dwarf_info.get_DIE_from_refaddr(typedef_ref_addr, type_die.cu)
            parse_dwarf_type(dwarf_info, typedef_type_die, curr_var)
            if type_name != None:
                curr_var.type_name = type_name
        else:
            curr_var.var_type = type_die.tag
            logger.error("Not supported yet: %s ",type_die.tag)
    else:
        curr_var.var_type = DIE.tag
    
        

def analyze_var(CU, dwarf_info, DIE, attribute_values, loc_parser, curr_fun: FunData):
    offset_pattern = r"\(DW_OP_fbreg:\s*(-?\d+)\)"
    global_pattern  = r"(?<=\(DW_OP_addr:\s)(.*)(?=\))"
    global_var = False
    if curr_fun != None:
        logger.warning(f"Analyze DW_TAG_variable for the Fun: {curr_fun.name}")
    else:
        global_var = True
        logger.warning(f"Global variable or function to be ignored")
        # Currently global variable is not supported
        return None
    curr_var = None
    for attr in attribute_values:
        if attr.name == "DW_AT_name":
            var_name = DIE.attributes["DW_AT_name"].value.decode()
            if var_name != None:
                curr_var = VarData(name=var_name)
                if curr_fun != None: # Global variable will have this None
                    if curr_fun.find_var(curr_var):
                        return
                    else:
                        logger.debug(f"Adding variable: {curr_var.name}")
                        curr_fun.add_var(curr_var)

        if curr_var != None:
            if (loc_parser.attribute_has_location(attr, CU['version'])):
                loc = loc_parser.parse_from_attribute(attr,
                                                    CU['version'])
                if isinstance(loc, LocationExpr):
                    offset = describe_DWARF_expr(loc.loc_expr, dwarf_info.structs, CU.cu_offset)
                    offset_match = re.search(offset_pattern, offset)
                    if offset_match:
                        offset_value = int(offset_match.group(1))
                        logger.debug(f"Register Offset: {curr_fun.reg_to_use}{curr_fun.fun_frame_base + offset_value}")
                        curr_var.offset = offset_value
                    global_match = re.search(global_pattern, offset)
                    if global_match:
                        addr_value = global_match.group(1)
                        logger.debug(f"Address: {addr_value}")
            elif (attr.name == "DW_AT_type"):
                parse_dwarf_type(dwarf_info, DIE, curr_var)

def analyze_typedef(CU, dwarf_info, DIE, attribute_values):
    print()
    logger.info(f"Analyze DW_TAG_typedef")
    curr_typedef = None
    for attr in attribute_values:
        if attr.name == "DW_AT_name":
            typedef_name = DIE.attributes["DW_AT_name"].value.decode()
            if typedef_name != None:
                curr_typedef = TypeDefData(typedef_name=typedef_name)
        if curr_typedef != None:
            if attr.name == "DW_AT_type":
                parse_dwarf_type(dwarf_info, DIE, curr_typedef)
            if curr_typedef.type_name in type_dict:
                curr_typedef.type_size = type_dict[curr_typedef.type_name]
    typedef_list.append(curr_typedef)
            
def analyze_base(CU, dwarf_info, DIE, attribute_values):
    print()
    logger.info("Analyze DW_TAG_base_type")
    for attr in attribute_values:
        if (attr.name == "DW_AT_name"):
            base_name = DIE.attributes["DW_AT_name"].value.decode()
        if (attr.name == "DW_AT_byte_size"):
            base_size = DIE.attributes["DW_AT_byte_size"].value
    type_dict[base_name] =  base_size
    

def analyze_attributes(attribute_values, location_lists):
    for attr in attribute_values:
        logger.debug(attr)