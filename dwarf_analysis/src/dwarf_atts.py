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
from typing import Optional, List
from dataclasses import dataclass, field

# Get the same logger instance. Use __name__ to get a logger with a hierarchical name or a specific string to get the exact same logger.
logger = logging.getLogger('custom_logger')

@dataclass(unsafe_hash=True)
class VarData:
    name: Optional[str] = None
    offset: str = None
    var_type: str = None

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
                logger.debug(f"  - {var.name}: Offset {var.offset}, Type {var.var_type}")

    def __repr__(self):
        """Returns a string representation of the object."""
        return f"FunData(name={self.name}, begin={self.begin}, end={self.end})"


def analyze_subprog(CU, dwarf_info, DIE, attribute_values, loc_parser):
    frame_base_pattern = r"\(DW_OP_breg\d+\s\((\w+)\):\s(-?\d+)\)"
    for attr in attribute_values:
        if loc_parser.attribute_has_location(attr, CU['version']): 
            logger.warning("Analyze DW_TAG_subprogram (non-internal function)")
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
            curr_fun.print_data()
            return curr_fun

def analyze_var(CU, dwarf_info, DIE, attribute_values, loc_parser, curr_fun: FunData):
    offset_pattern = r"\(DW_OP_fbreg:\s*(-?\d+)\)"
    global_pattern  = r"(?<=\(DW_OP_addr:\s)(.*)(?=\))"
    global_var = False
    if curr_fun != None:
        logger.warning(f"Analyze DW_TAG_variable for the Fun: {curr_fun.name}")
    else:
        global_var = True
        logger.warning(f"Global variable")
        # Currently global variable is not supported

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


def analyze_base(attribute_values, location_lists):
    logger.info("Analyze subprogram BASE")
    for attr in attribute_values:
        logger.debug(attr)

def analyze_typedef(attribute_values, location_lists):
    logger.info("Analyze subprogram TYPEDEF")
    for attr in attribute_values:
        logger.debug(attr)

def analyze_attributes(attribute_values, location_lists):
    for attr in attribute_values:
        logger.debug(attr)