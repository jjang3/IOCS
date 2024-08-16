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

# Get the same logger instance. Use __name__ to get a logger with a hierarchical name or a specific string to get the exact same logger.
logger = logging.getLogger('custom_logger')

var_list = list()
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

    def print_data(self):
        """Prints the function's data in a readable format."""
        logger.debug(f"Function Name: {self.name}")
        logger.debug(f"Begin Address: {hex(self.begin)}")
        logger.debug(f"End Address: {hex(self.end)}")
        if self.fun_frame_base != None:
            logger.debug(f"Frame base: {self.reg_to_use}-{self.fun_frame_base}")

    def __repr__(self):
        """Returns a string representation of the object."""
        return f"FunData(name={self.name}, begin={self.begin}, end={self.end})"


def analyze_subprog(CU, dwarf_info, DIE, attribute_values, loc_parser):
    frame_base_pattern = r"\(DW_OP_breg\d+\s\((\w+)\):\s(-?\d+)\)"
    logger.warning("Analyze DW_TAG_subprogram")
    for attr in attribute_values:
        if loc_parser.attribute_has_location(attr, CU['version']): 
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
            logger.info("Function name: %s", fun_name)
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
                            # logger.debug("%s\t%d", reg, offset_value)
            curr_fun.print_data()


def analyze_base(attribute_values, location_lists):
    logger.info("Analyze subprogram BASE")
    for attr in attribute_values:
        logger.debug(attr)

def analyze_var(attribute_values, location_lists):
    logger.info("Analyze subprogram VAR")
    for attr in attribute_values:
        logger.debug(attr) 

def analyze_typedef(attribute_values, location_lists):
    logger.info("Analyze subprogram TYPEDEF")
    for attr in attribute_values:
        logger.debug(attr)

def analyze_attributes(attribute_values, location_lists):
    for attr in attribute_values:
        logger.debug(attr)