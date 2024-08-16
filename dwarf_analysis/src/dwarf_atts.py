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

def analyze_subprog(attribute_values):
    logger.info("Analyze subprogram TAG")
    for attr in attribute_values:
        logger.debug(attr)   

def analyze_base(attribute_values):
    logger.info("Analyze subprogram BASE")
    for attr in attribute_values:
        logger.debug(attr)

def analyze_var(attribute_values):
    logger.info("Analyze subprogram VAR")
    for attr in attribute_values:
        logger.debug(attr) 

def analyze_typedef(attribute_values):
    logger.info("Analyze subprogram TYPEDEF")
    for attr in attribute_values:
        logger.debug(attr)

def analyze_attributes(attribute_values):
    for attr in attribute_values:
        logger.debug(attr)