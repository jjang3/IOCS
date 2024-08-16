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

# Get the directory of the current Python file (asm_rewriter/main.py)
current_dir = os.path.dirname(os.path.abspath(__file__))

# Add the 'src' directory relative to the current directory (asm_rewriter/src)
sys.path.append(os.path.join(current_dir))

print("sys.path:", sys.path)  # Print sys.path to check the directories

from dwarf_atts import *

def dwarf_analysis(input_binary):
    logger.info("DWARF analysis")
    target_dir = Path(os.path.abspath(input_binary))
    base_name = Path(input_binary).stem
    # logger.debug(base_name)
    dwarf_outfile   = target_dir.parent.joinpath("%s.dwarf" % base_name)
    analysis_file   = target_dir.parent.joinpath("%s.analysis" % base_name)
    with open(analysis_file) as ff:
        for line in ff:
            analysis_list = line.split(',')
    fp = open(dwarf_outfile, "w") 
    
    logger.debug("%s\n%s\n%s\n%s", target_dir, base_name, input_binary, dwarf_outfile)
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
        
        for CU in dwarfinfo.iter_CUs():
            for DIE in CU.iter_DIEs():
                cu_ver = CU['version']
                if (DIE.tag == "DW_TAG_subprogram"):
                    analyze_subprog(DIE.attributes.values())
                if (DIE.tag == "DW_TAG_base_type"):
                    analyze_base(DIE.attributes.values())
                if (DIE.tag == "DW_TAG_variable"):
                    analyze_var(DIE.attributes.values())
                if (DIE.tag == "DW_TAG_typedef"):
                    analyze_typedef(DIE.attributes.values())