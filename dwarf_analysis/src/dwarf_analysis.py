import sys, getopt
import logging, os
import re
import pprint
import copy

from tkinter import FALSE
# from binaryninja.types import MemberName

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

# print("sys.path:", sys.path)  # Print sys.path to check the directories

global fun_list
global typedef_list
global type_dict

from dwarf_atts import *
class DwarfAnalyzer:
    def __init__(self, base_name, dwarf_info, loc_parser, fp):
        self.base_name = base_name
        self.dwarf_info = dwarf_info
        self.loc_parser = loc_parser
        self.fp = fp
        self.curr_fun = None  # Initialize as None

    def analyze_subprog(self, CU, DIE, attributes):
        self.curr_fun = analyze_subprog(CU, self.dwarf_info, DIE, attributes, self.loc_parser, self.base_name)

    def analyze_var(self, CU, DIE, attributes):
        return analyze_var(CU, self.dwarf_info, DIE, attributes, self.loc_parser, self.curr_fun)

    def analyze_typedef(self, CU, DIE, attributes):
        return analyze_typedef(CU, self.dwarf_info, DIE, attributes)

    def analyze_base(self, CU, DIE, attributes):
        return analyze_base(CU, self.dwarf_info, DIE, attributes)

    def finalize_subprog(self):
        """Finalize the processing of the current function."""
        if self.curr_fun:
            logger.info(f"Finalizing function: {self.curr_fun.name}")
            fun_list.append(self.curr_fun)
            self.curr_fun = None  # Reset the current function after finalizing

    def run(self):
        for CU in self.dwarf_info.iter_CUs():
            for DIE in CU.iter_DIEs():
                # Finalize the previous function if a new subprogram is encountered
                if DIE.tag == "DW_TAG_subprogram" and self.curr_fun is not None:
                    self.finalize_subprog()

                self.process_die(CU, DIE)

            # Finalize the last subprogram after processing all DIEs
            if self.curr_fun is not None:
                self.finalize_subprog()

        # After processing all DIEs, write the function data to the file
        self.write_function_data_to_file(fun_list)

        logger.critical("Finished DWARF analysis")
        return fun_list

    def write_function_data_to_file(self, fun_list):
        """Writes the processed function data to the specified file."""
        fp = self.fp
        fp.write(f"FunCount: {len(fun_list)}\n")
        
        for fun in fun_list:
            fp.write(f"\n-------------FunBegin-----------------\n")
            fp.write(f"fun_name: {fun.name}\n")
            fp.write(f"FunBegin: {fun.begin}\n")
            fp.write(f"FunEnd: {fun.end}\n")
            
            for idx, var in enumerate(fun.var_list):
                fp.write(f"    -------------------------------\n")
                fp.write(f"\tVarName: {var.name}\n")
                fp.write(f"\tOffset: {var.offset}\n")
                fp.write(f"\tVarType: {var.var_type}\n")
                fp.write(f"\tBaseType: {var.type_name}\n")
                fp.write(f"    -------------VarEnd------------\n")
            
            fp.write(f"\n--------------FunEnd------------------\n")
        
        fp.write("\n")
        fp.close()

        

    def process_die(self, CU, DIE):
        """Helper method to process a DIE and its children recursively."""
        # Handle the DIE's tag
        if DIE.tag == "DW_TAG_subprogram":
            self.analyze_subprog(CU, DIE, DIE.attributes.values())
            # None
        elif DIE.tag == "DW_TAG_variable":
            self.analyze_var(CU, DIE, DIE.attributes.values())
        elif DIE.tag == "DW_TAG_typedef":
            self.analyze_typedef(CU, DIE, DIE.attributes.values())
        elif DIE.tag == "DW_TAG_base_type":
            self.analyze_base(CU, DIE, DIE.attributes.values())
        elif DIE.tag == None:
            None
        else:
            logger.info(f"Not yet handling the tag {DIE.tag}.")
            # None
            
def dwarf_analysis(input_binary):
    logger.info("DWARF analysis")
    target_dir = Path(os.path.abspath(input_binary))
    base_name = Path(input_binary).stem
    # logger.debug(base_name)
    dwarf_outfile   = target_dir.parent.joinpath("%s.dwarf" % base_name)
    logger.debug(dwarf_outfile)
    fp = open(dwarf_outfile, "w") 
    # exit()
    # logger.debug("%s\n%s\n%s\n%s", target_dir, base_name, input_binary, dwarf_outfile)
    with open(input_binary, 'rb') as f:
        elffile = ELFFile(f)
        if not elffile.has_dwarf_info():
            print('  file has no DWARF info')
            return

        # get_dwarf_info returns a DWARFInfo context object, which is the
        # starting point for all DWARF-based processing in pyelftools.
        dwarf_info = elffile.get_dwarf_info()
        
        # The location lists are extracted by DWARFInfo from the .debug_loc
        # section, and returned here as a LocationLists object.
        location_lists = dwarf_info.location_lists()

        # This is required for the descriptions module to correctly decode
        # register names contained in DWARF expressions.
        set_global_machine_arch(elffile.get_machine_arch())
        
        # Create a LocationParser object that parses the DIE attributes and
        # creates objects representing the actual location information.
        loc_parser = LocationParser(location_lists)

        analyzer = DwarfAnalyzer(base_name, dwarf_info, loc_parser, fp)
        
        return analyzer.run()