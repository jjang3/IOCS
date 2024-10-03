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
from elftools.dwarf.descriptions import describe_reg_name, describe_CFI_register_rule, describe_CFI_CFA_rule
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

global struct_list
global fun_list
global typedef_list
global type_dict

from dwarf_atts import *

 # ANSI escape codes for colors
LIGHT_BLUE = "\033[96m"
RESET = "\033[0m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[36m"
MAGENTA = "\033[95m"
ORANGE = "\033[38;5;214m" 
BRIGHT_RED = "\033[91m"

class DwarfAnalyzer:
    def __init__(self, base_name, dwarf_info, loc_parser, fp, elffile):
        self.base_name = base_name
        self.dwarf_info = dwarf_info
        self.loc_parser = loc_parser
        self.fp = fp
        self.elffile = elffile
        self.curr_fun = None  # Initialize as None
        self.curr_struct = None # Current structure (if any)
        self.curr_members = None # Current member (if any)
        self.curr_typedef = None # Current typedef (if any)
        self.stored_typedef = None  # Store typedef for later use
        self.cfa_dict = {}
        self.processed_params = set()  # Track already processed parameters by abstract origin

    def analyze_subprog(self, CU, DIE):
        self.curr_fun = analyze_subprog(CU, self.dwarf_info, DIE, self.loc_parser, self.cfa_dict)
        if self.curr_fun != None:
            self.curr_fun.print_data()

    def analyze_var(self, CU, DIE, attributes):
        return analyze_var(CU, self.dwarf_info, DIE, attributes, self.loc_parser, self.curr_fun, self.cfa_dict)

    def analyze_typedef(self, CU, DIE, attributes):
        return analyze_typedef(CU, self.dwarf_info, DIE, attributes)

    def analyze_base(self, CU, DIE, attributes):
        return analyze_base(CU, self.dwarf_info, DIE, attributes)

    def analyze_struct(self, CU, DIE, attributes):
        return analyze_struct(CU, self.dwarf_info, DIE, attributes)
    
    def analyze_member(self, CU, DIE, attributes):
        return analyze_member(CU, self.dwarf_info, DIE, attributes, self.loc_parser)
    
    def analyze_inlined_fun(self, CU, DIE):
        analyze_inlined(CU, self.dwarf_info, DIE, self.loc_parser, self.cfa_dict)

    def finalize_subprog(self):
        """Finalize the processing of the current function."""
        if self.curr_fun:
            logger.critical(f"Finalizing function: {self.curr_fun.name}")
            # if self.curr_fun.name == "open_listenfd": # Function Debugging
            #     exit()
            fun_list.append(self.curr_fun)
            self.curr_fun = None  # Reset the current function after finalizing
            print()
            # Debugging all the typedef information stored
            # for typedef in typedef_list:
            #     print_typedef_data(typedef)
    
    def get_architecture(self):
        """ Get the architecture from the ELF file """
        return self.elffile.get_machine_arch()

    def describe_CFI_CFA_rule(self, cfa):
        """ Describe the CFA rule for debugging purposes """
        if isinstance(cfa, tuple) and len(cfa) == 2:
            reg_num, offset = cfa
            reg_name = describe_reg_name(reg_num, self.get_architecture())
            return f"{reg_name} + {offset}"
        return str(cfa)

    def analyze_eh_frame(self):
        """ Analyze the .eh_frame and .debug_frame sections and extract CFA and frame-related information """
        dwarf_info = self.elffile.get_dwarf_info()
        cfi_entries = self.get_cfi_entries(dwarf_info)

        if not cfi_entries:
            logger.error("No CFI entries found in either .debug_frame or .eh_frame.")
            return

        logger.info("Analyzing CFI section for CFA information.")

        # Iterate through the CIE and FDE entries
        for entry in cfi_entries:
            if isinstance(entry, CIE):
                self.log_cie_details(entry)
            elif isinstance(entry, FDE):
                logger.info(f"FDE: Start PC: {entry['initial_location']}, Range: {entry['address_range']}")
                self.process_fde_instructions(entry)

    def get_cfi_entries(self, dwarf_info):
        """ Get CFI entries from .debug_frame or fallback to .eh_frame """
        cfi_entries = None

        if dwarf_info.debug_frame_sec:
            logger.info("Analyzing .debug_frame section for CFA information.")
            try:
                cfi_entries = dwarf_info.CFI_entries()
            except AttributeError:
                logger.error(".debug_frame section is not valid.")

        if not cfi_entries:
            logger.info("Trying .eh_frame section for CFA information.")
            cfi_entries = dwarf_info.EH_CFI_entries()

        return cfi_entries

    def log_cie_details(self, cie):
        """ Log details about CIE (Common Information Entry) """
        code_alignment = cie.header.get('code_alignment_factor', 'N/A')
        data_alignment = cie.header.get('data_alignment_factor', 'N/A')
        return_column = cie.header.get('return_address_column', 'N/A')

        logger.debug(f"CIE: Code alignment: {code_alignment}, Data alignment: {data_alignment}, Return column: {return_column}")

    def process_fde_instructions(self, fde):
        """ Process the Frame Description Entry (FDE) instructions to extract CFA details """
        decoded_table = fde.get_decoded()

        # Iterate over each row in the decoded call frame table
        for row in decoded_table.table:
            pc = row['pc']
            cfa_rule = row['cfa']

            # Parse the CFA rule to extract register and offset details
            cfa_description = describe_CFI_CFA_rule(cfa_rule)
            # logger.info(f"PC: {pc}, CFA: {cfa_description}")

            if isinstance(cfa_rule, CFARule):
                if cfa_rule.reg is not None:
                    # Use describe_CFI_CFA_rule to get a human-readable register name and offset
                    readable_cfa = describe_CFI_CFA_rule(cfa_rule)

                    # Store the human-readable CFA information
                    self.cfa_dict[pc] = readable_cfa
                else:
                    # Handle other cases, such as expressions, if applicable
                    logger.warning(f"CFA for PC {pc} has no direct register base")
            else:
                logger.error(f"Unexpected CFA rule type for PC {pc}")

            # Process any instructions in the row
            # if 'instructions' in row:
            #     self.process_instructions(row['instructions'])
            # else:
            #     logger.debug(f"No instructions found for PC: {row['pc']}")

    def process_instructions(self, instructions):
        """ Process the list of instructions in the row """
        for instruction in instructions:
            if instruction.op_name == 'DW_CFA_def_cfa':
                reg_num, offset = instruction.args
                reg_name = describe_reg_name(reg_num, 'x86_64')  # Assuming x86_64 architecture
                logger.info(f"CFA defined as register {reg_name} with offset {offset}")
            elif instruction.op_name == 'DW_CFA_def_cfa_offset':
                offset = instruction.args[0]
                logger.info(f"CFA offset set to {offset}")
            elif instruction.op_name == 'DW_CFA_offset':
                reg_num, offset = instruction.args
                reg_name = describe_reg_name(reg_num, 'x86_64')
                logger.info(f"Register {reg_name} saved at offset {offset} relative to CFA")
                if reg_num == 16:  # Register 16 is RIP in x86_64
                    logger.info(f"Return address (RIP) saved at offset {offset} relative to CFA.")
            elif instruction.op_name == 'DW_CFA_advance_loc':
                loc_increment = instruction.args[0]
                logger.debug(f"Advance location by {loc_increment}")
            elif instruction.op_name == 'DW_CFA_remember_state':
                logger.debug("Remember current state")
            elif instruction.op_name == 'DW_CFA_restore_state':
                logger.debug("Restore previously remembered state")
            else:
                logger.debug(f"Unhandled DWARF instruction: {instruction.op_name}")


    def run(self):
        # Add .eh_frame analysis after DWARF analysis
        self.analyze_eh_frame()

        # exit()
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
        return_fun_list = fun_list.copy()
        fun_list.clear()
        return return_fun_list

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
    
    def process_inlined_parameter(self, CU, DIE):
        """Helper method to process a formal parameter in an inlined function."""
        logger.info(f"{MAGENTA}Processing inlined parameter: {RESET}")

        # Handle attributes of DW_TAG_formal_parameter
        abstract_origin = DIE.attributes.get('DW_AT_abstract_origin')
        const_value = DIE.attributes.get('DW_AT_const_value')

        if abstract_origin:
            logger.debug(f"Abstract Origin: {abstract_origin.value:#x}")
        if const_value is not None:
            logger.debug(f"Const Value: {const_value.value}")

    def process_die(self, CU, DIE):

        """Helper method to process a DIE and its children recursively."""
        # Handle the DIE's tag
        if DIE.tag == "DW_TAG_subprogram":
            # Check if this is an inlined function by looking for DW_AT_abstract_origin
            if 'DW_AT_abstract_origin' in DIE.attributes:
                self.analyze_inlined_fun(CU, DIE)
            else:
                # Process the subprogram as a normal function
                self.analyze_subprog(CU, DIE)
                return
        elif DIE.tag == "DW_TAG_inlined_subroutine":
            logger.info(f"{LIGHT_BLUE}Processing inlined subroutine:{RESET}")
            abstract_origin = DIE.attributes.get('DW_AT_abstract_origin')
            entry_pc = DIE.attributes.get('DW_AT_entry_pc')
            low_pc = DIE.attributes.get('DW_AT_low_pc')
            high_pc = DIE.attributes.get('DW_AT_high_pc')

            # Process parameters from abstract origin first
            if abstract_origin:
                origin_offset = abstract_origin.value
                origin_die = CU.get_DIE_from_refaddr(origin_offset)
                if origin_die:
                    logger.debug(f"Abstract Origin DIE: {origin_die.tag}")
                    # Handle parameters from the abstract origin
                    for param in origin_die.iter_children():
                        if param.tag == "DW_TAG_formal_parameter":
                            # Avoid reprocessing if the parameter has already been processed
                            param_origin = param.attributes.get('DW_AT_abstract_origin')
                            if not param_origin or param_origin.value not in self.processed_params:
                                self.process_inlined_parameter(CU, param)
                                self.processed_params.add(param_origin.value if param_origin else param.offset)

            if entry_pc:
                logger.debug(f"Entry PC: {entry_pc.value:#x}")
            if low_pc and high_pc:
                logger.debug(f"Range: [{low_pc.value:#x}, {low_pc.value + high_pc.value:#x}]")

            # Process direct children parameters if not already processed
            for child in DIE.iter_children():
                if child.tag == "DW_TAG_formal_parameter":
                    abstract_origin_attr = child.attributes.get('DW_AT_abstract_origin')
                    if not abstract_origin_attr or abstract_origin_attr.value not in self.processed_params:
                        logger.debug("Processing formal parameter directly attached to inlined subroutine")
                        self.process_inlined_parameter(CU, child)
                        self.processed_params.add(abstract_origin_attr.value if abstract_origin_attr else child.offset)
            return

        elif DIE.tag == "DW_TAG_formal_parameter":
            abstract_origin_attr = DIE.attributes.get('DW_AT_abstract_origin')

            # Check if this parameter has already been processed
            if not abstract_origin_attr or abstract_origin_attr.value not in self.processed_params:
                logger.debug("Processing formal parameter directly encountered in the DIE")
                self.process_inlined_parameter(CU, DIE)
                # Add to processed_params to avoid re-processing
                self.processed_params.add(abstract_origin_attr.value if abstract_origin_attr else DIE.offset)
            return
        elif DIE.tag == "DW_TAG_variable":
            self.analyze_var(CU, DIE, DIE.attributes.values())
            return
        elif DIE.tag == "DW_TAG_base_type":
            self.analyze_base(CU, DIE, DIE.attributes.values())
            return
        if DIE.tag == "DW_TAG_structure_type":
            # Process and create StructData
            self.curr_struct = self.analyze_struct(CU, DIE, DIE.attributes.values())
            self.curr_members = list()  # Initialize members list
            return
        elif DIE.tag == "DW_TAG_member":
            # Process members and append to the current struct
            if self.curr_struct == None: # Debugging
                return
            member = self.analyze_member(CU, DIE, DIE.attributes.values())
            self.curr_members.append(member)
            return
        elif DIE.tag == "DW_TAG_typedef":
            if len(struct_list) > 0:
                self.curr_typedef = self.analyze_typedef(CU, DIE, DIE.attributes.values())
                if self.curr_typedef and self.curr_typedef.var_type == "DW_TAG_structure_type":
                    # Associate the typedef with the most recent struct
                    recent_struct: StructData
                    recent_struct = struct_list[-1]
                    recent_struct.name = self.curr_typedef.typedef_name
                    # Modified from the pop method to keep the data inside the struct_list in case
                    logger.debug(f"{BRIGHT_RED}Associate the typedef with the most recent struct {LIGHT_BLUE}{recent_struct.name}{RESET}")
                    print_struct_data(recent_struct)
                    self.curr_typedef.struct = recent_struct
                    self.curr_typedef = None
            else:
                self.curr_typedef = self.analyze_typedef(CU, DIE, DIE.attributes.values())
            return
        elif DIE.tag == None:
            if self.stored_typedef is not None:
                self.stored_typedef.struct.member_list = self.curr_members.copy()
                logger.debug(f"Adding members to struct typedef: {self.stored_typedef.typedef_name}")
                logger.warning("Clearing the struct")
                self.stored_typedef = None # Clear the stored typedef as well
                self.curr_members.clear()
            elif self.curr_struct is not None:
                self.curr_struct.member_list = self.curr_members.copy()
                logger.warning("Clearing the struct")
                # print_struct_data(self.curr_struct)
                struct_list.append(self.curr_struct)
                self.curr_struct = None
                self.curr_members.clear()
            return
        else:
            logger.error(f"Not yet handling the tag {DIE.tag}.\n")
            return
            
def dwarf_analysis(input_binary):
    
    logger.info("DWARF analysis")
    target_dir = Path(os.path.abspath(input_binary))
    base_name = Path(input_binary).stem
    # logger.debug(base_name)
    dwarf_outfile   = target_dir.parent.joinpath("%s.dwarf" % base_name)
    logger.debug(dwarf_outfile)
    fp = open(dwarf_outfile, "w")
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

        analyzer = DwarfAnalyzer(base_name, dwarf_info, loc_parser, fp, elffile)
        
        return analyzer.run()