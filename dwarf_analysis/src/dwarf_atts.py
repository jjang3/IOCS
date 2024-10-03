import sys, getopt
import logging, os
import re
import pprint
import copy
from tkinter import FALSE
# from binaryninja.types import MemberName

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

type_dict = dict()
@dataclass(unsafe_hash=True)
class VarData:
    name: Optional[str] = None
    offset: str = None
    var_type: str = None
    ptr_type: Optional[str] = None # Currently not used, if type_name is not found in the type_dict, then we can safely assume that pointer is to an object we cannot handle (e.g., struct)
    type_name: str = None
    member_list: Optional[list] = None # This is if the variable is a struct type, then we need to update the member information
    is_typedef: Optional[bool] = False

def print_var_data(var_data: VarData):
    """Prints the VarData information, and if the variable is a struct type, prints its members."""
    
    # Basic attributes for the variable
    attributes = [
        ("Name", var_data.name),
        ("Offset", var_data.offset),
        ("Var Type", var_data.var_type),
        ("Ptr Type", var_data.ptr_type),
        ("Type Name", var_data.type_name),
    ]
    
    # Construct the output for the basic variable information
    output = []
    for attr_name, attr_value in attributes:
        if attr_value is not None:
            output.append(f"{attr_name}: {attr_value}")
    
    # Print basic variable data
    logger.debug(", ".join(output))
    
    # If the variable has a member list, print member details
    if var_data.member_list:
        logger.debug("Members:")
        for member in var_data.member_list:
            logger.debug(f"  - {member.name}, Offset: {member.offset}, Var Type: {member.var_type}, Type Name: {member.type_name}")


struct_list = list()
@dataclass(unsafe_hash = True)
class StructData:
    name: Optional[str] = None
    offset: str = None
    size: int = None
    line: int = None
    member_list: Optional[list] = None

def print_struct_data(struct_data: StructData):
    """Prints the StructData information, omitting fields that are None."""
    attributes = [
        ("Name", struct_data.name),
        ("Offset", struct_data.offset),
        ("Size", struct_data.size),
        ("Line", struct_data.line),
    ]
    
    # Construct the output string
    output = []
    for attr_name, attr_value in attributes:
        if attr_value is not None:
            output.append(f"{attr_name}: {attr_value}")
    
    # Print the cleaned output
    logger.debug(", ".join(output))
    # Handle the member list
    if struct_data.member_list:
        for member in struct_data.member_list:
            print_var_data(member)
    else:
        logger.debug("Member List: None")

# This list will contain the typedef variable information of this program
typedef_list = list()
@dataclass(unsafe_hash=True)
class TypeDefData:
    typedef_name: Optional[str] = None
    var_type: str = None
    type_name: str = None
    type_size: Optional[int] = None
    struct: Optional[StructData] = None

def print_typedef_data(typedef_data: TypeDefData):
    """Prints the TypeDefData information, omitting fields that are None."""
    attributes = [
        ("Typedef Name", typedef_data.typedef_name),
        ("Var Type", typedef_data.var_type),
        ("Type Name", typedef_data.type_name),
        ("Type Size", typedef_data.type_size),
    ]
    
    # Construct the output string
    output = []
    for attr_name, attr_value in attributes:
        if attr_value is not None:
            output.append(f"{attr_name}: {attr_value}")
    
    # Print the cleaned output
    logger.debug(", ".join(output))
    
    # Print the associated StructData if present
    if typedef_data.struct is not None:
        logger.debug("Struct Information:")
        print_struct_data(typedef_data.struct)
    print()

 # ANSI escape codes for colors
LIGHT_BLUE = "\033[96m"
RESET = "\033[0m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[36m"
MAGENTA = "\033[95m"
ORANGE = "\033[38;5;214m" 
BRIGHT_RED = "\033[91m"

# Global function list 
fun_list = list()
class FunData:
    def __init__(self, name: str = None, begin: Optional[int] = None, end: Optional[int] = None, is_inlined=False):
        self.name = name
        self.begin = begin
        self.end = end
        self.reg_to_use = None
        self.fun_frame_base = None
        self.var_list: List[VarData] = []  # List to store VarData instances
        self.is_inlined = is_inlined
        self.inlined_instances = []  # List to store inlined instances
    
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

    def add_inlined_instance(self, begin, end):
        """Adds an inlined instance with start and end addresses."""
        self.inlined_instances.append((begin, end))

    def print_data(self):
        """Prints the function's data in a detailed and color-coded format."""
        logger.info(f"{LIGHT_BLUE}Function Name: {self.name}{RESET}")

        # Print begin and end addresses
        logger.debug(f"{CYAN}Begin Address: {(self.begin) if self.begin is not None else 'None'}{RESET}")
        logger.debug(f"{CYAN}End Address: {(self.end) if self.end is not None else 'None'}{RESET}")

        # Print frame base if available
        if self.fun_frame_base is not None:
            sign = '+' if self.fun_frame_base >= 0 else ''
            logger.debug(f"{CYAN}Frame base: {self.reg_to_use}{sign}{self.fun_frame_base}{RESET}")

        # Print information if the function is inlined
        if self.is_inlined:
            logger.debug(f"{YELLOW}This function is inlined{RESET}")
            for idx, (begin, end) in enumerate(self.inlined_instances):
                logger.debug(f"Inlined instance {idx + 1}:")
                logger.debug(f"  Begin Address: {hex(begin)}")
                logger.debug(f"  End Address: {hex(end)}")

        # Print variable information
        if self.var_list:
            logger.debug(f"{YELLOW}Variables:{RESET}")
            for var in self.var_list:
                logger.debug(f"{YELLOW}  - Variable Name: {var.name}{RESET}")

                if var.offset is not None:
                    logger.debug(f"{GREEN}    Offset: {var.offset}{RESET}")
                else:
                    logger.debug(f"{BRIGHT_RED}    Offset: None (Optimized or is a constant){RESET}")

                logger.debug(f"{MAGENTA}    Var Type: {var.var_type}{RESET}")
                logger.debug(f"    Type Name: {var.type_name}")
                if var.ptr_type is not None:
                    logger.debug(f"    Pointer Type: {var.ptr_type}")

                # Print struct members if available
                if var.member_list:
                    logger.debug(f"{GREEN}    Struct Members:{RESET}")
                    for member in var.member_list:
                        logger.debug(f"{YELLOW}      - Member Name: {member.name}{RESET}")
                        if member.offset is not None:
                            logger.debug(f"{GREEN}        Offset: {member.offset}{RESET}")
                        else:
                            logger.debug(f"{BRIGHT_RED}        Offset: None (Optimized or is a constant){RESET}")
                        logger.debug(f"{MAGENTA}        Var Type: {member.var_type}{RESET}")
                        logger.debug(f"        Type Name: {member.type_name}")
                print()

        # Print typedef information if applicable
        for var in self.var_list:
            if var.is_typedef:
                for typedef in typedef_list:
                    if typedef.typedef_name == var.type_name:
                        logger.debug(f"{CYAN}    Typedef: {typedef.typedef_name}{RESET}")
                        print_typedef_data(typedef)

        print()


    def __repr__(self):
        return f"FunData(name={self.name}, begin={self.begin}, end={self.end}, inlined={self.is_inlined})"

def parse_pc_range(DIE):
    """Helper function to parse DW_AT_low_pc and DW_AT_high_pc attributes."""
    low_pc_attr = DIE.attributes.get('DW_AT_low_pc', None)
    high_pc_attr = DIE.attributes.get('DW_AT_high_pc', None)
    
    if low_pc_attr and high_pc_attr:
        low_pc = low_pc_attr.value
        high_pc_form_class = describe_form_class(high_pc_attr.form)

        if high_pc_form_class == 'address':
            high_pc = high_pc_attr.value
        elif high_pc_form_class == 'constant':
            high_pc = low_pc + high_pc_attr.value
        else:
            logger.error(f"Invalid DW_AT_high_pc form class: {high_pc_form_class}")
            return None, None

        return low_pc, high_pc
    else:
        logger.warning("Function has no valid DW_AT_low_pc or DW_AT_high_pc")
        return None, None

def parse_frame_base(DIE, dwarf_info, loc_parser, CU, curr_fun, cfa_dict):
    """Helper function to handle DW_AT_frame_base attribute using CFA information from cfa_dict."""
    
    frame_base_attr = DIE.attributes.get('DW_AT_frame_base', None)
    if frame_base_attr:
        logger.debug(f"DW_AT_frame_base found for function '{curr_fun.name}'")

        # Parse the frame base attribute using loc_parser
        loc = loc_parser.parse_from_attribute(frame_base_attr, CU['version'])
        
        if isinstance(loc, list):
            # Iterate over location entries to extract relevant frame base information
            for loc_entity in loc:
                if isinstance(loc_entity, LocationEntry):
                    pc_begin = loc_entity.begin_offset
                    pc_end = loc_entity.end_offset
                    logger.info(f"Fun '{curr_fun.name}' uses frame base for PC range {hex(pc_begin)} - {hex(pc_end)}")

                    # Set frame base for each PC in the range based on cfa_dict
                    for pc in range(pc_begin, pc_end + 1):
                        if pc in cfa_dict:
                            cfa_value = cfa_dict[pc]
                            if not hasattr(curr_fun, 'frame_base_dict'):
                                curr_fun.frame_base_dict = {}
                            curr_fun.frame_base_dict[pc] = ("cfa", cfa_value)
                            logger.debug(f"Set CFA-based frame base for PC {hex(pc)}: ('cfa', {cfa_value})")
                        # else:
                        #     logger.warning(f"No CFA value found in cfa_dict for PC {hex(pc)} in function '{curr_fun.name}'")

            # Determine the general frame base to use for the function based on `cfa_dict` values
            if curr_fun.frame_base_dict:
                # For simplicity, pick the frame base from the midpoint of the function range as representative
                midpoint_pc = (curr_fun.begin + curr_fun.end) // 2
                if midpoint_pc in curr_fun.frame_base_dict:
                    cfa_type, cfa_value = curr_fun.frame_base_dict[midpoint_pc]
                    curr_fun.reg_to_use = cfa_value.split('+')[0]  # e.g., 'rbp' or 'rsp'
                    curr_fun.fun_frame_base = int(cfa_value.split('+')[1])  # e.g., offset value
                else:
                    logger.warning(f"Midpoint PC {hex(midpoint_pc)} not found in frame_base_dict for function '{curr_fun.name}'")
        else:
            # Handle non-location list attributes (directly decoded frame base)
            decoded_frame_base = describe_DWARF_expr(frame_base_attr.value, dwarf_info.structs, CU.cu_offset)
            # logger.debug(f"Decoded frame base: {decoded_frame_base}")

            if "DW_OP_call_frame_cfa" in decoded_frame_base:
                logger.info(f"Function '{curr_fun.name}' uses DW_OP_call_frame_cfa")

                # Use the CFA values from cfa_dict for each PC in the function range
                for pc in range(curr_fun.begin, curr_fun.end + 1):
                    if pc in cfa_dict:
                        cfa_value = cfa_dict[pc]
                        if not hasattr(curr_fun, 'frame_base_dict'):
                            curr_fun.frame_base_dict = {}
                        curr_fun.frame_base_dict[pc] = ("cfa", cfa_value)
                        # logger.debug(f"Set CFA-based frame base for PC {hex(pc)}: ('cfa', {cfa_value})")

                # Check if we have consistent CFA values with rbp and offset +16
                consistent_rbp_offset = False
                for cfa_type, cfa_value in curr_fun.frame_base_dict.values():
                    if cfa_type == "cfa" and "rbp" in cfa_value:
                        reg, offset = cfa_value.split('+')
                        offset = int(offset)
                        if reg.strip() == "rbp" and offset == 16:
                            consistent_rbp_offset = True
                            break

                if consistent_rbp_offset:
                    logger.info(f"Using rbp + 16 as the frame base for function '{curr_fun.name}'")
                    curr_fun.reg_to_use = "rbp"
                    curr_fun.fun_frame_base = 16
                else:
                    logger.warning(f"No consistent 'rbp + 16' found in CFA values for function '{curr_fun.name}'")

            else:
                # Assume other frame bases are also using rbp with offset found from cfa_dict if available
                logger.warning(f"Non-CFA frame base expression detected, attempting to derive frame base")
                for pc in range(curr_fun.begin, curr_fun.end + 1):
                    if pc in cfa_dict:
                        cfa_value = cfa_dict[pc]
                        if "rbp" in cfa_value:
                            reg, offset = cfa_value.split('+')
                            curr_fun.reg_to_use = reg.strip()
                            curr_fun.fun_frame_base = int(offset)
                            logger.info(f"Using derived frame base '{reg.strip()} + {offset}' for function '{curr_fun.name}'")
                            break

    else:
        # If there's no DW_AT_frame_base attribute, log a warning
        logger.warning(f"No DW_AT_frame_base found for function '{curr_fun.name}', unable to determine frame base")


def analyze_subprog(CU: CompileUnit, dwarf_info, DIE, loc_parser, cfa_dict):
    """Analyze subprogram DIE and extract function data."""
    fun_name_attr = DIE.attributes.get("DW_AT_name", None)
    if fun_name_attr:
        fun_name = fun_name_attr.value.decode()
        logger.info(f"Analyzing function: {fun_name}")
    else:
        logger.warning("Subprogram has no name, likely inlined")
        return None

    # Initialize FunData object
    curr_fun = FunData(name=fun_name)

    # Skip external functions with DW_AT_declaration
    is_declaration = DIE.attributes.get('DW_AT_declaration', None)

    if is_declaration and is_declaration.value:
        logger.error(f"Skipping external function {fun_name} as it is only a dec.\n")
        return None

    # Parse low_pc and high_pc
    low_pc, high_pc = parse_pc_range(DIE)
    if low_pc is not None and high_pc is not None:
        curr_fun.begin = low_pc
        curr_fun.end = high_pc
        # logger.debug(f"Set begin: {hex(curr_fun.begin)}, end: {hex(curr_fun.end)}")

    # Handle frame base
    parse_frame_base(DIE, dwarf_info, loc_parser, CU, curr_fun, cfa_dict)

    # Finalize analysis for subprogram
    # logger.info("Finished analyzing subprogram")
    return curr_fun

def analyze_inlined(CU: CompileUnit, dwarf_info, DIE, loc_parser, cfa_dict):
    """Process an inlined function by updating its low_pc, high_pc, and frame base."""
    abstract_origin_offset = DIE.attributes['DW_AT_abstract_origin'].value
    abstract_origin = dwarf_info.get_DIE_from_refaddr(abstract_origin_offset)

    if 'DW_AT_name' in abstract_origin.attributes:
        abstract_name = abstract_origin.attributes["DW_AT_name"].value.decode()
        curr_fun = next((fun for fun in fun_list if fun.name == abstract_name), None)

        if curr_fun:
            # Update the inlined function's begin and end addresses
            low_pc, high_pc = parse_pc_range(DIE)
            if low_pc is not None and high_pc is not None:
                curr_fun.begin = low_pc
                curr_fun.end = high_pc
                logger.info(f"Updated inlined function {abstract_name}: {hex(low_pc)}/{hex(high_pc)}")
                parse_frame_base(DIE, dwarf_info, loc_parser, CU, curr_fun, cfa_dict)
                curr_fun.print_data()
            else:
                logger.warning(f"Inlined function {abstract_name} missing PC range")
        else:
            logger.warning(f"No corresponding FunData found for inlined function {abstract_name}")
    else:
        logger.warning(f"Abstract origin DIE has no name attribute")


def get_type_name(dwarf_info: DWARFInfo, type_die: DIE, from_typedef=False):
    seen_dies = set()  # To track visited DIEs and avoid infinite loops

    while type_die:
        # If it's a typedef and it has a name, use the typedef's name and stop recursion
        if type_die.tag == "DW_TAG_typedef":
            if 'DW_AT_name' in type_die.attributes:
                typedef_name = type_die.attributes['DW_AT_name'].value.decode()
                logger.debug(f"Got typedef name: {typedef_name}")
                return typedef_name
            elif 'DW_AT_type' in type_die.attributes:
                ref_addr = type_die.attributes['DW_AT_type'].value + type_die.cu.cu_offset
                if ref_addr in seen_dies:
                    logger.error("Infinite loop detected in typedef chain.")
                    return None
                seen_dies.add(ref_addr)
                type_die = dwarf_info.get_DIE_from_refaddr(ref_addr, type_die.cu)

        # If the type has a name, return the name
        elif 'DW_AT_name' in type_die.attributes:
            type_name = type_die.attributes['DW_AT_name'].value.decode()
            logger.debug(f"Got the type name: {type_name}")
            return type_name

        # If it's a structure type and has no name, look for the typedef that referred to it
        elif type_die.tag == "DW_TAG_structure_type":
            if from_typedef:
                logger.warning("No name for the structure type, using typedef name.")
                return None  # No name in the structure type, the typedef should provide the name

            if 'DW_AT_type' in type_die.attributes:
                ref_addr = type_die.attributes['DW_AT_type'].value + type_die.cu.cu_offset
                if ref_addr in seen_dies:
                    logger.error("Infinite loop detected in type chain.")
                    return None
                seen_dies.add(ref_addr)
                type_die = dwarf_info.get_DIE_from_refaddr(ref_addr, type_die.cu)
            else:
                logger.warning(f"No name or type found for the DIE: {type_die.tag}")
                break

        # Follow the DW_AT_type chain for other types
        elif 'DW_AT_type' in type_die.attributes:
            ref_addr = type_die.attributes['DW_AT_type'].value + type_die.cu.cu_offset
            if ref_addr in seen_dies:
                logger.error("Infinite loop detected in type chain.")
                return None
            seen_dies.add(ref_addr)
            type_die = dwarf_info.get_DIE_from_refaddr(ref_addr, type_die.cu)

        # If no name or type is found, break out of the loop
        else:
            logger.warning(f"No name or type found for the DIE: {type_die.tag}")
            break
    return None

def parse_dwarf_type(dwarf_info, DIE, curr_var: VarData):
    """
    Parses the DWARF type information for a given DIE and updates the current variable's type information.

    Parameters:
    dwarf_info: The DWARFInfo object that holds DWARF information.
    DIE: The current DIE being analyzed (should contain type info).
    curr_var: The VarData object representing the current variable whose type is being analyzed.

    Returns:
    None. The function modifies the `curr_var` object with the parsed type information.
    """

    logger.info(f"Parsing DWARF Type for the tag: {DIE.tag}")
    # Check if the DIE contains a DW_AT_type attribute.
    if 'DW_AT_type' in DIE.attributes:
        # Resolve the referenced type DIE.
        ref_addr = DIE.attributes['DW_AT_type'].value + DIE.cu.cu_offset
        type_die = dwarf_info.get_DIE_from_refaddr(ref_addr, DIE.cu)

        # Handle base type (e.g., int, float, etc.)
        if type_die.tag == "DW_TAG_base_type":
            logger.debug("Processing DW_TAG_base_type")
            set_var_type(dwarf_info, type_die, curr_var)

        # Handle pointer or array type (e.g., pointers to other types or arrays).
        elif type_die.tag in ["DW_TAG_pointer_type", "DW_TAG_array_type"]:
            logger.debug(f"Processing {type_die.tag}")
            set_var_type(dwarf_info, type_die, curr_var)

        # Handle typedef types, which may refer to other types.
        elif type_die.tag == "DW_TAG_typedef":
            logger.debug("Processing DW_TAG_typedef")
            curr_var.is_typedef = True  # Mark this variable as a typedef.
            process_typedef(dwarf_info, type_die, curr_var)

        # Handle structure types.
        elif type_die.tag == "DW_TAG_structure_type":
            logger.debug("Processing DW_TAG_structure_type")
            process_structure_type(dwarf_info, type_die, curr_var)

        elif type_die.tag == "DW_TAG_const_type":
            logger.debug(f"Variable {curr_var.name} is a constant.")
            curr_var.is_constant = True

        else:
            # If the type is unsupported, log an error and assign the tag as the variable type.
            curr_var.var_type = type_die.tag
            logger.error(f"Not supported yet: {type_die.tag}")

    # Handle cases where DIE has a DW_AT_name but no DW_AT_type (e.g., typedef uint16_t).
    elif 'DW_AT_name' in DIE.attributes:
        curr_var.var_type = DIE.tag
        logger.debug("Processing a named type without DW_AT_type")
        type_name = get_type_name(dwarf_info, DIE)
        if type_name:
            curr_var.type_name = type_name

    # If there's no type or name, just assign the DIE tag.
    else:
        curr_var.var_type = DIE.tag


def set_var_type(dwarf_info, type_die, curr_var):
    """
    Helper function to set the base type or pointer/array type for the current variable.
    """
    # logger.debug("Setting the variable type")
    curr_var.var_type = type_die.tag
    type_name = get_type_name(dwarf_info, type_die)
    if type_name:
        curr_var.type_name = type_name


def process_typedef(dwarf_info, type_die, curr_var):
    """
    Helper function to process typedefs, which may refer to underlying types.
    Recursively follows typedef references and sets the type for curr_var.
    """
    logger.debug("Processing typedef variable")

    # Check if DW_AT_name is present in the typedef DIE, and directly use it as the type name
    if 'DW_AT_name' in type_die.attributes:
        typedef_name = type_die.attributes['DW_AT_name'].value.decode()
        curr_var.type_name = typedef_name
        logger.debug(f"Using typedef name: {typedef_name}")

    # Resolve the underlying type that this typedef points to
    if 'DW_AT_type' in type_die.attributes:
        typedef_ref_addr = type_die.attributes['DW_AT_type'].value + type_die.cu.cu_offset
        typedef_type_die = dwarf_info.get_DIE_from_refaddr(typedef_ref_addr, type_die.cu)
        parse_dwarf_type(dwarf_info, typedef_type_die, curr_var)

    # Handle structure types referred by typedef
    if curr_var.var_type == "DW_TAG_structure_type" and not curr_var.type_name:
        # If no name has been assigned to the structure, try to retrieve it from the structure DIE
        type_name = get_type_name(dwarf_info, type_die)
        if type_name:
            curr_var.type_name = type_name
            logger.debug(f"Retrieved structure name from typedef: {type_name}")


def process_structure_type(dwarf_info, type_die, curr_var):
    """
    Helper function to process structure types and update curr_var with structure-related info.
    """
    logger.debug("Processing structure type")
    curr_var.var_type = type_die.tag
    type_name = get_type_name(dwarf_info, type_die)
    if type_name:
        curr_var.type_name = type_name
    else:
        logger.debug(f"Unnamed structure for variable: {curr_var}")


def analyze_var(CU, dwarf_info, DIE, attribute_values, loc_parser, curr_fun: FunData, cfa_dict):
    """
    Analyzes a DW_TAG_variable DIE within the context of a function (curr_fun).

    Parameters:
    CU: Compilation Unit that contains this DIE.gcc 
    dwarf_info: DWARFInfo object for accessing DIE data.
    DIE: Current DIE being analyzed (expected to be a DW_TAG_variable).
    attribute_values: Attributes associated with this DIE.
    loc_parser: Helper for parsing location expressions.
    curr_fun: FunData object representing the current function context.

    Returns:
    None. Updates the current function's variable list (if applicable).
    """

    # Regular expressions to extract frame base and global variable addresses.
    offset_pattern = r"\(DW_OP_fbreg:\s*(-?\d+)\)"
    global_pattern = r"(?<=\(DW_OP_addr:\s)(.*)(?=\))"
    global_var = False


    # Check if the variable belongs to a function (global vars are not supported here).
    if curr_fun is not None:
        logger.info(f"{LIGHT_BLUE}Analyze DW_TAG_variable for the Fun: {curr_fun.name}{RESET}")
    else:
        global_var = True
        logger.warning("Global variable or function to be ignored")
        # Exit early if the variable is global (not supported).
        return None

    curr_var = None  # Initialize the current variable being processed.

    # Iterate through the attributes of the DW_TAG_variable DIE.
    for attr in attribute_values:

        # Handle DW_AT_name attribute (to extract the variable's name).
        if attr.name == "DW_AT_name":
            var_name = DIE.attributes["DW_AT_name"].value.decode()
            if var_name is not None:
                curr_var = VarData(name=var_name)
                # Ensure that the variable is not already present in the function's variable list.
                if curr_fun is not None and not curr_fun.find_var(curr_var):
                    logger.debug(f"Adding variable: {curr_var.name}")
                    curr_fun.add_var(curr_var)

        # If curr_var is set, process its attributes (such as location and type).
        if curr_var is not None:
            # Check for location information using loc_parser.
            if loc_parser.attribute_has_location(attr, CU.header['version']):
                loc = loc_parser.parse_from_attribute(attr, CU.header['version'], die=DIE)
                if isinstance(loc, list):
                    # Iterate through location entries to extract PC ranges
                    for loc_entry in loc:
                        if isinstance(loc_entry, LocationEntry):
                            pc_begin = loc_entry.begin_offset
                            pc_end = loc_entry.end_offset
                            logger.warning(f"Variable {curr_var.name} is valid from PC {(pc_begin)} to {(pc_end)}")
                            
                            # Extract frame base offset from the location expression if available
                            offset = describe_DWARF_expr(loc_entry.loc_expr, dwarf_info.structs, CU.cu_offset)
                            offset_match = re.search(offset_pattern, offset)

                            if offset_match:
                                # Compute the variable's offset relative to the function's frame base.
                                offset_value = int(offset_match.group(1))
                                if curr_fun.fun_frame_base is not None:
                                    final_offset = curr_fun.fun_frame_base + offset_value
                                    logger.debug(f"Register Offset: {curr_fun.reg_to_use}{final_offset}")
                                    curr_var.offset = final_offset

                            # Handle global variables by extracting their address.
                            global_match = re.search(global_pattern, offset)
                            if global_match:
                                addr_value = global_match.group(1)
                                logger.debug(f"Address: {addr_value}")
                    # exit()
                elif isinstance(loc, LocationExpr):
                    # Extract frame base offset from the location expression.
                    offset = describe_DWARF_expr(loc.loc_expr, dwarf_info.structs, CU.cu_offset)
                    offset_match = re.search(offset_pattern, offset)

                    if offset_match:
                        # Compute the variable's offset relative to the function's frame base.
                        offset_value = int(offset_match.group(1))
                        final_offset = curr_fun.fun_frame_base + offset_value
                        logger.debug(f"{GREEN}Register Offset: {curr_fun.reg_to_use}{final_offset}{RESET}")
                        curr_var.offset = final_offset
                        # Handle struct type variables by resolving their members and offsets.
                        if curr_var.var_type == "DW_TAG_structure_type" and curr_var.member_list is None:
                            for struct in struct_list:
                                print(struct.name)
                                if curr_var.type_name == struct.name: # Shouldn't this be type_name? why curr_var.name
                                    print(struct.member_list)
                                    curr_var.member_list = copy.deepcopy(struct.member_list)
                                    logger.debug(f"Copying the member list with {LIGHT_BLUE}{struct.name}{RESET}")
                                
                            for member in curr_var.member_list:
                                member.offset += curr_var.offset

                            pprint.pprint(curr_var.member_list)
                        elif curr_var.var_type == "DW_TAG_structure_type" and curr_var.member_list is not None:
                            for member in curr_var.member_list:
                                member.offset += curr_var.offset
                            pprint.pprint(curr_var.member_list)
                    
                    # Handle global variables by extracting their address.
                    global_match = re.search(global_pattern, offset)
                    if global_match:
                        addr_value = global_match.group(1)
                        logger.debug(f"Address: {addr_value}")
                else:
                    logger.error("")

            # If the attribute is DW_AT_type, parse the variable's type.
            elif attr.name == "DW_AT_type":
                logger.debug("Parsing variable DWARF type")
                parse_dwarf_type(dwarf_info, DIE, curr_var)

                # Handle typedef variables (search typedef_list for corresponding struct).
                if curr_var.is_typedef:
                    for typedef in typedef_list:
                        typedef: TypeDefData
                        if typedef.typedef_name == curr_var.type_name:
                            if curr_var.var_type == "DW_TAG_structure_type":
                                # If the variable is a struct type, copy the member list from the typedef.
                                curr_var.member_list = typedef.struct.member_list.copy() # this should not be deepcopy as we want typedef member_list to be connected
    print()

def analyze_typedef(CU, dwarf_info, DIE, attribute_values):
    print()
    logger.info(f"Analyze DW_TAG_typedef")
    curr_typedef = None
    for attr in attribute_values:
        if attr.name == "DW_AT_name":
            typedef_name = DIE.attributes["DW_AT_name"].value.decode()
            if typedef_name != None:
                logger.debug(f"Name: {typedef_name}")
                curr_typedef = TypeDefData(typedef_name=typedef_name)
        if curr_typedef != None:
            if attr.name == "DW_AT_type":
                parse_dwarf_type(dwarf_info, DIE, curr_typedef)
                if curr_typedef.var_type == "DW_TAG_structure_type":
                    logger.warning("Typedef type: DW_TAG_structure_type")
                    # If the typedef is struct type, then return the typedef to pass the typedef 
                    # to the structure type
                    typedef_list.append(curr_typedef)
                    return curr_typedef
            if curr_typedef.type_name in type_dict:
                curr_typedef.type_size = type_dict[curr_typedef.type_name]

    if curr_typedef != None:
        print_typedef_data(curr_typedef)
        typedef_list.append(curr_typedef)

    return None
            
def analyze_base(CU, dwarf_info, DIE, attribute_values):
    logger.info("Analyze DW_TAG_base_type")
    for attr in attribute_values:
        if (attr.name == "DW_AT_name"):
            base_name = DIE.attributes["DW_AT_name"].value.decode()
        if (attr.name == "DW_AT_byte_size"):
            base_size = DIE.attributes["DW_AT_byte_size"].value
    type_dict[base_name] =  base_size
    print()
    
def analyze_struct(CU, dwarf_info, DIE, attribute_values):
    print() # Analyzing struct without name as its name may be defined later
    logger.info("Analyze DW_TAG_struct_type")
    struct_name = None
    struct_size = None
    line_num = None
    for attr in attribute_values:
        if (attr.name == "DW_AT_name"):
            struct_name = DIE.attributes["DW_AT_name"].value.decode()
            # if struct_name != "http_request": # Debugging
            #     return None
        if (attr.name == "DW_AT_byte_size"):
            struct_size = DIE.attributes["DW_AT_byte_size"].value
        if (attr.name == 'DW_AT_decl_line'):
            line_num    = DIE.attributes['DW_AT_decl_line'].value
    logger.debug(f"{LIGHT_BLUE}{struct_name} {YELLOW}and {struct_size} and {line_num}")
    temp_struct = StructData(name=struct_name,size=struct_size,line=line_num)
    return temp_struct

def analyze_member(CU, dwarf_info, DIE, attribute_values, loc_parser):
    """
    Analyzes a DW_TAG_member DIE to extract member details such as name, offset, type, and type name.

    Parameters:
    CU: Compilation Unit that contains this DIE.
    dwarf_info: DWARFInfo object for accessing DIE data.
    DIE: Current DIE being analyzed (expected to be a DW_TAG_member).
    attribute_values: Attributes associated with this DIE.
    loc_parser: Helper for parsing location expressions.

    Returns:
    VarData: A VarData object containing member details (name, offset, type, type_name).
    """
    
    # Regex for extracting the data member location (offset)
    mem_off_regex = r"(?<=\(DW_OP_plus_uconst:\s)(.*)(?=\))"
    print()
    logger.info("Analyze DW_TAG_member")
    member_var = None  # Initialize the current member variable
    
    # Iterate through the attributes of the DW_TAG_member DIE
    for attr in attribute_values:
        if (attr.name == "DW_AT_name"):
            member_name = DIE.attributes["DW_AT_name"].value.decode()
            if attr.name == "DW_AT_name":
                member_name = DIE.attributes["DW_AT_name"].value.decode()
                if member_name != None:
                    member_var = VarData(name=member_name)
        # If member_var is set, continue processing other attributes
        if member_var:
            # Check for the DW_AT_data_member_location attribute to get the member's offset
            if attr.name == "DW_AT_data_member_location":
                if loc_parser.attribute_has_location(attr, CU['version']):
                    # If the attribute has a location expression, parse it
                    loc = loc_parser.parse_from_attribute(attr, CU['version'])
                    if isinstance(loc, LocationExpr):
                        offset = describe_DWARF_expr(loc.loc_expr, dwarf_info.structs, CU.cu_offset)
                        offset_match = re.search(mem_off_regex, offset)
                        if offset_match:
                            offset_value = int(offset_match.group(1))
                            member_var.offset = offset_value
                            logger.debug(f"Member name: {member_var.name} | Offset value: {offset_value}")
                else:
                    # If it's a simple constant value, directly assign it
                    member_var.offset = attr.value
                    logger.debug(f"Member name: {member_var.name} | Offset value: {member_var.offset}")


            # Check for DW_AT_type attribute to get the member's type and type name
            if attr.name == "DW_AT_type":
                logger.debug("Parsing member's DWARF type")
                parse_dwarf_type(dwarf_info, DIE, member_var)
                

    if member_var != None:
        return member_var
    

def analyze_attributes(attribute_values, location_lists):
    for attr in attribute_values:
        logger.debug(attr)