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

# Global function list 
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
        """Prints the function's data in a detailed and color-coded format."""
        # Function information with LIGHT_BLUE color
        logger.info(f"{LIGHT_BLUE}Function Name: {self.name}{RESET}")
        logger.debug(f"{CYAN}Begin Address: {hex(self.begin) if self.begin else 'None'}{RESET}")
        logger.debug(f"{CYAN}End Address: {hex(self.end) if self.end else 'None'}{RESET}")
        
        if self.fun_frame_base is not None:
            logger.debug(f"{CYAN}Frame base: {self.reg_to_use}-{self.fun_frame_base}{RESET}")
        
        # Print variables with YELLOW color
        if self.var_list:
            logger.debug(f"{YELLOW}Variables:{RESET}")
            for var in self.var_list:
                output = f"{YELLOW}  - {var.name}: Offset {var.offset}, Var Type: {var.var_type}, Type Name: {var.type_name}{RESET}"
                if var.ptr_type is not None:
                    output += f", Pointer Type: {var.ptr_type}"
                logger.debug(output)

                # If the variable is a struct, print its members with GREEN color
                if var.member_list:
                    logger.debug(f"{GREEN}    Struct Members:{RESET}")
                    for member in var.member_list:
                        logger.debug(f"{GREEN}      - {member.name}: Offset {member.offset}, Var Type: {member.var_type}, Type Name: {member.type_name}{RESET}")

        # Print typedef information with CYAN color
        for var in self.var_list:
            if var.is_typedef:
                for typedef in typedef_list:
                    if typedef.typedef_name == var.type_name:
                        logger.debug(f"{CYAN}    Typedef: {typedef.typedef_name}{RESET}")
                        print_typedef_data(typedef)


    def __repr__(self):
        """Returns a string representation of the object."""
        return f"FunData(name={self.name}, begin={self.begin}, end={self.end})"

def analyze_subprog(CU: CompileUnit, dwarf_info, DIE, attribute_values, loc_parser
                    , base_name):
    frame_base_pattern = r"\(DW_OP_breg\d+\s\((\w+)\):\s(-?\d+)\)"
    cfa_pattern = b'\x9c'  # DW_OP_call_frame_cfa
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
                    logger.debug(f"Function {LIGHT_BLUE}{DIE.attributes['DW_AT_name'].value.decode('utf-8')}{RESET} is declared in file: {file_name}")
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

            logger.debug(f"Function name: {fun_name}")

            # 1. Check for DW_AT_frame_base
            frame_base_attr = DIE.attributes.get('DW_AT_frame_base')
            if frame_base_attr:
                logger.debug(f"DW_AT_frame_base found for function {fun_name}")
                # Check if it's a location list or a single location
                loc = loc_parser.parse_from_attribute(frame_base_attr, CU['version'])
                # Handle a list of location entries (location list)
                if isinstance(loc, list):
                    logger.debug("Parsing location list for DW_AT_frame_base")
                    for loc_entity in loc:
                        if isinstance(loc_entity, LocationEntry):
                            offset_expr = describe_DWARF_expr(loc_entity.loc_expr, dwarf_info.structs, CU.cu_offset)
                            logger.debug(f"Location expression: {offset_expr}")
                            
                            # Handle CFA or rbp
                            if "DW_OP_call_frame_cfa" in offset_expr:
                                logger.info(f"Function {fun_name} uses DW_OP_call_frame_cfa for frame base")
                                curr_fun.reg_to_use = "cfa"
                                curr_fun.fun_frame_base = 0  # No offset for CFA itself
                            else:
                                frame_match = re.search(frame_base_pattern, offset_expr)
                                if frame_match:
                                    reg = frame_match.group(1)
                                    offset_value = int(frame_match.group(2))
                                    logger.info(f"Function {fun_name} uses register {reg} with offset {offset_value}")
                                    curr_fun.reg_to_use = reg
                                    curr_fun.fun_frame_base = offset_value
                # Single location expression case
                else:
                    decoded_frame_base = describe_DWARF_expr(frame_base_attr.value, dwarf_info.structs, CU.cu_offset)
                    logger.debug(f"Single location for DW_AT_frame_base: {decoded_frame_base}")
                    if "DW_OP_call_frame_cfa" in decoded_frame_base:
                        logger.info(f"Function {fun_name} uses DW_OP_call_frame_cfa")
                        curr_fun.reg_to_use = "cfa"
                        curr_fun.fun_frame_base = 0  # No offset for CFA
                    else:
                        frame_match = re.search(frame_base_pattern, decoded_frame_base)
                        if frame_match:
                            reg = frame_match.group(1)
                            offset_value = int(frame_match.group(2))
                            logger.info(f"Function {fun_name} uses register {reg} with offset {offset_value}")
                            curr_fun.reg_to_use = reg
                            curr_fun.fun_frame_base = offset_value
                # exit()


            loc = loc_parser.parse_from_attribute(attr, CU['version'])
            if isinstance(loc, list):
                logger.debug("Parsing location list")
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
    logger.debug("Setting the variable type")
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



def analyze_var(CU, dwarf_info, DIE, attribute_values, loc_parser, curr_fun: FunData):
    """
    Analyzes a DW_TAG_variable DIE within the context of a function (curr_fun).

    Parameters:
    CU: Compilation Unit that contains this DIE.
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
        logger.warning(f"Analyze DW_TAG_variable for the Fun: {curr_fun.name}")
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
            if loc_parser.attribute_has_location(attr, CU['version']):
                loc = loc_parser.parse_from_attribute(attr, CU['version'])
                if isinstance(loc, LocationExpr):
                    # Extract frame base offset from the location expression.
                    offset = describe_DWARF_expr(loc.loc_expr, dwarf_info.structs, CU.cu_offset)
                    offset_match = re.search(offset_pattern, offset)

                    if offset_match:
                        # Compute the variable's offset relative to the function's frame base.
                        offset_value = int(offset_match.group(1))
                        final_offset = curr_fun.fun_frame_base + offset_value
                        logger.debug(f"Register Offset: {curr_fun.reg_to_use}{final_offset}")
                        curr_var.offset = final_offset

                        # Handle struct type variables by resolving their members and offsets.
                        if curr_var.var_type == "DW_TAG_structure_type":
                            if curr_var.member_list is None:
                                # Find the struct in the struct_list and copy its members.
                                for struct in struct_list:
                                    struct: StructData
                                    if curr_var.type_name == struct.name:
                                        curr_var.member_list = struct.member_list.copy()

                            # Adjust member offsets based on the struct's offset in the frame.
                            for member in curr_var.member_list:
                                member: VarData
                                member.offset += curr_var.offset

                    # Handle global variables by extracting their address.
                    global_match = re.search(global_pattern, offset)
                    if global_match:
                        addr_value = global_match.group(1)
                        logger.debug(f"Address: {addr_value}")

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
                                curr_var.member_list = typedef.struct.member_list.copy()
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
    print()
    logger.info("Analyze DW_TAG_base_type")
    for attr in attribute_values:
        if (attr.name == "DW_AT_name"):
            base_name = DIE.attributes["DW_AT_name"].value.decode()
        if (attr.name == "DW_AT_byte_size"):
            base_size = DIE.attributes["DW_AT_byte_size"].value
    type_dict[base_name] =  base_size
    
def analyze_struct(CU, dwarf_info, DIE, attribute_values):
    print()
    logger.info("Analyze DW_TAG_struct_type")
    struct_name = None
    struct_size = None
    line_num = None
    for attr in attribute_values:
        if (attr.name == "DW_AT_name"):
            struct_name = DIE.attributes["DW_AT_name"].value.decode()
        if (attr.name == "DW_AT_byte_size"):
            struct_size = DIE.attributes["DW_AT_byte_size"].value
        if (attr.name == 'DW_AT_decl_line'):
            line_num    = DIE.attributes['DW_AT_decl_line'].value
    logger.debug(f"{struct_name} and {struct_size} and {line_num}")
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
            if loc_parser.attribute_has_location(attr, CU['version']):
                loc = loc_parser.parse_from_attribute(attr, CU['version'])
                if attr.name == "DW_AT_data_member_location" and isinstance(loc, LocationExpr):
                    offset = describe_DWARF_expr(loc.loc_expr, dwarf_info.structs, CU.cu_offset)
                    offset_match = re.search(mem_off_regex, offset)
                    if offset_match:
                        offset_value = int(offset_match.group(1))
                        member_var.offset = offset_value
                        logger.debug(f"Member name: {member_var.name} | Offset value: {offset_value}")

            # Check for DW_AT_type attribute to get the member's type and type name
            if attr.name == "DW_AT_type":
                logger.debug("Parsing member's DWARF type")
                parse_dwarf_type(dwarf_info, DIE, member_var)
                

    if member_var != None:
        return member_var
    

def analyze_attributes(attribute_values, location_lists):
    for attr in attribute_values:
        logger.debug(attr)