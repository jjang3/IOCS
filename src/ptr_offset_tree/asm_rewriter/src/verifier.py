import fileinput
import time
import os, sys
import logging
import re
import csv

# Get the same logger instance. Use __name__ to get a logger with a hierarchical name or a specific string to get the exact same logger.
logger = logging.getLogger('main')

# Add the parent directory to sys.path
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

import main

import insts
import bin_analysis

def is_instruction(line):
    """
    Check if a line is an assembly instruction.
    This function assumes that an assembly instruction starts with
    an alphanumeric character (excluding labels and directives) and
    not a comment or empty line.
    """
    # Trim leading and trailing whitespaces
    stripped_line = line.strip()

    # Check for empty line, comment, label, or directive
    if (not stripped_line or
        stripped_line.startswith(';') or
        ':' in stripped_line or
        stripped_line.startswith('.')):
        return False

    # Assuming the line is an instruction if it doesn't fall into the above categories
    return True

def parse_assembly_instructions(filename):
    """
    Parses the given assembly file and prints out only the assembly instructions.
    """
    instructions = []

    with open(filename, 'r') as file:
        for line in file:
            if is_instruction(line):
                instructions.append(line.strip())

    return instructions


def static_verifier(file_path, flag, analysis_list, target_fun_var_info):
    verify_count = 0
    check = True
    failed_insts = list()
    if flag == "PRE":
        logger.info("Pre-condition verification")
        # Example usage
        instructions = parse_assembly_instructions(file_path)
        for instruction in instructions:
            # Regex pattern to match opcodes
            # pattern = r"^\s*(\b\w+\b)"
            pattern = r"^\s*(\S+)\s+([^,]+)\s*(?:,\s*(.*))?$"
            no_op_pattern = r"^\s*(\S+)\s*$"
            print(instruction)
            # opcodes = re.findall(pattern, instruction, re.MULTILINE)
            inst_regex = re.match(pattern, instruction)
            no_op_inst_regex = re.match(no_op_pattern, instruction)
            # for opcode in opcodes:
            if inst_regex:
                # Capitalize the opcode
                opcode = inst_regex.group(1).upper()
                # Check if the capitalized opcode exists in the Instruction enum
                # and print the result
                opcode_check = insts.IntelInstruction.has_value(opcode)
                if opcode_check:
                    logger.critical("Checked")
                    None
                else:
                    # This is critical so we exit, since it means there is an unfamilliar opcode detected
                    logger.error("Verify failed %s", opcode)
                    exit()
                    check = False
                
                operand1 = inst_regex.group(2)  # Always present for this pattern
                print(operand1)
                reg_check = insts.ReservedRegs.has_value(operand1)
                if reg_check == True:
                    # Register r9,r10,r11 is used, but it's not critical, we just take note of it
                    logger.warning("Verify failed %s", instruction)
                    # exit()
                    check = False
                    failed_insts.append(instruction)
                else:
                    logger.critical("OP1 Checked")
                # Check if the optional second operand exists
                operand2 = inst_regex.group(3) if inst_regex.group(3) is not None else None
                print(operand2)
                if operand2 is not None:
                    reg_check = insts.ReservedRegs.has_value(operand1)
                    if reg_check is True:
                        # Register r9,r10,r11 is used, but it's not critical, we just take note of it
                        logger.warning("Verify failed %s", instruction)
                        # exit()
                        failed_insts.append(instruction)
                        check = False
                    else:
                        logger.critical("OP2 Checked")
            elif no_op_inst_regex:
                opcode = no_op_inst_regex.group(1).upper()
                opcode_check = insts.IntelInstruction.has_value(opcode)
                if opcode_check:
                    logger.critical("Checked")
                    None
                else:
                    logger.error("Verify failed %s", opcode)
                    failed_insts.append(instruction)
                    check = False
        return check, failed_insts
    
    elif flag == "POST":
        logger.info("Verify compiled binary %s", file_path)
        new_bn_fun_var_info = bin_analysis.process_new_binary(file_path, analysis_list, target_fun_var_info)
        # bin_analysis.process_new_binary(file_path, analysis_list)
        # main.custom_pprint(new_bn_fun_var_info)
        # for fun in new_bn_fun_var_info:
        #     for var in new_bn_fun_var_info[fun]:
        #         var: bin_analysis.BnVarData
        #         # logger.debug(var.patch_inst.inst_print())
        #         logger.debug(var.patch_inst.inst_type)
        #         if var.patch_inst.inst_type == "rdgsbase":
        #             logger.error("Found")
            # logger.debug(bn_var.patch_inst)