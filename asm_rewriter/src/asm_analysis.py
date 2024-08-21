import logging
import sys
import fileinput
import inspect
import argparse
import shutil
import pprint 
import os
import re

# Get the same logger instance. Use __name__ to get a logger with a hierarchical name or a specific string to get the exact same logger.
logger = logging.getLogger('custom_logger')

class PatchingInst:
    def __init__(self, opcode, prefix, operand_1, operand_2):
        # This is based on AT&T syntax, where it is opcode, src, dest ->
        self.opcode = opcode
        self.prefix = prefix
        self.src = operand_1
        self.dest = operand_2
        self.patch = None
    
    def inst_print(self):
        logger.debug(
            f"Instruction Details:\n"
            f"  - Opcode      : {self.opcode}\n"
            f"  - Prefix      : {self.prefix}\n"
            f"  - Source      : {self.src}\n"
            f"  - Destination : {self.dest}\n"
            f"  - Patching    : {self.patch}\n"
            # f"  - Pointer     : {getattr(self, 'ptr_op', 'N/A')}\n" # Need to be added later
        )
    