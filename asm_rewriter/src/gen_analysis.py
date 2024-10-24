import sys, getopt
import logging, os
import re
import pprint
import copy
import argparse
import shutil

from binaryninja import *

class BinAnalysis:
    def fun_analysis(self):
        print("")
        fun_set = set()
        for func in self.bv.functions:
            func: Function
            if func.symbol.type != SymbolType.ImportedFunctionSymbol:
                # Exclude compiler-generated or auto-generated functions
                if not func.name.startswith("_") and \
                   not func.name.startswith("sub_") and \
                   ".isra." not in func.name and \
                   ".constprop." not in func.name and \
                   "tm_clones" not in func.name:  # Filter out tm_clones-related functions
                    print(func.name)  # Only print filtered internal functions
                    fun_set.add(func.name)
        return fun_set

    def __init__(self, bv):
        self.bv = bv
        self.fun: Optional[Function] = None
        self.fun_begin = None
        self.fun_end = None

def gen_analysis_file(input_binary_path, output):
    fp = open(output, "w")
    print(input_binary_path, output)

    # Load and analyze the binary with options that prioritize speed
    bv = BinaryViewType.get_view_of_file_with_options(input_binary_path, options={
        "arch.x86.disassembly.syntax": "AT&T"
    })
    # Create a BinAnalysis object and run the analysis
    bn = BinAnalysis(bv)
    output_set = bn.fun_analysis()
    idx = 0
    for fun in output_set:
        if idx == len(output_set)-1:
            fp.write(f"{fun}")
        else:
            fp.write(f"{fun},")
        idx += 1
    fp.close()

def main():
    # Get the size of the terminal
    columns, rows = shutil.get_terminal_size(fallback=(80, 20))

    # Create a string that fills the terminal width with spaces
    # Subtract 1 to accommodate the newline character at the end of the string
    empty_space = ' ' * (columns - 1)

    # Create the parser
    parser = argparse.ArgumentParser(description='Process some inputs.')

    # Add arguments
    parser.add_argument('--binary', type=str, help='Path to a binary file')
    parser.add_argument('--output', type=str, help='Path to an output file')

    # Parse arguments
    args = parser.parse_args()

    # Determine base_name if binary is provided
    if args.binary is not None:
        print(f"Processing {args.binary}")
        gen_analysis_file(args.binary, args.output)

# Call main function
if __name__ == '__main__':
    main()