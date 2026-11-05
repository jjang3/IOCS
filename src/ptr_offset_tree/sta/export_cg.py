import cgitb
import sys, getopt
import logging
import shutil
import pprint
import inspect
import os
import webbrowser
import time

from binaryninja import *
from binaryninja.binaryview import BinaryViewType
from binaryninja.architecture import Architecture, ArchitectureHook
from binaryninja.interaction import get_save_filename_input, show_message_box, TextLineField, ChoiceField, SaveFileNameField, get_form_input
from binaryninja.settings import Settings
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon, MessageBoxButtonResult, InstructionTextTokenType, BranchType, DisassemblyOption, FunctionGraphType, ThemeColor
from binaryninja.function import DisassemblySettings
from binaryninja.plugin import PluginCommand
from termcolor import colored

class CustomFormatter(logging.Formatter):

    # FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s | %(levelname)s"
    # logging.basicConfig(level=os.environ.get("LOGLEVEL", "DEBUG"), format=FORMAT)
    blue = "\x1b[33;34m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_green = "\x1b[42;1m"
    purp = "\x1b[38;5;13m"
    reset = "\x1b[0m"
    # format = "%(funcName)5s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"
    format = "[Line:%(lineno)4s -%(funcName)18s()] %(levelname)7s    %(message)s "

    FORMATS = {
        logging.DEBUG: yellow + format + reset,
        logging.INFO: blue + format + reset,
        logging.WARNING: purp + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_green + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)
    
# Debug options here
debug_level = logging.DEBUG
ch = logging.StreamHandler()
ch.setLevel(debug_level) 
ch.setFormatter(CustomFormatter())

log = logging.getLogger(__name__)
log.setLevel(debug_level)

# create console handler with a higher log level
log_disable = False
log.addHandler(ch)
log.disabled = log_disable

colors = {
  'green': [162, 217, 175], 'red': [222, 143, 151], 'blue': [128, 198, 233], 'cyan': [142, 230, 237],
  'lightCyan': [176, 221, 228], 'orange': [237, 189, 129], 'yellow': [237, 223, 179], 'magenta': [218, 196, 209],
  'none': [74, 74, 74], 'disabled': [144, 144, 144]
}

escape_table = {"'": "&#39;", ">": "&#62;", "<": "&#60;", '"': "&#34;", ' ': "&#160;"}


def rgbStr(tokenType):
    r = 1
    g = 1
    b = 1
    # print(f"rgb({r}, {g}, {b})")
    return f"rgb({r}, {g}, {b})"

def escape(toescape):
	# handle extended unicode
	toescape = toescape.encode('ascii', 'xmlcharrefreplace')
	# still escape the basics
	return ''.join(escape_table.get(chr(i), chr(i)) for i in toescape)
def instruction_data_flow(self, function, address):
    # TODO:  Extract data flow information
    length = self.bv.get_instruction_length(address)
    func_bytes = self.bv.read(address, length)
    hex = func_bytes.hex()
    padded = ' '.join([hex[i:i + 2] for i in range(0, len(hex), 2)])
    return f'Opcode: {padded}'


def export_graph(self, callgraph):
    heightconst = 15
    ratio = 0.48
    widthconst = heightconst * ratio
    output = f'''<html>
    <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="{callgraph.width * widthconst + 20}" height="{callgraph.height * heightconst + 20}">
        <style type="text/css">
            @import url(https://fonts.googleapis.com/css?family=Source+Code+Pro);
            body {{
                /* These colors are only for the bottom section, can tweak later */
                background-color: rgb(42, 42, 42);
                color: rgb(220, 220, 220);
                font-family: "Source Code Pro", "Lucida Console", "Consolas", monospace;
            }}
                a, a:visited  {{
                color: rgb(200, 200, 200);
                font-weight: bold;
            }}
            svg {{
                background-color: {rgbStr('GraphBackgroundDarkColor')};
                display: block;
                margin: 0 auto;
            }}
            .basicblock {{
                stroke: {rgbStr('GraphNodeOutlineColor')};
                fill: {rgbStr('GraphNodeDarkColor')};
            }}
            .edge {{
                fill: none;
                stroke-width: 1px;
            }}
            .back_edge {{
                fill: none;
                stroke-width: 2px;
            }}
            .UnconditionalBranch, .IndirectBranch {{
                stroke: {rgbStr('UnconditionalBranchColor')};
                color: {rgbStr('UnconditionalBranchColor')};
            }}
            .FalseBranch {{
                stroke: {rgbStr('FalseBranchColor')};
                color: {rgbStr('FalseBranchColor')};
            }}
            .TrueBranch {{
                stroke: {rgbStr('TrueBranchColor')};
                color: {rgbStr('TrueBranchColor')};
            }}
            .arrow {{
                stroke-width: 1;
                fill: currentColor;
            }}
            text {{
                                font-family: "Source Code Pro", "Lucida Console", "Consolas", monospace;
                font-size: 9pt;
                fill: {rgbStr('TextToken')};
            }}
            .RegisterToken {{
                fill: {rgbStr('RegisterColor')};
            }}
            .CodeRelativeAddressToken, .PossibleAddressToken, .IntegerToken, .FloatingPointToken, .ArrayIndexToken {{
                fill: {rgbStr('NumberColor')};
            }}
            .CodeSymbolToken {{
                fill: {rgbStr('CodeSymbolColor')};
            }}
            .DataSymbolToken {{
                fill: {rgbStr('DataSymbolColor')};
            }}
            .LocalVariableToken, .ArgumentNameToken {{
                fill: {rgbStr('StackVariableColor')};
            }}
            .IndirectImportToken, .ImportToken, .ExternalSymbolToken {{
                fill: {rgbStr('ImportColor')};
            }}
            .AnnotationToken {{
                fill: {rgbStr('AnnotationColor')};
            }}
            .CommentToken {{
                fill: {rgbStr('CommentColor')};
            }}
            .AddressDisplayToken {{
                fill: {rgbStr('AddressColor')};
            }}
            .UnknownMemoryToken, .OpcodeToken {{
                fill: {rgbStr('OpcodeColor')};
            }}
            .StringToken, .CharacterConstantToken {{
                fill: {rgbStr('StringColor')};
            }}
            .TypeNameToken {{
                fill: {rgbStr('TypeNameColor')};
            }}
            .FieldNameToken, .StructOffsetToken {{
                fill: {rgbStr('FieldNameColor')};
            }}
            .KeywordToken, .EnumerationMemberToken {{
                fill: {rgbStr('KeywordColor')};
            }}
            .NamespaceToken {{
                fill: {rgbStr('NameSpaceColor')};
            }}
            .NamespaceSeparatorToken {{
                fill: {rgbStr('NameSpaceSeparatorColor')};
            }}
            .GotoLabelToken {{
                fill: {rgbStr('GotoLabelColor')};
            }}
            .OperationToken {{
                fill: {rgbStr('OperationColor')};
            }}
            .BaseStructureNameToken, .BaseStructureSeparatorToken {{
                fill: {rgbStr('BaseStructureNameColor')};
            }}
            .TextToken, .InstructionToken, .BeginMemoryOperandToken, .EndMemoryOperandToken {{
                fill: {rgbStr('TextToken')};
            }}
        </style>
        <defs>
            <marker id="arrow-TrueBranch" class="arrow TrueBranch" viewBox="0 0 10 10" refX="10" refY="5" markerUnits="strokeWidth" markerWidth="8" markerHeight="6" orient="auto">
                <path d="M 0 0 L 10 5 L 0 10 z" />
            </marker>
            <marker id="arrow-FalseBranch" class="arrow FalseBranch" viewBox="0 0 10 10" refX="10" refY="5" markerUnits="strokeWidth" markerWidth="8" markerHeight="6" orient="auto">
                <path d="M 0 0 L 10 5 L 0 10 z" />
            </marker>
            <marker id="arrow-UnconditionalBranch" class="arrow UnconditionalBranch" viewBox="0 0 10 10" refX="10" refY="5" markerUnits="strokeWidth" markerWidth="8" markerHeight="6" orient="auto">
                <path d="M 0 0 L 10 5 L 0 10 z" />
            </marker>
            <marker id="arrow-IndirectBranch" class="arrow IndirectBranch" viewBox="0 0 10 10" refX="10" refY="5" markerUnits="strokeWidth" markerWidth="8" markerHeight="6" orient="auto">
                <path d="M 0 0 L 10 5 L 0 10 z" />
            </marker>
        </defs>
        <g id="functiongraph0" class="functiongraph">
            <title>Function callgraph 0</title>
    '''
    edges = ''
    for i, block in enumerate(callgraph):
        x = ((block.x) * widthconst)
        y = ((block.y) * heightconst)
        width = ((block.width) * widthconst)
        height = ((block.height) * heightconst)

        # Render block
        output += f'		<g id="basicblock{i}">\n'
        output += f'			<title>Basic Block {i}</title>\n'
        rgb = colors['none']
        try:
            bb = block.basic_block
            if hasattr(bb.highlight, 'color'):
                color_code = bb.highlight.color
                color_str = bb.highlight._standard_color_to_str(color_code)
                if color_str in colors:
                    rgb = colors[color_str]
            else:
                rgb = [bb.highlight.red, bb.highlight.green, bb.highlight.blue]
        except:
            pass
        output += f'			<rect class="basicblock" x="{x}" y="{y}" height="{height + 12}" width="{width + 16}" fill="rgb({rgb[0]},{rgb[1]},{rgb[2]})"/>\n'

        # Render instructions, unfortunately tspans don't allow copying/pasting more
        # than one line at a time, need SVG 1.2 textarea tags for that it looks like

        output += f'			<text x="{x}" y="{y + (i+1) * heightconst}">\n'
        for i, line in enumerate(block.lines):
            output += f'				<tspan id="instr-{hex(line.address)[:-1]}" x="{x + 6}" y="{y + 6 + (i + 0.7) * heightconst}">'
            hover = self.instruction_data_flow(function, line.address)
            output += f'<title>{hover}</title>'
            for token in line.tokens:
                # TODO: add hover for hex, function, and reg tokens
                output += f'<tspan class="{InstructionTextTokenType(token.type).name}">{escape(token.text)}</tspan>'
            output += '</tspan>\n'
        output += '			</text>\n'
        output += '		</g>\n'

        # Edges are rendered in a seperate chunk so they have priority over the
        # basic blocks or else they'd render below them

        for edge in block.outgoing_edges:
            points = ""
            x, y = edge.points[0]
            points += str(x * widthconst) + "," + str(y * heightconst + 12) + " "
            for x, y in edge.points[1:-1]:
                points += str(x * widthconst) + "," + str(y * heightconst) + " "
            x, y = edge.points[-1]
            points += str(x * widthconst) + "," + str(y * heightconst + 0) + " "
            edgeType=BranchType(edge.type).name
            if edge.back_edge:
                edges += f'		<polyline class="back_edge {edgeType}" points="{points}" marker-end="url(#arrow-{edgeType})"/>\n'
            else:
                edges += f'		<polyline class="edge {edgeType}" points="{points}" marker-end="url(#arrow-{edgeType})"/>\n'
    output += ' ' + edges + '\n'
    output += '	</g>\n'
    output += '</svg>\n'

    timestring=time.strftime("%c")
    # output += f'<p>This CFG generated by <a href="https://binary.ninja/">Binary Ninja</a> from {origname} on {timestring} showing {offset} as {form}.</p>'
    output += '</html>'
    return output

def get_or_set_call_node(self, callgraph, function_nodes, function):
    # create a new node if one doesn't exist already
    if function not in function_nodes:
        node = FlowGraphNode(callgraph)

        function_nodes[function] = node

        if function.symbol.type == SymbolType.ImportedFunctionSymbol:
            token_type = InstructionTextTokenType.ImportToken
        else:
            token_type = InstructionTextTokenType.CodeSymbolToken

        # Set the node's text to be the name of the function
        node.lines = [
            DisassemblyTextLine(
                [
                    InstructionTextToken(
                        token_type,
                        function.name,
                        function.start
                    )
                ]
            )
        ]

        callgraph.append(node)
    else:
        node = function_nodes[function]

    return node

def collect_calls(self, view, rootFun):
    log.info("collect_calls")
    #  dict containing callee -> set(callers)    
    calls = {}
    if (self.rootFun == None):
        funs = view.functions
        log.debug(funs)
        rootlines = ['ROOT']
    else:
        funs = map(lambda x: x.function, view.get_code_refs(self.rootFun.start))
        rootlines = [self.rootFun.name]
        
    for fun in self.bv.functions:
        for ref in self.bv.get_code_refs(fun.start):
            caller = ref.function
            calls[fun] = calls.get(fun, set())
            call_il = caller.get_low_level_il_at(ref.address)
            if isinstance(call_il, Call) and isinstance(call_il.dest, Constant):
                calls[fun].add(caller)
    
    callgraph = FlowGraph()
    callgraph.function = view.get_function_at(view.entry_point)
    root_node = FlowGraphNode(callgraph)
    root_node.lines = rootlines
    callgraph.append(root_node)
    function_nodes = {}
    
    for callee in view.functions:
    # create a new node if one doesn't exist already
        callee_node = self.get_or_set_call_node(callgraph, function_nodes, callee)

        # create nodes for the callers, and add edges
        callers = calls.get(callee, set())

        if not callers:
            root_node.add_outgoing_edge(
                BranchType.FalseBranch, callee_node
            )
        for caller in callers:
            caller_node = self.get_or_set_call_node(callgraph, function_nodes, caller)

            # Add the edge between the caller and the callee
            if ctypes.addressof(callee_node.handle.contents) not in [
                ctypes.addressof(edge.target.handle.contents)
                for edge in caller_node.outgoing_edges]:
                    caller_node.add_outgoing_edge(
                        BranchType.TrueBranch,
                        callee_node
                    )
    callgraph.layout_and_wait()
    return callgraph