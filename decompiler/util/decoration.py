"""Module handling plotting and pretty printing."""
from __future__ import annotations

import os
import subprocess
import textwrap
from logging import warning
from re import compile
from subprocess import CompletedProcess, Popen, run
from sys import stdout
from tempfile import NamedTemporaryFile
from typing import Dict, Optional, TextIO

import z3
from binaryninja import BranchType, EdgePenStyle, EdgeStyle, FlowGraph, FlowGraphNode, HighlightStandardColor, ThemeColor, show_graph_report
from decompiler.structures.ast.ast_nodes import (
    AbstractSyntaxTreeNode,
    CaseNode,
    ConditionNode,
    DoWhileLoopNode,
    FalseNode,
    ForLoopNode,
    LoopNode,
    SeqNode,
    SwitchNode,
    TrueNode,
    WhileLoopNode,
)
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest
from decompiler.structures.ast.syntaxgraph import AbstractSyntaxInterface
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.graphs.cfg import BasicBlock, BasicBlockEdge, BasicBlockEdgeCondition, ControlFlowGraph
from decompiler.structures.pseudo.operations import Condition
from decompiler.util.to_dot_converter import ToDotConverter
from networkx import DiGraph
from pygments import format, lex
from pygments.formatters.html import HtmlFormatter
from pygments.lexers.c_like import CLexer

try:
    run(["graph-easy", "-v"], capture_output=True)
    GRAPH_EASY_INSTALLED = True
except FileNotFoundError as _:
    GRAPH_EASY_INSTALLED = False

try:
    run(["astyle", "-V"], capture_output=True)
    ASTYLE_INSTALLED = True
except FileNotFoundError as _:
    ASTYLE_INSTALLED = False


class DecoratedGraph:
    def __init__(self, graph: DiGraph = None):
        """Create a new DecoratedGraph or load an old instance."""
        self._graph = graph if graph else DiGraph()

    @property
    def graph(self) -> DiGraph:
        """Return the graph being decorated."""
        return self._graph

    def _write_dot(self, handle: Optional[TextIO] = None):
        """Write the graph to the given handle or NamedTemporaryFile."""
        if not handle:
            handle = NamedTemporaryFile(mode="w+")
        handle.write(ToDotConverter.write(self._graph))
        handle.flush()
        handle.seek(0)
        return handle

    def export_ascii(self) -> str:
        """Export the current graph into an ascii representation."""
        if not GRAPH_EASY_INSTALLED:
            warning(f"Invoking graph-easy although it seems like it is not installed on the system.")
        with self._write_dot() as handle:
            result: CompletedProcess = run(["graph-easy", "--as=ascii", handle.name], capture_output=True)
        return result.stdout.decode("utf-8")

    def export_dot(self, path: str):
        """Export the graph into a dotfile at the given location."""
        with open(path, "w") as outfile:
            self._write_dot(outfile)

    def export_plot(self, path: str, type="png"):
        """
        Generate a png picture of the current graph at the given path.

        path -- Path to the plot to be created.
        type -- a string describing the output type (commonly pdf, png)
        """
        with Popen(
            ["dot", f"-T{type}", f"-o{path}"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        ) as proc:
            dot_source: str = ToDotConverter.write(self.graph)
            stdout, stderr = proc.communicate(input=dot_source)

            if proc.returncode:
                raise ValueError(f"Could not plot graph! ({stderr})")


class DecoratedCFG(DecoratedGraph):
    """Class handling graphs decorated for plotting and printing."""

    NODE_DECORATION = {"shape": "box", "color": "blue"}

    EDGE_DECORATION = {
        BasicBlockEdgeCondition.unconditional: {"color": "blue"},
        BasicBlockEdgeCondition.true: {"color": "darkgreen"},
        BasicBlockEdgeCondition.false: {"color": "darkred"},
        BasicBlockEdgeCondition.indirect: {"style": "dotted"},
        BasicBlockEdgeCondition.switch: {"color": "orange"},
    }

    EDGE_TYPE_MAP = {
        BasicBlockEdgeCondition.unconditional: BranchType.UnconditionalBranch,
        BasicBlockEdgeCondition.false: BranchType.FalseBranch,
        BasicBlockEdgeCondition.true: BranchType.TrueBranch,
        BasicBlockEdgeCondition.switch: BranchType.IndirectBranch,
        BasicBlockEdgeCondition.indirect: BranchType.IndirectBranch,
    }

    @classmethod
    def from_cfg(cls, cfg: ControlFlowGraph) -> DecoratedCFG:
        """Generate a DecoratedGraph by parsing the given cfg."""
        graph = cls()
        for basic_block in cfg:
            graph.decorate_node(basic_block)
        for edge in cfg.edges:
            graph.decorate_edge(edge)
        return graph

    @classmethod
    def show_flowgraph(cls, cfg: ControlFlowGraph, name: str):
        """Draws our control flow graph in binary ninja. For debugging algorithms' intermediate results"""
        graph = cls.from_cfg(cfg)
        show_graph_report(name, graph.export_flowgraph())

    @classmethod
    def get_ascii(cls, cfg: ControlFlowGraph, name: str = "") -> str:
        return "\n".join([name, cls.from_cfg(cfg).export_ascii()])

    @classmethod
    def print_ascii(cls, cfg: ControlFlowGraph, name: str = "") -> None:
        print(cls.get_ascii(cfg, name))

    def decorate_node(self, node: BasicBlock):
        """Decorate the given node with dotviz attributes."""
        self._graph.add_node(node.name, **self.NODE_DECORATION, label=self._format_label(node))

    def decorate_edge(self, edge: BasicBlockEdge):
        """Decorate the given edge with dotviz attributes based on its type."""
        self._graph.add_edge(edge.source.name, edge.sink.name, **self.EDGE_DECORATION[edge.condition_type], type=edge.condition_type)

    @staticmethod
    def _format_label(node: BasicBlock) -> str:
        """Generate a label for the given BasicBlock."""
        if node.instructions is None:
            instructions_left_aligned = " "
        else:
            instructions_left_aligned = "\n".join(map(str, node.instructions))
        return f"{node.name}.\n{instructions_left_aligned}"

    def export_flowgraph(self) -> FlowGraph:
        """Generate a binaryninja FlowGraph with the contents of the decorated graph."""
        graph = FlowGraph()
        nodes = {node: FlowGraphNode(graph) for node in self._graph}
        for reference, node in nodes.items():
            graph.append(node)
            node.lines = self._graph.nodes[reference]["label"]
        for source, sink, data in self._graph.edges(data=True):
            nodes[source].add_outgoing_edge(self.EDGE_TYPE_MAP[data["type"]], nodes[sink])
        return graph


class DecoratedAST(DecoratedGraph):
    """Class representing an decorated AST for plotting purposes."""

    GENERAL_NODE_DECORATION = {"style": "filled", "fillcolor": "#fff2ae"}

    NODE_DECORATION = {
        SeqNode: {"fillcolor": "#e6f5c9", "highlight": HighlightStandardColor.GreenHighlightColor},
        ConditionNode: {"fillcolor": "#e6f5c9", "highlight": HighlightStandardColor.RedHighlightColor},
        SwitchNode: {"fillcolor": "#fdcdac", "highlight": HighlightStandardColor.YellowHighlightColor},
        CaseNode: {"fillcolor": "#e6f5c9", "highlight": HighlightStandardColor.OrangeHighlightColor},
        WhileLoopNode: {"fillcolor": "#b3e2cd", "highlight": HighlightStandardColor.BlueHighlightColor},
        DoWhileLoopNode: {"fillcolor": "#b3e2cd", "highlight": HighlightStandardColor.BlueHighlightColor},
        ForLoopNode: {"fillcolor": "#b3e2cd", "highlight": HighlightStandardColor.BlueHighlightColor},
    }

    EDGE_DECORATION = {
        "true_branch": {"branch_type": BranchType.TrueBranch, "label": "T", "color": "#228B22"},
        "false_branch": {"branch_type": BranchType.FalseBranch, "label": "F", "color": "#c2261f"},
        SwitchNode: {
            "branch_type": BranchType.UserDefinedBranch,
            "edge_style": EdgeStyle(EdgePenStyle.DashLine, 1, ThemeColor.YellowStandardHighlightColor),
        },
        CaseNode: {
            "branch_type": BranchType.UserDefinedBranch,
            "edge_style": EdgeStyle(EdgePenStyle.SolidLine, 1, ThemeColor.YellowStandardHighlightColor),
        },
    }

    def __init__(self, graph=None):
        super().__init__(graph)
        self._node_to_id = {}
        self.condition_map: Dict[z3.BoolRef, Condition] = {}

    @classmethod
    def from_ast(cls, ast: AbstractSyntaxInterface, with_reaching_condition: bool = False) -> DecoratedAST:
        """Generate a decorated graph based on the given AbstractSyntaxTree or AbstractSyntaxForest."""
        graph = cls()
        graph.condition_map = dict()
        if isinstance(ast, AbstractSyntaxForest):
            graph.condition_map = ast.condition_handler.get_condition_map()
        elif isinstance(ast, AbstractSyntaxTree):
            graph.condition_map = ast.condition_map
        node_id = 0
        for node in ast.topological_order():
            if isinstance(node, (TrueNode, FalseNode)):
                continue
            graph.decorate_node(node, node_id, with_reaching_condition)
            node_id += 1
        graph._add_edges()
        return graph

    def decorate_node(self, node: AbstractSyntaxTreeNode, node_id: int, with_reaching_condition: bool = False):
        """Decorate the given node while adding it to the DecoratedAST."""
        attributes = self.GENERAL_NODE_DECORATION.copy()
        attributes.update(self.NODE_DECORATION.get(type(node), {}))

        label = f"{node_id}. {node.__class__.__name__}"
        if with_reaching_condition:
            label += f"\n {node.reaching_condition.rich_string_representation(self.condition_map)}"

        if hasattr(node, "condition"):
            resolved_condition = node.condition.rich_string_representation(self.condition_map)
            if isinstance(node, ConditionNode):
                label += self._format_node_content("if (" + resolved_condition + ")")
            elif isinstance(node, ForLoopNode):
                label += self._format_node_content(
                    f"{node.loop_type.value} ({node.declaration}; {resolved_condition}; {node.modification})"
                )
            elif isinstance(node, LoopNode):
                label += self._format_node_content(f"{node.loop_type.value} ({resolved_condition})")
            else:
                label += self._format_node_content(f"{node}")
        else:
            label += self._format_node_content(f"{node}")

        self._graph.add_node(node_id, **attributes, label=label)
        self._node_to_id[node] = node_id

    def _add_edges(self):
        """Add an edge for each outgoing relation of the given node."""
        for node, node_id in self._node_to_id.items():
            if isinstance(node, ConditionNode):
                if node.true_branch_child:
                    self._graph.add_edge(node_id, self._node_to_id[node.true_branch_child], **self.EDGE_DECORATION["true_branch"])
                if node.false_branch_child:
                    self._graph.add_edge(node_id, self._node_to_id[node.false_branch_child], **self.EDGE_DECORATION["false_branch"])
            else:
                for child in node.children:
                    self._graph.add_edge(node_id, self._node_to_id[child], **self.EDGE_DECORATION.get(type(node), {}))

    @classmethod
    def get_ascii(cls, ast: AbstractSyntaxTree, name: str = "") -> str:
        """Return ascii representation of AST"""
        return "\n".join([name, cls.from_ast(ast).export_ascii()])

    @classmethod
    def print_ascii(cls, ast: AbstractSyntaxTree, name: str = "") -> None:
        """Print ascii representation of AST"""
        print(cls.get_ascii(ast, name))

    @classmethod
    def show_flowgraph(cls, ast: AbstractSyntaxTree, name: str):
        """Show AST in a BinaryNinja tab"""
        graph = cls.from_ast(ast)
        show_graph_report(name, graph._generate_flowgraph())

    def _generate_flowgraph(self) -> FlowGraph:
        """Generate a binaryninja FlowGraph with the contents of the decorated graph."""
        graph = FlowGraph()
        nodes = {node: FlowGraphNode(graph) for node in self.graph}

        for node_id, node in nodes.items():
            graph.append(node)
            node.lines = self._graph.nodes[node_id].get("label", "No Label")
            node.highlight = self._graph.nodes[node_id].get("highlight", HighlightStandardColor.NoHighlightColor)

        for source, sink, data in self._graph.edges(data=True):
            nodes[source].add_outgoing_edge(data.get("branch_type", BranchType.UnconditionalBranch), nodes[sink], data.get("edge_style"))

        return graph

    @staticmethod
    def _format_node_content(label: str, max_width: int = 60):
        """Keep content of decorated nodes <= max_width for readability purposes."""
        splitted_lines = "\n"
        for label in label.splitlines():
            splitted_lines += "\n" + textwrap.fill(label, max_width)
        return splitted_lines


class DecoratedCode:
    """Class representing C code ready for pretty printing."""

    class TempFile:
        """Context manager to write content to NamedTemporaryFile and release for windows, returns file name"""

        def __init__(self, content: str):
            self.tmpf = NamedTemporaryFile(mode="w", delete=False)
            self.tmpf.write(content)
            self.name = self.tmpf.name
            self.tmpf.flush()
            self.tmpf.close()

        def __enter__(self) -> str:
            return self.name

        def __exit__(self, exc_type, exc_val, exc_tb):
            os.unlink(self.name)

    def __init__(self, code: str, style="paraiso-dark"):
        """Generate an object handling code decoration."""
        self._text = code
        self._style = style

    @property
    def code(self) -> str:
        """Return the code decorated in its current form."""
        return self._text

    @classmethod
    def generate_html_from_code(cls, code, style: str) -> str:
        """Shorthand helper function to generate html from code."""
        decoration = cls(code, style=style)
        decoration.reformat()
        return decoration.export_html()

    @classmethod
    def print_code(cls, code: str, output_stream: TextIO = None, color: bool = True, style="paraiso-dark"):
        """Classmethod for quick pretty printing to the commandline."""
        decoration = cls(code, style=style)
        decoration.reformat()
        if not output_stream:
            output_stream = stdout
        if color:
            output_stream.write(decoration.export_ascii())
        else:
            output_stream.write(decoration.code)
        output_stream.write("\n")

    @classmethod
    def formatted_plain(cls, code) -> str:
        """Classmethod for indentation of plain code without colors"""
        decoration = cls(code)
        decoration.reformat()
        return decoration.code

    def reformat(self):
        """Call astyle on command line to reformat the code."""
        if not ASTYLE_INSTALLED:
            warning(f"Invoking astyle although it seems like it is not installed on the system.")
        with self.TempFile(self._text) as filename:
            run(["astyle", "-z2", "-n", filename], check=True, capture_output=True)
            with open(filename, "r") as output:
                self._text = output.read()

    def export_ascii(self) -> str:
        with self.TempFile(self._text) as filename:
            result: CompletedProcess = run(["pygmentize", "-l", "cpp", f"-O style={self._style}", filename], capture_output=True)
        return result.stdout.decode("ascii")

    def export_html(self) -> str:
        """Export an html representation of the current code."""
        tokens = lex(self._text, CLexer())
        html = format(tokens, HtmlFormatter(full=True, style=self._style))
        return self._filter_css_comments(html)

    @staticmethod
    def _filter_css_comments(html):
        """Strip the CSS block comments generated by pygments > 2.4.0, since it messes up binaryninja."""
        find_comments = compile(r"/\*[^*]*\*/")
        return find_comments.sub("", html)
