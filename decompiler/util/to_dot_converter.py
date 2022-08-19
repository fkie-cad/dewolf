from typing import TextIO

from networkx import DiGraph

HEADER = "strict digraph  {"
FOOTER = "}"

"""
########## CFG ##########

node: NAME=node.name, label="string with content --> careful with `"` ", shape=box, color=blue
edge: source.name, sink.name, type=not_needed?, color=orange/blue/red 
"""


"""
########## AST ##########

node: NAME=id, label="string with content --> careful with `"` ", style=filled, fillcolor=#llll, 
        highlight=HighlightStandardColor.GreenHighlightColor, 
edge: source.name, sink.name, branch_type=not_needed?, color="#....", label=T, 
"""


class ToDotConverter:

    ATTRIBUTES = {"color", "fillcolor", "label", "shape", "style"}

    def __init__(self, graph: DiGraph):
        self._graph = graph

    @classmethod
    def write(cls, graph: DiGraph, handle: TextIO):
        converter = cls(graph)
        handle.write(converter._create_dot())

    def _create_dot(self):
        content = HEADER + "\n"
        for node, data in self._graph.nodes(data=True):
            content += f"{node} [{self._get_attributes(data)}]; \n"
        for source, sink, data in self._graph.edges(data=True):
            content += f"{source} -> {sink} [{self._get_attributes(data)}]; \n"
        content += FOOTER
        return content

    def _get_attributes(self, data):
        attributes = ""
        return ', '.join(key + '=' + self._process(value) for key, value in data.items() if key in self.ATTRIBUTES)

    def _process(self, value: str):
        """make sure that attribute value fulfills dot-notation"""
        # while '"' in value:
        value = value.replace('"', '\\"')
        # while "\n" in value:
        value = value.replace("\n", "\\n")
        return f'"{value}"'
