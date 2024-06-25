"""Module handling conversion to dot-format."""

from networkx import DiGraph

HEADER = "digraph  {"
FOOTER = "}"


class ToDotConverter:
    """Class in charge of writing a networkx DiGraph into dot-format"""

    ATTRIBUTES = {"color", "fillcolor", "label", "shape", "style", "dir"}

    def __init__(self, graph: DiGraph):
        self._graph = graph

    @classmethod
    def write(cls, graph: DiGraph) -> str:
        """Write dot-format of given graph into handle."""
        converter = cls(graph)
        return converter._create_dot()

    def _create_dot(self) -> str:
        """Create dot-file content."""
        content = HEADER + "\n"
        for node, data in self._graph.nodes(data=True):
            content += f"{node} [{self._get_attributes(data)}]; \n"
        for source, sink, data in self._graph.edges(data=True):
            content += f"{source} -> {sink} [{self._get_attributes(data)}]; \n"
        content += FOOTER
        return content

    def _get_attributes(self, data):
        """Return string for node attributes."""
        return ", ".join(key + "=" + self._process(value) for key, value in data.items() if key in self.ATTRIBUTES)

    def _process(self, value: str):
        """Ensure that attribute string fulfills dot-notation."""
        value = value.replace('"', '\\"')
        value = value.replace("\n", "\\n")
        return f'"{value}"'
