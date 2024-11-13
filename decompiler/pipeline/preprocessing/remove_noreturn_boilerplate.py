"""Module for removing boilerplate code"""

from typing import Iterator, List

from decompiler.pipeline.preprocessing.util import get_constant_condition, is_noreturn_node
from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.graphs.branches import ConditionalEdge, FalseCase, TrueCase
from decompiler.structures.graphs.rootedgraph import RootedGraph
from decompiler.structures.pseudo.instructions import Branch, Comment
from decompiler.task import DecompilerTask
from networkx import MultiDiGraph, dominance_frontiers


class RemoveNoreturnBoilerplate(PipelineStage):
    """
    RemoveNoreturnBoilerplate finds and removes boilerplate related to non-returning functions.
    Caution: this stage changes code semantic
    """

    name = "remove-noreturn-boilerplate"

    def run(self, task: DecompilerTask):
        if task.options.getboolean(f"{self.name}.remove_noreturn_boilerplate", fallback=False):
            self._cfg = task.graph
            self._aggressive_removal_postdominators_merged_sinks()

    def _get_noreturn_nodes(self) -> Iterator[BasicBlock]:
        """
        Iterate leaf nodes of cfg, yield nodes containing a call to a non-returning funtion.
        """
        leaf_nodes = [x for x in self._cfg.nodes if self._cfg.out_degree(x) == 0]
        for node in leaf_nodes:
            if is_noreturn_node(node):
                yield node

    def _patch_condition_edges(self, edges: List[ConditionalEdge]) -> None:
        """
        This method removes whatever was detected to be boilerplate.

        It works by changing the conditions leading to the boilerplate in a way, that it is never reached.
        """
        for edge in edges:
            match edge:
                case TrueCase():
                    condition = get_constant_condition(False)
                case FalseCase():
                    condition = get_constant_condition(True)
                case _:
                    continue
            instructions = edge.source.instructions
            assert isinstance(instructions[-1], Branch)
            instructions.pop()
            instructions.append(Comment("Removed potential boilerplate code"))
            instructions.append(Branch(condition))

    def _aggressive_removal_postdominators_merged_sinks(self):
        """
        Finds and removes boilerplate code, using the heuristic described below

        Nodes that will always transfer the control flow to a non-returning function are removed,
        except when the node is always executed.
        In other words, we cut the CFG between the post-dominance frontier and the nodes postdominated by non-returning nodes.
        Differen non-returning nodes are considered to be 'the same', by adding a merged sink.

        Implementations detail: We calculate the postdominance frontier via the dominance frontier of the reversed CFG.
        To add virtual nodes to the (read-only) reversed CFG, we create an editable shallow copy of it.
        """
        if len(self._cfg) == 1:
            return  # do not remove the only node
        # determine returning and non-returning leaf nodes
        noreturn_nodes = list(self._get_noreturn_nodes())
        leaf_nodes = [x for x in self._cfg.nodes if self._cfg.out_degree(x) == 0]
        returning_leaf_nodes = [node for node in leaf_nodes if node not in noreturn_nodes]
        # create a virtual merged end node (for post dominance calculation)
        # additionally we create another virtual node so that different non-returning nodes are 'merged'
        min_used_address = min(block.address for block in self._cfg)
        virtual_end_node = BasicBlock(min_used_address - 1)
        virtual_merged_noreturn_node = BasicBlock(min_used_address - 2)
        # reverse CFG and add virtual nodes to it
        reversed_cfg_view: MultiDiGraph = self._cfg._graph.reverse(copy=False)
        reversed_cfg_shallow_copy = MultiDiGraph(reversed_cfg_view)
        reversed_cfg_shallow_copy.add_node(virtual_end_node)
        reversed_cfg_shallow_copy.add_node(virtual_merged_noreturn_node)
        # connect virtual nodes to the leafs
        for noreturn_node in noreturn_nodes:
            reversed_cfg_shallow_copy.add_edge(virtual_merged_noreturn_node, noreturn_node)
        reversed_cfg_shallow_copy.add_edge(virtual_end_node, virtual_merged_noreturn_node)
        for leaf_node in returning_leaf_nodes:
            reversed_cfg_shallow_copy.add_edge(virtual_end_node, leaf_node)
        # calculate postdominance-frontier
        post_dominance_frontier = dominance_frontiers(reversed_cfg_shallow_copy, virtual_end_node)
        # add a root to the graph, so it works with the networkx method
        wrapped_reverse_cfg = RootedGraph(reversed_cfg_shallow_copy, virtual_end_node)
        # find the edges to be removed
        condition_edges = set()
        for post_dominator in post_dominance_frontier[virtual_merged_noreturn_node]:
            for edge_from_post_dominator in list(self._cfg.get_out_edges(post_dominator)):
                if wrapped_reverse_cfg.is_dominating(virtual_merged_noreturn_node, edge_from_post_dominator.sink):
                    condition_edges.add(edge_from_post_dominator)
        # remove the edges leading to boilerplate
        self._patch_condition_edges(list(condition_edges))
