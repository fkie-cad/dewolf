import logging
from collections import defaultdict
from typing import DefaultDict, Dict, List, Optional, Set

from decompiler.pipeline.controlflowanalysis.restructuring_commons.abnormal_loops import AbnormalEntryRestructurer, AbnormalExitRestructurer
from decompiler.pipeline.controlflowanalysis.restructuring_commons.graphslice import GraphSlice
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest
from decompiler.structures.graphs.classifiedgraph import EdgeProperty
from decompiler.structures.graphs.interface import GraphInterface
from decompiler.structures.graphs.restructuring_graph.transition_cfg import TransitionBlock, TransitionCFG
from decompiler.util.insertion_ordered_set import InsertionOrderedSet


class CyclicRegionFinder:
    def __init__(self, t_cfg: TransitionCFG, asforest: AbstractSyntaxForest):
        self.t_cfg: TransitionCFG = t_cfg
        self.loop_region: Optional[TransitionCFG] = None
        self.abnormal_entry_restructurer = AbnormalEntryRestructurer(t_cfg, asforest)
        self.abnormal_exit_restructurer = AbnormalExitRestructurer(t_cfg, asforest)

    def find(self, head: TransitionBlock):
        self.loop_region = self._compute_initial_loop_nodes(head)
        graph_changed = False

        if any(edge.property == EdgeProperty.retreating for edge in self.t_cfg.get_in_edges(head)):
            logging.info(f"Restructure Abnormal Entry in loop region with head {head}")
            self.abnormal_entry_restructurer.restructure(self.loop_region)
            graph_changed = True

        loop_successors: List[TransitionBlock] = self._compute_loop_successors()
        if len(loop_successors) > 1:
            logging.info(f"Restructure Abnormal Exit in loop region with head {self.loop_region.root}")
            loop_successors = [self.abnormal_exit_restructurer.restructure(self.loop_region, loop_successors)]
            graph_changed = True

        return self.loop_region, loop_successors, graph_changed

    def _compute_initial_loop_nodes(self, head: TransitionBlock) -> TransitionCFG:
        """
        Computes the cyclic region for the current head node.
            - Compute the set of latching nodes, i.e., the nodes that have the head as successor.
            - Compute the cyclic region
        """
        latching_nodes: List[TransitionBlock] = self._get_latching_nodes(head)
        return GraphSlice.compute_graph_slice_for_sink_nodes(self.t_cfg, head, latching_nodes, back_edges=False)

    def _get_latching_nodes(self, head: TransitionBlock):
        """Return all nodes with outgoing back-edges to the head node."""
        return [edge.source for edge in self.t_cfg.get_in_edges(head) if edge.property != EdgeProperty.non_loop]

    def _compute_loop_successors(self) -> List[TransitionBlock]:
        """Compute the set of exit nodes of the current loop region."""
        initial_successor_nodes = self._get_initial_loop_successor_nodes()
        return self._refine_initial_successor_nodes(initial_successor_nodes)

    def _get_initial_loop_successor_nodes(self) -> InsertionOrderedSet[TransitionBlock]:
        """Return the initial set of possible exit nodes for the current loop region."""
        initial_successor_nodes = InsertionOrderedSet()
        for node in self.loop_region:
            for successor in self.t_cfg.get_successors(node):
                if successor not in self.loop_region:
                    initial_successor_nodes.add(successor)
        return initial_successor_nodes

    def _refine_initial_successor_nodes(self, successor_nodes: InsertionOrderedSet[TransitionBlock]) -> List[TransitionBlock]:
        """
        Refine the set of exit nodes, to avoid unnecessary restructuring.

        :param successor_nodes: The initial set of successors.
        :return: The refined set of successor nodes.
        """
        while len(successor_nodes) > 1:
            new_successor_nodes: InsertionOrderedSet[TransitionBlock] = InsertionOrderedSet()
            for node in list(successor_nodes):
                if node != self.t_cfg.root and self._all_predecessors_in_current_region(node):
                    successor_nodes.remove(node)
                    self._add_node_to_current_region(node)
                    for successor in self.t_cfg.get_successors(node):
                        # One could check only add the real successors to the check list and then recompute afterwards
                        if successor not in self.loop_region:
                            new_successor_nodes.add(successor)
                if len(new_successor_nodes) + len(successor_nodes) <= 1:
                    break
            if not new_successor_nodes:
                break
            successor_nodes.update(new_successor_nodes)
        return [succ_node for succ_node in successor_nodes if succ_node not in self.loop_region]

    def _all_predecessors_in_current_region(self, node: TransitionBlock) -> bool:
        """Check whether all predecessors of node 'node' are contained in the current loop region."""
        return all((predecessor in self.loop_region) for predecessor in self.t_cfg.get_predecessors(node))

    def _add_node_to_current_region(self, node: TransitionBlock) -> None:
        """
        Add the input node to the current loop region. Note that all predecessors of the node are contained in the current loop region.
        """
        self.loop_region.add_node(node)
        self.loop_region.add_edges_from(self.t_cfg.get_in_edges(node))
        self.loop_region.add_edges_from((edge for edge in self.t_cfg.get_out_edges(node) if edge.sink in self.loop_region))


class AcyclicRegionFinder:
    MIN_REGION_SIZE = 3

    def __init__(self, t_cfg: TransitionCFG):
        self.t_cfg = t_cfg

    def find(self, head: TransitionBlock) -> Optional[Set[TransitionBlock]]:
        region = self._find_minimal_subset_for_restructuring(head)
        if self._is_restructurable(region, head):
            return region
        return None

    def _find_minimal_subset_for_restructuring(self, head: TransitionBlock) -> Set[TransitionBlock]:
        """
        Try to find a smaller subset of the dominance region that we can restructure
            - We search for possible exit nodes
            - A possible exit node of a region is a node that would separate the region into two sets.

        :param head: The head of the dominator tree
        :return: A smaller region that we can restructure if possible and the dominance region otherwise
        """
        dominance_region: Set[TransitionBlock] = set(self.t_cfg.dominator_tree.iter_postorder(head))
        if len(dominance_region) <= self.MIN_REGION_SIZE:
            return dominance_region
        region_subgraph: GraphInterface = self.t_cfg.subgraph(tuple(dominance_region))
        possible_exit_nodes = self._get_possible_exit_nodes(region_subgraph)

        for dominator, dominated_nodes in possible_exit_nodes.items():
            if len(smaller_region := dominance_region - dominated_nodes) >= self.MIN_REGION_SIZE and self._has_at_most_one_exit_node(
                smaller_region
            ):
                return smaller_region
        return dominance_region

    def _get_possible_exit_nodes(self, region_subgraph: GraphInterface) -> Dict[TransitionBlock, Set[TransitionBlock]]:
        """
        Computes the set of possible exits nodes for the given region, to find a smaller region for the restructuring.
            - For a possible exit node, the set of dominated vertices should be equal to the set of reachable vertices.
            - If an exit node has only one successor, then we do not consider it as an exit node.
              Considering these exit nodes has no benefit, because the region size only decreases by one and we get problems if this one
              node is a break or continue. Besides, this one node has the same reaching condition as the possible exit node.
        """
        topological_order = list(region_subgraph.iter_topological())
        dominated_by_node: DefaultDict[TransitionBlock, Set[TransitionBlock]] = defaultdict(set)
        reachability_of_node: DefaultDict[TransitionBlock, Set[TransitionBlock]] = defaultdict(set)
        possible_exit_nodes = list()
        for node in reversed(topological_order):
            self.__compute_reachability_and_dominance_for(node, dominated_by_node, reachability_of_node, region_subgraph)
            if (
                dominated_by_node[node]
                and dominated_by_node[node] == reachability_of_node[node]
                and self._has_more_than_one_successor(node)
            ):
                possible_exit_nodes.append(node)
        return {node: dominated_by_node[node] for node in reversed(possible_exit_nodes)}

    def __compute_reachability_and_dominance_for(
        self,
        node: TransitionBlock,
        dominated_by_node: DefaultDict[TransitionBlock, Set[TransitionBlock]],
        reachability_of_node: DefaultDict[TransitionBlock, Set[TransitionBlock]],
        region_subgraph: GraphInterface,
    ):
        """Compute the reachability and dominance for the given node in the given region using the precomputed sets of the successors."""
        for successor in region_subgraph.get_successors(node):
            reachability_of_node[node].update(reachability_of_node[successor])
            reachability_of_node[node].add(successor)
        for child in self.t_cfg.strictly_dominated_by(node):
            dominated_by_node[node].update(dominated_by_node[child])
            dominated_by_node[node].add(child)

    def _has_more_than_one_successor(self, node: TransitionBlock) -> bool:
        """Checks whether the given node has only one successor in the graph."""
        return len(self.t_cfg.get_successors(node)) > 1

    def _is_restructurable(self, dominance_region: Set[TransitionBlock], node: TransitionBlock) -> bool:
        """Checks whether the given acyclic region with given head can be restructured."""
        return self._is_large_enough_region(dominance_region) and (
            self._has_at_most_one_exit_node(dominance_region) or self._has_at_most_one_postdominator(node, dominance_region)
        )

    def _is_large_enough_region(self, region: Set[TransitionBlock]) -> bool:
        """Check whether we can restructure the acyclic region."""
        return (len(self.t_cfg) >= self.MIN_REGION_SIZE and len(region) >= self.MIN_REGION_SIZE) or (
            1 < len(self.t_cfg) < self.MIN_REGION_SIZE and len(region) > 1
        )

    def _has_at_most_one_postdominator(self, header: TransitionBlock, nodes: Set[TransitionBlock]) -> bool:
        """
        This function checks whether at most one vertex post-dominates the region consisting of the sets in nodes with head 'header'.

        :param header: The vertex of which we want to know whether it is post-dominated by at most one vertex.
        :param nodes: The set of nodes that are dominated by the header.
        :return: True, if the header is post-dominated by at most one vertex, and false otherwise.
        """
        region_successors = set(succ for node in nodes for succ in self.t_cfg.get_successors(node)) - nodes
        if len(region_successors) == 0:
            return True
        if len(region_successors) > 1:
            return False
        graph_slice: TransitionCFG = GraphSlice.compute_graph_slice_for_sink_nodes(self.t_cfg, header, list(region_successors))
        diff = set(graph_slice.nodes).symmetric_difference(nodes)
        return diff == region_successors

    def _has_at_most_one_exit_node(self, region_nodes: Set[TransitionBlock]) -> bool:
        """
        Checks whether at most one of the nodes in 'nodes' is an exit node of the region.
            - By exit node we mean nodes that have a successor outside the region.

        :param region_nodes: The set of nodes that we consider for possible exit nodes.
        :return: True, it we have at most one exit node, and False otherwise.
        """
        found_exit = False
        for node in region_nodes:
            if any(successor not in region_nodes for successor in self.t_cfg.get_successors(node)):
                if found_exit:
                    return False
                found_exit = True
        return True
