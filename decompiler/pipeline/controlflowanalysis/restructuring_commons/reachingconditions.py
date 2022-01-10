from typing import Dict, List

from decompiler.structures.graphs.restructuring_graph.transition_cfg import TransitionBlock, TransitionCFG
from decompiler.structures.logic.logic_condition import LogicCondition


def compute_reaching_conditions(
    graph_slice: TransitionCFG, src: TransitionBlock, cfg: TransitionCFG
) -> Dict[TransitionBlock, LogicCondition]:
    """
    Compute the reaching conditions from TransitionBlock src to all other vertices of the graph slice, which is acyclic.

    :param graph_slice: The graph slice whose reaching condition we want to compute.
    :param src: The head of the graph_slice.
    :param cfg: The complete control flow graph of which the graph slice is a subgraph.
    :return: A dictionary where we assign to each TransitionBlock of graph_slice its reaching condition from src using z3-conditions.
    """
    reaching_conditions: Dict[TransitionBlock, LogicCondition] = {src: graph_slice.condition_handler.get_true_value()}
    sink_nodes = _sink_nodes(graph_slice)
    if len(sink_nodes) == 1 and _sink_postdominates_source_in_cfg(graph_slice, sink_nodes[0], src, cfg):
        reaching_conditions[sink_nodes[0]] = graph_slice.condition_handler.get_true_value()
        _compute_reaching_condition_of_unique_predecessors(sink_nodes[0], graph_slice, reaching_conditions)
    for node in graph_slice.iter_topological():
        if node in reaching_conditions:
            continue
        reaching_conditions[node] = _compute_reaching_condition_of(node, graph_slice, reaching_conditions)
    return reaching_conditions


def _compute_reaching_condition_of_unique_predecessors(
    sink_node: TransitionBlock, graph_slice: TransitionCFG, reaching_conditions: Dict[TransitionBlock, LogicCondition]
) -> None:
    """
    If the sink node has only one predecessor, then this node has also reaching condition true. So, as long as the predecessor is unique,
    we set its reaching condition to true.

    :param sink_node: The unique sink node of the graph slice.
    :param graph_slice: The graph slice we consider.
    :param reaching_conditions: The dictionary where we save the reaching conditions
    """
    current_node = sink_node
    while (predecessors := list(graph_slice.get_predecessors(current_node))) and len(predecessors) == 1:
        reaching_conditions[predecessors[0]] = graph_slice.condition_handler.get_true_value()
        current_node = predecessors[0]


def _compute_reaching_condition_of(
    node: TransitionBlock, graph_slice: TransitionCFG, reaching_conditions: Dict[TransitionBlock, LogicCondition]
) -> LogicCondition:
    """
    Compute the reaching condition of the input node, under the condition that the reaching condition of all predecessor.
    nodes is already computed and saved in the reaching condition dictionary.

    :param node: The node whose reaching condition we want to compute.
    :param graph_slice: The graph slice where we compute the reaching conditions.
    :param reaching_conditions: The dictionary that maps to each TransitionBlock its reaching condition, if it is already computed.
    :return: The reaching condition of the input node.
    """
    resulting_reaching_condition = graph_slice.condition_handler.get_false_value()
    for predecessor in sorted(graph_slice.get_predecessors(node), key=lambda pre: len(reaching_conditions[pre].operands)):
        tag = graph_slice.get_edge(predecessor, node).tag
        reaching_condition = reaching_conditions[predecessor] & tag
        resulting_reaching_condition |= reaching_condition
    return resulting_reaching_condition


def _sink_nodes(graph_slice: TransitionCFG) -> List[TransitionBlock]:
    """
    Compute for a given control flow graph the set of out-degree zero vertices.

    :param graph_slice: The control flow graph whose out-degree zero node we want to compute
    :return: A list of all out-degree zero nodes.
    """
    return [node for node in graph_slice.nodes if graph_slice.out_degree(node) == 0]


def _sink_postdominates_source_in_cfg(graph_slice: TransitionCFG, sink: TransitionBlock, src: TransitionBlock, cfg: TransitionCFG) -> bool:
    """
    Check whether the sink node 'sink' post-dominates the source node 'src' which is the head of the input graph 'graph_slice'
    in the control flow graph where the graph slice is contained.
        - We know that the graph has exactly one sink node.
        - To check that this unique sink node also post-dominates the source in the original cfg, we have to check that no TransitionBlock,
          except may be the sink node, has neighbours outside the region.

    :param graph_slice: The graph slice we consider.
    :param sink: The sink whose post-dominance we want to check.
    :param src: The source node.
    :param cfg: he complete control flow graph of which the graph slice is a subgraph.
    :return: True, if the sink post-dominates the source and false, otherwise.
    """
    if sink == src:
        return False
    for node in graph_slice.nodes:
        if node == sink:
            continue
        for succ in cfg.get_successors(node):
            if succ not in graph_slice.nodes:
                return False
    return True
