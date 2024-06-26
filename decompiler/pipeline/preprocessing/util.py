"""Helper functions for modules in the preprocessing pipeline."""

from collections import defaultdict
from typing import DefaultDict, Dict, Set, Tuple

from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.maps import DefMap, UseMap
from decompiler.structures.pseudo.expressions import Variable


def init_maps(cfg: ControlFlowGraph) -> tuple[DefMap, UseMap]:
    """
    Initialize the UseMap and DefMap of a given control flow graph.

    :param cfg: The control flow graphs whose use- and def-maps we want to compute.
    :return: A tuple(def_map, use_map) where def_map is the DefMap of the given control flow graph and use_map is the UseMap of the given
    control flow graph.
    """
    def_map = DefMap()
    use_map = UseMap()
    for location in cfg.instruction_locations:
        def_map.add(location)
        use_map.add(location)
    return def_map, use_map


def _init_basicblocks_of_definition(cfg: ControlFlowGraph) -> Dict[Variable, BasicBlock]:
    """
    We compute for each variable the basic blocks where it is defined. This must be unique, since we are in SSA-Form

    :param cfg: Control Flow Graph
    :return: Dictionary that has as key a defined variable and as value the cfg node where the variable is defined
    """
    basicblock_of_definition = dict()
    for node in cfg.nodes:
        for instruction in node.instructions:
            for variable in instruction.definitions:
                if variable in basicblock_of_definition.keys():
                    raise ValueError(
                        f"Variable {variable} is defined twice. Once in basic block {basicblock_of_definition[variable]} and once in basic "
                        f"block {node}"
                    )
                basicblock_of_definition[variable] = node
    return basicblock_of_definition


def _init_basicblocks_usages_variable(cfg: ControlFlowGraph) -> DefaultDict[Variable, Set[BasicBlock]]:
    """
    We compute for each variable the basic blocks where it is used.

    :param cfg: Control Flow Graph
    :return: Dictionary that has as key a used variable and as value the set of cfg nodes where the variable is used
    """
    basicblocks_usages_variable: DefaultDict[Variable, Set[BasicBlock]] = defaultdict(set)
    for node in cfg.nodes:
        for instruction in node.instructions:
            for variable in instruction.requirements:
                basicblocks_usages_variable[variable].add(node)
    return basicblocks_usages_variable
