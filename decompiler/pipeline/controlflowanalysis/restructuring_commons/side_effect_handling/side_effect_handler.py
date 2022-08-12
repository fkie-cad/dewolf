from __future__ import annotations

from typing import Optional

from decompiler.pipeline.commons.reaching_definitions import ReachingDefinitions
from decompiler.pipeline.controlflowanalysis.restructuring_commons.side_effect_handling.data_graph import DataGraph
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.task import DecompilerTask


class SideEffectHandler:
    def __init__(self, ast: AbstractSyntaxTree, cfg: ControlFlowGraph, data_graph: DataGraph):
        self._ast: AbstractSyntaxTree = ast
        self._cfg: ControlFlowGraph = cfg
        self._data_graph: DataGraph = data_graph

    @classmethod
    def resolve(cls, task: DecompilerTask) -> None:
        # return
        data_graph = DataGraph.generate_from_ast(task.syntax_tree)
        side_effect_handler = cls(task.syntax_tree, task.graph, data_graph)
        # DecoratedAST.from_ast(task.syntax_tree).export_plot("/home/eva/Projects/dewolf-decompiler/AST/ast.png")
        from decompiler.util.decoration import DecoratedAST, DecoratedCFG

        # DecoratedCFG.from_cfg(data_graph).export_plot("/home/eva/Projects/dewolf-decompiler/AST/cfg.png")
        side_effect_handler.apply()

    def apply(self):
        reaching_definitions = ReachingDefinitions(self._data_graph)
        all_defined_ssa_variables = set(var.ssa_name for node in self._data_graph.nodes for var in node.definitions)
        # TODO: What about variables defined via phi-functions
        # TODO: How about added variables without SSA-values?
        # for logic_node in self._data_graph.get_logic_nodes():
        #     definitions: Dict[Variable, List[Instruction]] = dict()
        #     for instruction in reaching_definitions.reach_in_block(logic_node):
        #         for definition in instruction.definitions:
        #             definitions[definition] = definitions.get(definition, list()) + [instruction]
        #     for symbol in logic_node.logic_condition.get_symbols():
        #         pseudo_condition = self._ast.condition_map[symbol]
        #         for used_variable in pseudo_condition.requirements:
        #             if used_variable not in all_defined_ssa_variables:
        #                 continue
        #             for def_instruction in definitions[used_variable]:
        #                 definition = [def_var for def_var in def_instruction.definitions if def_var == used_variable][0]
        #                 if used_variable.ssa_name != definition.ssa_name:
        #                     raise "We have to handle side effects!"
