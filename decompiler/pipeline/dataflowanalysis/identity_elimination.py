"""Module implementing a pipeline stage eliminating congruent variables."""

from __future__ import annotations

from collections import defaultdict, namedtuple
from dataclasses import dataclass
from logging import error, info
from typing import DefaultDict, Dict, Iterator, List, Optional, Set, Tuple, Union

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.cfg import BasicBlock
from decompiler.structures.pseudo.expressions import Constant, GlobalVariable, UnknownExpression, Variable
from decompiler.structures.pseudo.instructions import Assignment, BaseAssignment, Instruction, Phi, Relation
from decompiler.task import DecompilerTask
from networkx import DiGraph, node_disjoint_paths, weakly_connected_components
from networkx.exception import NetworkXNoPath


@dataclass
class DefinitionLocation:
    block: BasicBlock
    definition: BaseAssignment


class _IdentityDataflow:
    """
    Class implementing helper methods for IdentityGraph to extract dataflow information from a given graph.
    Implemented for usage in IdentityElimination and VariableReplacer only.
    """

    def __init__(self):
        """Generate a new IdentityDataflow object."""
        self._use_map: DefaultDict[Variable, List[Instruction]] = defaultdict(list)
        self._def_map: Dict[Variable, DefinitionLocation] = dict()

    def parse_dataflow(self, instruction: Instruction, basic_block: BasicBlock):
        """Parse the dataflow information of the given instruction."""
        for required_variable in instruction.requirements:
            self._use_map[required_variable].append(instruction)
        for defined_value in instruction.definitions:
            assert isinstance(instruction, BaseAssignment), f"The Instruction {instruction} must be an Assignment if it has a Definition."
            self._def_map[defined_value] = DefinitionLocation(basic_block, instruction)

    def get_usages(self, variable: Variable) -> Iterator[Instruction]:
        """Yield all parsed usages for the given Variable."""
        yield from self._use_map[variable]

    def get_definition(self, variable: Variable) -> Optional[DefinitionLocation]:
        """Get the DefinitionLocation of the given variable."""
        return self._def_map.get(variable, None)


class _IdentityGraph(DiGraph):
    """
    Graph representing direct (assignments) and indirect (phi) identities.
    Implemented for usage in IdentityElimination only.
    """

    def __init__(self, function_parameters: List[Variable]):
        """
        Initialization for the Identity Graph.

        - The attribute function_parameters is the set of names of function-arguments
        - The attribute no_identity_of tells us which variables we can not identify with each other because they are used to define
          each other but not as a pure identity. For example, if we have the assignment a = b + 1, a and b can not be identities.
          But, the assignment a = b does not tell us that they can not be identities, most likely they are identities.
        """
        super().__init__()
        self.function_parameters: Set[str] = {arg.name for arg in function_parameters}
        self.no_identity_of: Dict[Variable, Set[Variable]] = dict()

    def add_assignment(self, assignment: Assignment, basic_block: BasicBlock) -> None:
        """
        Add the given instruction to the identity graph.
            - First check that the assignments defines exactly one variable.
            - Then compute the set of required variables and add the according edges to the identity graph.
        """
        if not isinstance(defined_value := assignment.destination, Variable) or isinstance(defined_value, GlobalVariable):
            return
        required_values = self._get_variables_utilized_for_direct_assignment(assignment)
        self.add_node(defined_value, definition=assignment, block=basic_block, is_phi=isinstance(assignment, Phi))
        for required_value in required_values:
            if isinstance(required_value, UnknownExpression):
                continue
            self.add_edge(defined_value, required_value)

    def initialize_no_identity_of(self, assignment: Assignment):
        """Initialize the attribute no_identity_of for the given assignment, resp. the variable defined in this assignment."""
        if isinstance(assignment.value, Variable) or isinstance(assignment, Phi):
            no_identity_of_def = set()
        else:
            no_identity_of_def = set(assignment.requirements)
        for definition in assignment.definitions:
            self.no_identity_of[definition] = no_identity_of_def

    def prune_non_identity_phi_functions(self, consider_undefined_variables: bool = False):
        """
        Prune any phi functions from the graph those operands are not identities.
        - We remove all edges between a variable that is defined via a phi-function and its requirements, if there are at least two
          disjoint paths between the defined variable and a degree zero variable.
        - To compute the number of paths, we temporarily introduce a new leaf node 'leaf', and add an edge between each leaf and the global
          leaf. This allows us to use the netwokx function `node_disjoint_paths`. We do this for each weak connected component separately.

        - The boolean value `consider_undefined_variables` tells us whether we consider undefined variables as definitions, if there is a
        conflict between two nodes of a weakly connected component.
        """
        for weakly_cc in list(weakly_connected_components(self)):
            phi_nodes, out_degree_zero_nodes = self._parse_weakly_connected_component(weakly_cc, consider_undefined_variables)
            if len(out_degree_zero_nodes) <= 1:
                continue
            for leaf in out_degree_zero_nodes:
                self.add_edge(leaf, "leaf")
            for phi in phi_nodes:
                try:
                    if self.out_degree(phi) <= 1 or len(list(node_disjoint_paths(self, phi, "leaf", cutoff=2))) <= 1:
                        continue
                except NetworkXNoPath:
                    continue
                for node in list(self.successors(phi)):
                    self.remove_edge(phi, node)
                self.add_edge(phi, "leaf")
            self.remove_node("leaf")

    def _parse_weakly_connected_component(
        self, connected_component: Set[Variable], consider_undefined_variables: bool = False
    ) -> Tuple[List[Variable], List[Union[Variable, Constant]]]:
        """
        Returns two list, one that contains all variables that are defined via a Phi-function and one that returns all leaves, i.e., nodes
        with out-degree zero.
        """
        has_conflict = consider_undefined_variables and self._has_conflict(connected_component)
        phi_nodes: List[Variable] = list()
        out_degree_zero_nodes: List[Union[Variable, Constant]] = list()
        for node in connected_component:
            if self.nodes[node].get("is_phi", False):
                phi_nodes.append(node)
            if self.out_degree(node) == 0 and (has_conflict or self._is_defining_value(node)):
                out_degree_zero_nodes.append(node)
        return phi_nodes, out_degree_zero_nodes

    def _has_conflict(self, connected_component: Set[Variable]) -> bool:
        """Checks whether there are two variables in the connected component that can not get the same name."""
        for variable in [var for var in connected_component if var in self.no_identity_of]:
            if self.no_identity_of[variable] & connected_component:
                return True
        return False

    def _is_defining_value(self, expression: Union[Variable, Constant]) -> bool:
        """Checks whether the given expression is a constant or a variable that has a definition or is a function argument."""
        return not isinstance(expression, UnknownExpression) and (
            isinstance(expression, Constant) or expression in self.no_identity_of or expression.name in self.function_parameters
        )

    def yield_identities(self) -> Iterator[Set[Variable]]:
        """
        Yield all identity groups connected by direct identities.
        -> First we try to prune any phi functions from the graph those operands are not identities, when assuming that undefined variables
           do not count as definitions.
           Running this first, already removes some conflicts and improves the output.
        -> Second, we consider undefined-variables as definitions if this would lead to conflicts, i.e.,
           instructions of the form `a = a + 3`, where the used `a` is undefined.
        """
        self.prune_non_identity_phi_functions(False)
        self.prune_non_identity_phi_functions(True)
        for identity_candidates in weakly_connected_components(self):
            if len(identity_candidates) > 1:
                yield identity_candidates

    def _get_variables_utilized_for_direct_assignment(self, assignment: Assignment) -> Set[Union[Constant, Variable]]:
        """
        Get the variables assigned by the given assignment, that can be identities of the defined variable.
        """
        defined_variable: Variable = assignment.destination
        required_variables = set()
        if isinstance(assignment, Phi):
            required_variables = self._required_variables_for_phi_function(assignment, defined_variable)
        elif isinstance(required_variable := assignment.value, Variable) and self._is_required_variable_for_assignment(
            required_variable, defined_variable
        ):
            required_variables = {required_variable}
        return required_variables

    def _required_variables_for_phi_function(self, phi_function: Phi, defined_variable: Variable) -> Set[Union[Constant, Variable]]:
        if defined_variable.is_aliased is True and self._not_all_variables_have_same_name(phi_function):
            return set()
        if defined_variable.is_aliased is False and self._is_aliased_variable_in(phi_function.value):
            return set()
        return set(phi_function.value)

    @staticmethod
    def _is_required_variable_for_assignment(required_variable: Variable, defined_variable: Variable) -> bool:
        return (
            defined_variable.is_aliased is False and required_variable.is_aliased is False
        ) or required_variable.name == defined_variable.name

    @staticmethod
    def _not_all_variables_have_same_name(assignment: Assignment) -> bool:
        defined_variable = assignment.destination
        required_values = assignment.value
        return any(
            not isinstance(required_value, UnknownExpression)
            and (isinstance(required_value, Constant) or required_value.name != defined_variable.name)
            for required_value in required_values
        )

    @staticmethod
    def _is_aliased_variable_in(required_values: List[Union[Constant, Variable]]) -> bool:
        return not all(
            not isinstance(required_variable, UnknownExpression)
            and (isinstance(required_variable, Constant) or required_variable.is_aliased is False)
            for required_variable in required_values
        )

    def find_replacement_variable_of_group(self, identity_group: Set[Variable]) -> Optional[Variable]:
        """Returns the variable of the identity group that is initially defined."""
        replacement_variable = None
        optional_variable = None
        for variable in identity_group:
            if self.out_degree(variable) > 0:
                continue
            if not self._is_defining_value(variable):
                optional_variable = variable
                continue
            if replacement_variable is None:
                replacement_variable = variable
            else:
                info(
                    f"At least two variables in the identity group {identity_group} have out degree zero, namely "
                    f"{replacement_variable} and {variable}, i.e., these set of vertices is not an identity group"
                )
                return None
        if replacement_variable:
            return replacement_variable
        elif optional_variable:
            return optional_variable
        else:
            info(
                f"No variable in the identity group {identity_group} has out degree zero, "
                f"thus this set of Variables has no initial definition."
            )
            return None


class _VariableReplacer:
    """
    Class in charge of replacing identity groups found during IdentityElimination with a replacement variable.
    Implemented for utilization by IdentityElimination only.
    """

    def __init__(self, dataflow: _IdentityDataflow):
        """Create a new VariableReplacer instance using the given dataflow information."""
        self._dataflow = dataflow

    def replace_variables(self, replacees: Set[Variable], replacement: Variable):
        """
        Replace the given list of variables with the given replacement variable.

        replacees -- The List of variables to be replaced
        replacement -- The Variable utilized for replacement
        """
        info(f"[{self.__class__.__name__}] merging identity group {', '.join([str(x) for x in replacees])} into {replacement}")
        self._substitute_usages(replacees, replacement)
        self._handle_definitions(replacees, replacement)

    def _handle_definitions(self, replacees: Set[Variable], replacement: Variable):
        """
        Handle the definitions of the variables to be replaced.
        - The only remaining Definition should be the one defining the variable 'replacement' which is contained in replacees.
        - All other definitions must result in an tautology, so we can remove them.

        replacees -- The List of variables to be replaced
        replacement -- The Variable utilized for replacement
        """
        for defined_variable in replacees:
            if defined_variable == replacement:
                continue
            if (definition_location := self._dataflow.get_definition(defined_variable)) is None:
                continue
            if not self._is_tautology_after_replacement(definition_location.definition, replacement):
                message = f"There are at least two definitions in the identity group {definition_location.definition}, {replacement}."
                error(message)
                raise ValueError(message)
            definition_location.block.remove_instruction(definition_location.definition)

    def _substitute_usages(self, replacees: Set[Variable], replacement: Variable):
        """Substitute all usages of the given variables by an usage of the replacement Variable."""
        for replacee, replacee_usage in self._iterate_variable_usages(replacees):
            replacee_usage.substitute(replacee, replacement)

    def _iterate_variable_usages(self, replacees: Set[Variable]) -> Iterator[Tuple[Variable, Instruction]]:
        """Iterate all combinations of replacees and instructions they are utilized in."""
        for utilized_variable in replacees:
            yield from [
                (utilized_variable, dependant_instruction) for dependant_instruction in self._dataflow.get_usages(utilized_variable)
            ]

    @staticmethod
    def _is_tautology_after_replacement(definition: Assignment, replacement: Variable) -> bool:
        """Check if the given assignment would result in a tautology after the substitution of both definition and value."""
        if isinstance(definition, Phi) and set(definition.value) == {replacement}:
            return True
        if definition.value == replacement:
            return True
        return False


class IdentityElimination(PipelineStage):
    """Analysis stage eliminating identities between variables by merging them."""

    name = "identity-elimination"

    def run(self, task: DecompilerTask):
        """Find all congruent variables in the given graph and merge them."""
        identity_graph, dataflow = self._parse_cfg(task)
        variable_replacer = _VariableReplacer(dataflow)
        for identity_group in identity_graph.yield_identities():
            if replacement_variable := identity_graph.find_replacement_variable_of_group(identity_group):
                variable_replacer.replace_variables(identity_group, replacement_variable)

    @staticmethod
    def _parse_cfg(task: DecompilerTask) -> Tuple[_IdentityGraph, _IdentityDataflow]:
        """Set up the IdentityGraph and The IdentityDataflow objects in a single iteration of all instructions."""
        dataflow = _IdentityDataflow()
        identity_graph = _IdentityGraph(task.function_parameters)
        for basic_block in task.graph:
            for instruction in basic_block.instructions:
                dataflow.parse_dataflow(instruction, basic_block)
                if isinstance(instruction, Assignment):
                    identity_graph.initialize_no_identity_of(instruction)
                    identity_graph.add_assignment(instruction, basic_block)
                elif isinstance(instruction, Relation):
                    identity_graph.no_identity_of[instruction.destination] = {instruction.value}
        return identity_graph, dataflow
