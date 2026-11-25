"""Module for the Out of SSA translation of Boissinot et al."""

from collections import defaultdict
from contextlib import contextmanager
from copy import deepcopy
from itertools import combinations, product
from typing import DefaultDict, Dict, Iterator, List, Optional, Set

import networkx as nx
from decompiler.pipeline.commons.livenessanalysis import LivenessAnalysis
from decompiler.pipeline.ssa.parallel_spaces import ParallelSpaces
from decompiler.pipeline.ssa.value_interferencegraph import ValueInterferenceGraph, can_be_in_same_class
from decompiler.pipeline.ssa.variable_renaming import VariableRenamer
from decompiler.structures.graphs.branches import UnconditionalEdge
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo.expressions import Constant, GlobalVariable, Variable
from decompiler.structures.pseudo.instructions import Assignment, Phi, Relation
from decompiler.task import DecompilerTask

LIFTED_CONSTANT_NAME = "__lifted_constant__"


class BoissinotVariableRenamer(VariableRenamer):
    """Class that renames the variables of the CFG according to the given variable classes."""

    def __init__(self, task: DecompilerTask, interference_graph: InterferenceGraph, variable_classes: List[List[Variable]]):
        """
        Initialize the renamer and compute the renaming map.

        :param task: The task whose CFG is renamed.
        :param interference_graph: The interference graph of the variables.
        :param variable_classes: The classes of variables, all variables of one class get the same name.
        """
        super().__init__(task, interference_graph)
        self.variable_classes = variable_classes
        self.function_arg_for_variable: Dict[Variable, str] = {v: k for k, v in self.variable_for_function_arg.items()}

        self._assigned_names: List[str] = []
        self._name_count = 0
        self._generate_renaming_map()

    def _generate_renaming_map(self) -> None:
        """Choose a name for every variable class and store the replacement of each variable in the renaming map."""
        self._split_classes_with_different_types()

        # parameter classes first, so they keep the parameter name
        for variable_class in sorted(self.variable_classes, key=lambda c: not any(v in self.function_arg_for_variable for v in c)):
            variable_class = sorted(variable_class, key=lambda variable: f"{variable.name}{variable.ssa_label}")  # Determinism
            global_variables = [variable for variable in variable_class if isinstance(variable, GlobalVariable)]

            if len(global_variables) == 0:
                self._rename_class_without_globals(variable_class)
            elif len(global_variables) == len(variable_class):
                self._rename_class_of_globals(variable_class)
            else:
                raise Exception("Found a class containing globals and ordinary variables")

    def _split_classes_with_different_types(self) -> None:
        """
        Split classes with variables of different types into separate classes by their type.

        This shouldn't occur, but in rare cases it sadly does. The new classes are appended at the end.
        """
        unsplit_classes = []
        split_classes = []
        for variable_class in self.variable_classes:
            types = set(variable.type for variable in variable_class)
            if len(types) <= 1:
                unsplit_classes.append(variable_class)
            else:
                for variable_type in types:
                    split_classes.append([variable for variable in variable_class if variable.type == variable_type])
        self.variable_classes = unsplit_classes + split_classes

    def _rename_class_without_globals(self, variable_class: List[Variable]) -> None:
        """Rename the variables of a class that has no global variables."""
        function_arguments = [variable for variable in variable_class if variable in self.function_arg_for_variable]
        if len(function_arguments) > 1:  # We only want to have at most one function argument in each class
            raise Exception("Found more than one argument in a PCK")
        if len(function_arguments) == 1:
            new_name = self._get_unused_name(self.function_arg_for_variable[function_arguments[0]])
        elif len(variable_class) >= 1:
            new_name = self._get_unused_name(self._choose_name_of_ordinary_class(variable_class))
        else:
            return

        for variable in variable_class:
            self.renaming_map[variable] = Variable(new_name, variable.type, None, variable.is_aliased, variable, variable.tags)

    def _choose_name_of_ordinary_class(self, variable_class: List[Variable]) -> str:
        """
        Returns the name of the first variable in the class, that is not a lifted constant.

        We do not want our high level variable to be named "__lifted_constant__" because this is a special name.
        If all variables are lifted constants, the name is "var".
        """
        return next((variable.name for variable in variable_class if LIFTED_CONSTANT_NAME not in variable.name), "var")

    def _rename_class_of_globals(self, variable_class: List[Variable]) -> None:
        """Rename the variables of a class that only has global variables."""
        new_name = self._get_unused_name(variable_class[0].name)
        for variable in variable_class:
            self.renaming_map[variable] = GlobalVariable(
                new_name, variable.type, variable.initial_value, None, variable.is_aliased, variable, variable.is_constant, variable.tags
            )

    def _get_unused_name(self, name: str) -> str:
        """Returns the given name, or a new name derived from it if it is already used for another class, and marks the name as used."""
        if name in self._assigned_names:
            name = f"{name}__{self._name_count}"
            self._name_count += 1
        self._assigned_names.append(name)
        return name


class Boissinot:
    """
    Out-of-SSA translation of Boissinot et al., "Revisiting Out-of-SSA Translation for Correctness, Code Quality, and
    Efficiency" (CGO 2009):
        1. Insert parallel copies for every Phi function (conventional SSA).
        2. Build the value-based interference graph: two variables interfere if their live ranges intersect and they
           have different values (rule "Value" of the paper).
        3. Coalesce the copies by decreasing weight, then share copies of the same variable whose live ranges
           intersect (copy sharing), and rename the variables per class.
        4. Sequentialize the parallel copies.

    Differences to the paper:
        - The weight of a copy is the loop nesting depth of its block, a static estimate of the block frequency (the
          paper uses profile information and reports similar results for static estimates).
        - Two classes are only merged if they do not mix global and other variables, all their global variables have
          the same name, all variables have the same type, they do not mix aliased and non-aliased variables, and all
          aliased variables have the same name (see can_be_in_same_class). These constraints are needed so
          that a variable of the decompiled code has one type and one memory location; they only prevent merges.
        - Variables connected by a Relation always get the same name.
        - The class of a function parameter gets the parameter name.
        - The paper's linear-time intersection check (equal_anc) is not implemented; an explicit interference graph is
          used instead (only a runtime difference).
    """

    def __init__(self, task: DecompilerTask, phi_functions: DefaultDict[BasicBlock, List[Phi]]):
        """The dict phi_functions maps to each basic block the list of Phi-functions it contains."""
        self._task: DecompilerTask = task
        self._cfg: ControlFlowGraph = self._task.cfg  # type: ignore
        self._phi_functions_of: DefaultDict[BasicBlock, List[Phi]] = phi_functions

        self._label_count: DefaultDict[str, int] = defaultdict(int)
        self._parallel_spaces = ParallelSpaces(phi_functions)

        self._cfg_copy: ControlFlowGraph
        self._interference_graph: ValueInterferenceGraph
        self._coloring_graph: InterferenceGraph
        self._variable_classes: List[List[Variable]]

    def perform(self) -> None:
        """Translate the CFG of the task out of SSA form."""
        self._to_cssa()  # Step 1
        self._build_interference_graph()  # Step 2
        self._coalesce_and_rename()  # Step 3

        self._remove_nop_instr(self._cfg)

        self._parallel_spaces.remove_nop_copies()
        self._parallel_spaces.sequentialize()  # Step 4
        self._parallel_spaces.insert_into_cfg(self._cfg)  # Step 4
        self._remove_phis(self._cfg)

    # Step 1: conventional SSA

    def _to_cssa(self) -> None:
        """phi functions are lifted out of the CFG and replaced with copy instructions. If necessary, new basic blocks are being inserted."""
        self._compute_label_count()

        for basic_block in self._phi_functions_of:
            for predecessor in self._get_predecessors(basic_block):  # type: ignore
                copy_block = self._get_block_for_copies(basic_block, predecessor)
                self._lift_phi_arguments(basic_block, predecessor, copy_block)
            self._lift_phi_definitions(basic_block)

    def _compute_label_count(self) -> None:
        """Computes the maximum SSA label for each variable in the CFG and stores it in self._label_count.
        We need this to generate new SSA labels for variables when we lift phi functions out of SSA form."""
        for variable in self._cfg.get_variables():
            if not variable.ssa_label:
                continue
            current_count = self._label_count.get(variable.name)
            if not current_count or current_count < variable.ssa_label:
                self._label_count[variable.name] = variable.ssa_label

    def _get_predecessors(self, basic_block: BasicBlock) -> Iterator[Optional[BasicBlock]]:
        """Yields the predecessors of the basic block, followed by None if the Phi-functions have an argument from the function entry."""
        yield from list(self._cfg.get_predecessors(basic_block))
        if self._phi_functions_of[basic_block] and None in self._phi_functions_of[basic_block][0].origin_block:
            yield None

    def _get_block_for_copies(self, basic_block: BasicBlock, predecessor: Optional[BasicBlock]) -> BasicBlock:
        """
        Returns the block that receives the copies for the Phi-arguments coming from the given predecessor.

        This is the predecessor itself if it only has an unconditional edge to the basic block. Otherwise, a new block is inserted
        on the edge. A predecessor of None stands for the function entry, the new block becomes the root.
        """
        edge = self._cfg.get_edge(predecessor, basic_block)  # type: ignore
        if predecessor is not None and isinstance(edge, UnconditionalEdge):
            return predecessor

        new_block = self._insert_basic_block_before(basic_block)
        if predecessor:
            self._cfg.substitute_edge(edge, edge.copy(sink=new_block))  # type: ignore
        else:
            self._cfg.root = new_block
        return new_block

    def _insert_basic_block_before(self, basic_block: BasicBlock) -> BasicBlock:
        """creates a new basic block and inserts it before the given basic block in the CFG. Returns the new basic block."""
        new_basic_block = self._cfg.create_block()
        self._cfg.add_edge(UnconditionalEdge(new_basic_block, basic_block))
        return new_basic_block

    def _lift_phi_arguments(self, basic_block: BasicBlock, predecessor: Optional[BasicBlock], copy_block: BasicBlock) -> None:
        """Replace the arguments of the Phi-functions of the basic block that come from the predecessor by new variables, which are
        assigned at the end of the copy block."""
        for phi_function in self._phi_functions_of[basic_block]:
            argument = phi_function.origin_block[predecessor]
            if not isinstance(argument, (Variable, Constant)):
                raise RuntimeError("Unexpected Phi requirement!")

            copy_variable = self._create_copy_variable(phi_function.destination)
            phi_function.substitute_for_block(predecessor, copy_variable)
            if copy_block is not predecessor:
                phi_function.origin_block[copy_block] = phi_function.origin_block.pop(predecessor)  # type: ignore

            self._parallel_spaces.add_end_of_block_assign(copy_block.address, Assignment(copy_variable, argument))

    def _lift_phi_definitions(self, basic_block: BasicBlock) -> None:
        """Replace the definitions of the Phi-functions of the basic block by new variables, which are copied to the old definitions
        directly after the Phi-functions."""
        for phi_function in self._phi_functions_of[basic_block]:
            definition = phi_function.definitions[0]
            copy_variable = self._create_phi_destination_variable(definition)
            phi_function.rename_destination(definition, copy_variable)

            self._parallel_spaces.add_after_phi_assign(basic_block.address, Assignment(definition, copy_variable))

    def _create_copy_variable(self, destination: Variable | GlobalVariable) -> Variable | GlobalVariable:
        """Returns a new variable with a new SSA label, to be used as the destination of a copy.
        Name, type, is_aliased, and tags are copied from the given destination, which is the definition of a Phi-function.
        Global variables stay globals, so they don't get mixed up with normal variables."""
        self._label_count[destination.name] += 1
        if isinstance(destination, GlobalVariable):
            return GlobalVariable(
                destination.name,
                destination.type,
                destination.initial_value,
                self._label_count[destination.name],
                destination.is_aliased,
                None,
                destination.is_constant,
                destination.tags,
            )
        return Variable(
            destination.name,
            destination.type,
            ssa_label=self._label_count[destination.name],
            is_aliased=destination.is_aliased,
            ssa_name=None,
            tags=destination.tags,
        )

    def _create_phi_destination_variable(self, definition: Variable | GlobalVariable) -> Variable | GlobalVariable:
        """Returns a new variable to be used as the new destination of a Phi-function that defines the given variable.
        The label of a global variable is increased twice."""
        if isinstance(definition, GlobalVariable):
            self._label_count[definition.name] += 1
        return self._create_copy_variable(definition)

    # Step 2: value-based interference graph

    def _build_interference_graph(self) -> None:
        """Builds the interference graph for the given control flow graph."""
        self._cfg_copy = self._clone_cfg()
        # insert the potentially needed copy instructions form the parallel space into the cfg
        self._parallel_spaces.insert_into_cfg(self._cfg_copy)
        with self._phi_origins_in_clone():
            self._interference_graph = ValueInterferenceGraph(self._cfg_copy)

    def _clone_cfg(self) -> ControlFlowGraph:
        """
        Clone the CFG so:
          - each BasicBlock in the clone has a *new list* of instructions (so you may insert/remove
            instructions in the clone without affecting the original),
          - but the Instruction and Variable objects inside the lists are the *same* objects
            (so renaming a Variable in either graph is visible in the other).
        """
        cfg_copy = ControlFlowGraph()
        block_map: Dict[BasicBlock, BasicBlock] = dict()

        for basic_block in self._cfg:
            new_basic_block = BasicBlock(basic_block.address, instructions=list(basic_block))
            cfg_copy.add_node(new_basic_block)
            block_map[basic_block] = new_basic_block

        for edge in self._cfg.edges:
            cfg_copy.add_edge(edge.copy(source=block_map[edge.source], sink=block_map[edge.sink]))

        if self._cfg.root is not None:
            cfg_copy.root = block_map[self._cfg.root]

        return cfg_copy

    @contextmanager
    def _phi_origins_in_clone(self) -> Iterator[None]:
        """The phi functions are shared with the original cfg, so their origin blocks are the original blocks.
        Within this context they refer to the blocks of the clone, so that liveness analysis finds the phi arguments."""
        block_of_address = {block.address: block for block in self._cfg_copy}
        phis = [instruction for block in self._cfg_copy for instruction in block if isinstance(instruction, Phi)]
        original_origin_blocks = [phi._origin_block for phi in phis]
        try:
            for phi in phis:
                phi._origin_block = {
                    block_of_address.get(block.address) if block is not None else None: value for block, value in phi._origin_block.items()
                }
            yield
        finally:
            for phi, origin_block in zip(phis, original_origin_blocks):
                phi._origin_block = origin_block

    # Step 3: coalescing and renaming

    def _coalesce_and_rename(self) -> None:
        """Step 3 of the Boissinot et al. algorithm: construct the variable classes based on the interference graph and rename the
        variables accordingly."""
        # We do the coloring on a separate graph
        self._coloring_graph = deepcopy(self._interference_graph)
        # Ensure that all relations are satisfied and combine all variables mentioned in a Phi function
        self._merge_related_variables()
        # Ensure consistency in node names
        self._wrap_variables_in_frozensets()
        self._variable_classes = self._construct_variable_classes()

        # the renamer works on the cloned cfg, which shares its variables with the original cfg
        cfg, self._task.cfg = self._task.cfg, None
        try:
            renaming_task = deepcopy(self._task)
        finally:
            self._task.cfg = cfg
        renaming_task.cfg = self._cfg_copy

        renamer = BoissinotVariableRenamer(renaming_task, self._interference_graph, self._variable_classes)
        renamer.rename()

    def _merge_related_variables(self) -> None:
        """Relabels nodes to frozensets of variables, where each frozenset contains all variables that are (transitively) connected by a
        Relation or a Phi-function."""
        group_of: Dict[Variable, frozenset] = {}
        for basic_block in self._cfg:
            for instruction in basic_block.instructions:
                if (
                    isinstance(instruction, Relation)
                    and isinstance(instruction.value, Variable)
                    and isinstance(instruction.destination, Variable)
                ):
                    self._merge_groups(group_of, [instruction.value, instruction.destination])
                elif isinstance(instruction, Phi):
                    self._merge_groups(group_of, [*instruction.requirements, *instruction.definitions])
                elif isinstance(instruction, Relation):
                    raise Exception("Found a suspicious relation, where at least one of the operands is not a variable")
        nx.relabel_nodes(self._coloring_graph, group_of, False)

    def _merge_groups(self, group_of: Dict[Variable, frozenset], variables: List[Variable]) -> None:
        """Puts the variables and all variables in their groups into one new group."""
        merged_variables = []
        for variable in variables:
            if variable in group_of:
                merged_variables.extend(list(group_of[variable]))
            else:
                merged_variables.append(variable)

        for variable in merged_variables:
            group_of[variable] = frozenset(merged_variables)

    def _wrap_variables_in_frozensets(self) -> None:
        """Ensures consistency in node names: all nodes have to be frozensets of variables"""
        group_of = {}
        for node in self._coloring_graph.nodes():
            if isinstance(node, Variable):
                group_of[node] = frozenset([node])
            elif not isinstance(node, frozenset):
                raise Exception("Found a 'Variable' that's neither a Variable nor a frozenset.")
        nx.relabel_nodes(self._coloring_graph, group_of, False)

    def _construct_variable_classes(self) -> List[List[Variable]]:
        """Creates variable classes based on the interference graph and the criteria defined in can_be_in_same_class like described in
        the paper by Boissinot et al."""
        variable_classes = self._get_classes_of_coloring_graph()

        basic_blocks = self._get_basic_blocks_by_loop_depth()
        self._merge_classes_of_copies(variable_classes, basic_blocks)
        self._share_copies(variable_classes, basic_blocks)

        return [list(variable_class) for variable_class in {id(c): c for c in variable_classes.values()}.values()]  # each class once

    def _get_classes_of_coloring_graph(self) -> DefaultDict[Variable, List[Variable]]:
        """Returns for each variable the class given by its node in the coloring graph. The members of a class share one list."""
        variable_classes = defaultdict(list)
        for node in self._coloring_graph.nodes(data=False):
            if not isinstance(node, frozenset):
                raise Exception("Found a node which is not a frozenset while constructing variable classes!")
            node_variables = list(node)
            for variable in node:
                variable_classes[variable] = node_variables
        return variable_classes

    def _merge_classes_of_copies(self, variable_classes: DefaultDict[Variable, List[Variable]], basic_blocks: List[BasicBlock]) -> None:
        """Merge the classes of variables that are connected by a copy assignment, if they do not interfere based on our new criteria."""
        for copy in self._get_copy_assignments(basic_blocks):
            destination_class = variable_classes[copy.destination]
            value_class = variable_classes[copy.value]
            if destination_class is not value_class and not self._interference_graph.are_interfering(*destination_class, *value_class):
                if self._can_be_merged(destination_class, value_class):
                    self._merge_classes(variable_classes, destination_class, value_class)

    def _share_copies(self, variable_classes: DefaultDict[Variable, List[Variable]], basic_blocks: List[BasicBlock]) -> None:
        """
        Check remaining copies for the special criterion of Boissinot et al.

        Given two assignments of the form x = y and z = y, if their live ranges intersect, they can be in the same class
        (copy sharing, Sec. III-B).
        """
        with self._phi_origins_in_clone():
            liveness = LivenessAnalysis(self._cfg_copy)

        copies_of = self._group_copy_destinations_by_source_class(variable_classes, basic_blocks)
        live_after_definition = self._live_after_definitions(
            liveness, {variable for destinations in copies_of.values() if len(destinations) > 1 for variable in destinations}
        )

        has_changed = True
        while has_changed:
            has_changed = False
            for destinations in copies_of.values():
                for variable_1, variable_2 in combinations(destinations, 2):
                    if self._share_copy(variable_classes, variable_1, variable_2, live_after_definition):
                        has_changed = True

    def _group_copy_destinations_by_source_class(
        self, variable_classes: DefaultDict[Variable, List[Variable]], basic_blocks: List[BasicBlock]
    ) -> DefaultDict[int, List[Variable]]:
        """Returns the destinations of the remaining copies, grouped by the class of the copied variable (identified by its id)."""
        copies_of: DefaultDict[int, List[Variable]] = defaultdict(list)
        for copy in self._get_copy_assignments(basic_blocks):
            if variable_classes[copy.destination] != variable_classes[copy.value]:
                copies_of[id(variable_classes[copy.value])].append(copy.destination)
        return copies_of

    def _share_copy(
        self,
        variable_classes: DefaultDict[Variable, List[Variable]],
        variable_1: Variable,
        variable_2: Variable,
        live_after_definition: Dict[Variable, Set[Variable]],
    ) -> bool:
        """Merge the classes of the two variables, if they are copies of the same variable, their live ranges intersect and their classes
        do not interfere. Returns True if the classes were merged."""
        class_1 = variable_classes[variable_1]
        class_2 = variable_classes[variable_2]
        if class_1 is class_2 or not self._can_be_merged(class_1, class_2):
            return False
        # Under strict SSA the live ranges intersect iff one variable is live right after the definition of the other
        if variable_2 not in live_after_definition[variable_1] and variable_1 not in live_after_definition[variable_2]:
            return False
        if self._interference_graph.are_interfering(*class_1, *class_2):
            return False

        self._merge_classes(variable_classes, class_1, class_2)
        return True

    def _get_copy_assignments(self, basic_blocks: List[BasicBlock]) -> Iterator[Assignment]:
        """Yields all assignments between two variables in the given basic blocks."""
        for basic_block in basic_blocks:
            for instruction in basic_block.instructions:
                if (
                    isinstance(instruction, Assignment)
                    and isinstance(instruction.destination, Variable)
                    and isinstance(instruction.value, Variable)
                ):
                    yield instruction

    def _can_be_merged(self, first_class: List[Variable], second_class: List[Variable]) -> bool:
        """Returns True if every variable of the first class can be in the same class as every variable of the second class."""
        return all(can_be_in_same_class(first, second) for first, second in product(first_class, second_class))

    def _merge_classes(
        self, variable_classes: DefaultDict[Variable, List[Variable]], first_class: List[Variable], second_class: List[Variable]
    ) -> None:
        """Replaces the two classes by one new class containing the variables of both."""
        merged_class = [*first_class, *second_class]
        for variable in merged_class:
            variable_classes[variable] = merged_class

    def _live_after_definitions(self, liveness: LivenessAnalysis, variables: Set[Variable]) -> Dict[Variable, Set[Variable]]:
        """Returns for each of the given variables the set of variables that are live directly after its definition."""
        live_after: Dict[Variable, Set[Variable]] = {}
        for basic_block in self._cfg_copy:
            live = set(liveness.live_out_of(basic_block))
            for instruction in reversed(basic_block.instructions):
                for definition in instruction.definitions:
                    if definition in variables:
                        live_after[definition] = set(live)
                # the definitions of the phi-functions are at the block entry, their arguments are used in the predecessors
                if not isinstance(instruction, Phi):
                    live.difference_update(instruction.definitions)
                    live.update(instruction.requirements)
        return defaultdict(set, live_after)

    def _get_basic_blocks_by_loop_depth(self) -> List[BasicBlock]:
        """Returns a list of all basic blocks in the CFG, sorted by their loop nesting depth in descending order."""
        depth = self._loop_depths()
        return sorted(depth.keys(), key=lambda basic_block: depth[basic_block], reverse=True)

    def _loop_depths(self) -> Dict[BasicBlock, int]:
        """
        Returns the loop nesting depth of every basic block, i.e. the number of loop headers whose natural loop contains the block.
        The paper orders the copies by block frequency (Sec. III-B), the nesting depth is a static estimate of it.
        """
        immediate_dominators: Dict[BasicBlock, BasicBlock] = nx.immediate_dominators(self._cfg_copy._graph, self._cfg_copy.root)
        immediate_dominators.setdefault(self._cfg_copy.root, self._cfg_copy.root)

        loops = defaultdict(set)  # all back edges to the same header form one loop
        for tail, header in self._cfg_copy._graph.edges():
            if self._dominates(header, tail, immediate_dominators):
                loops[header].update(self._get_loop_nodes(header, tail))

        return {basic_block: sum(basic_block in loop for loop in loops.values()) for basic_block in self._cfg_copy}

    def _dominates(self, dominator: BasicBlock, dominated: BasicBlock, immediate_dominators: Dict[BasicBlock, BasicBlock]) -> bool:
        """Returns True if dominator dominates dominated in the CFG, False otherwise."""
        if dominated not in immediate_dominators:  # unreachable block: dominated by nothing
            return False
        current = dominated
        while current != self._cfg_copy.root:
            if current == dominator:
                return True
            current = immediate_dominators[current]
        return current == dominator  # Check if the root is the dominator

    def _get_loop_nodes(self, header: BasicBlock, tail: BasicBlock) -> List[BasicBlock]:
        """Returns a list of all basic blocks involved in the loop with the given header and the back edge tail->header."""
        loop = [header]
        worklist = []
        if tail is not header:
            loop.append(tail)
            worklist.append(tail)
        while worklist:
            basic_block = worklist.pop()
            for predecessor in self._cfg_copy.get_predecessors(basic_block):
                if (predecessor not in loop) and (predecessor is not None):
                    loop.append(predecessor)
                    worklist.append(predecessor)

        return loop

    # Clean up

    def _remove_phis(self, cfg: ControlFlowGraph) -> None:
        """Remove all Phi-functions from the CFG."""
        for basic_block in cfg:
            for instruction in basic_block.instructions:
                if isinstance(instruction, Phi):
                    basic_block.replace_instruction(instruction, [])

    def _remove_nop_instr(self, cfg: ControlFlowGraph) -> None:
        """Remove all instructions of the form x = x and all relations as they have been considered already and are not needed anymore."""
        for basic_block in cfg:
            for instruction in basic_block.instructions:
                if (
                    isinstance(instruction, Assignment)
                    and isinstance(instruction.destination, Variable)
                    and isinstance(instruction.value, Variable)
                    and instruction.destination == instruction.value
                ) or isinstance(instruction, Relation):
                    basic_block.replace_instruction(instruction, [])
