"""
Module for translating out of SSA form with the algorithm of Sreedhar et al.

Reference: V. C. Sreedhar, R. D.-C. Ju, D. M. Gillies, V. Santhanam: "Translating Out of Static Single Assignment Form",
Static Analysis Symposium (SAS) 1999.

Outline of the steps:
    1. Phi congruence classes: every variable starts in its own class, the classes of the operands of a Relation and of all global
       variables with the same name are merged.
    2. Copy insertion (Section 4.3, Method III): for every Phi function, pairs of resources (the destination and the arguments, each
       together with its block) whose classes interfere are examined. Depending on the liveness of the classes at the blocks of the
       resources (four cases) a resource is chosen for which a copy is inserted, or the pair is left unresolved and resolved
       afterwards by looking at the neighbors in the graph of unresolved pairs. Afterwards, the classes of all resources of the Phi
       function are merged.
    3. Copy removal (Section 5): the inserted copies and the copies already present in the program are removed if the classes of the
       destination and the source of the copy can be merged without interference.
    4. Sequentialization: the copies placed in front of a branch or after the Phi functions of a block are parallel copies. They are
       turned into a sequence of assignments, with a temporary variable for cycles.
    5. Renaming: all variables of a congruence class are replaced by one variable, and the Phi functions and Relations are removed.

Differences to the paper, because of the structure of dewolf:
    a) The paper only knows variables as Phi arguments. The ConstantLifter lifts constant arguments into new variables beforehand.
    b) Copies for Phi arguments are placed before the branch that ends the predecessor block. Thus, the variables read by this
       branch are added to the live-out set of the block.
    c) A Phi argument from the function entry (origin block None) gets a new entry block before the root, where its copy is placed.
    d) Relations, global and aliased variables and function parameters restrict which congruence classes may be merged
       (see the variable kinds below).
"""

import itertools
from collections import defaultdict
from typing import Any, DefaultDict, Dict, Generator, Iterable, Iterator, List, NamedTuple, Optional, Set, Tuple, Union, cast

from decompiler.pipeline.commons.livenessanalysis import LivenessAnalysis
from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.graphs.branches import UnconditionalEdge
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo.expressions import Constant, GlobalVariable, Tag, Variable
from decompiler.structures.pseudo.instructions import Assignment, GenericBranch, Instruction, Phi, Relation
from decompiler.task import DecompilerTask
from decompiler.util.insertion_ordered_set import InsertionOrderedSet

# Kinds of variables, a congruence class has the highest kind of its members. They restrict which classes may be merged.
_KIND_GLOBAL = 1 << 4  # 16
_KIND_ALIASED = 1 << 3  # 8
_KIND_FUNC_ARG = 1 << 2  # 4
_KIND_LOCAL = 1 << 1  # 2
_KIND_WILD = 1 << 0  # 1

# Classes of these kinds may only be merged with a class of the same kind if their representatives have the same name.
_NAME_CHECK_MASK = _KIND_GLOBAL | _KIND_ALIASED

# Maps each kind to the kinds it may be merged with.
_ALLOWED_MERGES = {
    _KIND_GLOBAL: _KIND_GLOBAL | _KIND_WILD,
    _KIND_ALIASED: _KIND_ALIASED | _KIND_WILD,
    _KIND_FUNC_ARG: _KIND_FUNC_ARG | _KIND_LOCAL | _KIND_WILD,
    _KIND_LOCAL: _KIND_FUNC_ARG | _KIND_LOCAL | _KIND_WILD,
    _KIND_WILD: _KIND_GLOBAL | _KIND_ALIASED | _KIND_FUNC_ARG | _KIND_LOCAL | _KIND_WILD,
}


class NameHandler:
    """Manages the generation of unique names and SSA labels for variables."""

    def __init__(self):
        self._name_map: DefaultDict[str, int] = defaultdict(int)
        self._ssa_names: DefaultDict[str, int] = defaultdict(int)

    def register_ssa_var(self, variable: Variable) -> None:
        """Remember the SSA label of the variable, so that new labels for its name are larger."""
        if variable.ssa_label and variable.ssa_label > self._ssa_names[variable.name]:
            self._ssa_names[variable.name] = variable.ssa_label

    def get_name(self, requested_name: str) -> str:
        """Return the requested name, or the name with the smallest unused numeric suffix if it is already in use."""
        suffix = self._name_map[requested_name]
        name = requested_name if suffix == 0 else f"{requested_name}_{suffix}"
        while self._name_map.get(name, 0) > 0:
            suffix += 1
            name = f"{requested_name}_{suffix}"
        self._name_map[name] = 1  # mark as used (it was unused, so its count was 0)
        self._name_map[requested_name] = suffix + 1
        return name

    def get_ssa_label(self, name: str) -> int:
        """Return a new SSA label for the given name."""
        self._ssa_names[name] += 1
        return self._ssa_names[name]


class ConstantLifter:
    """Pre-processing pass that lifts Constants out of Phi instructions into dedicated assignments."""

    _CONST_LIFT_NAME = "v_const"

    def __init__(self, task: DecompilerTask):
        self._task = task
        self._cfg: ControlFlowGraph = cast(ControlFlowGraph, self._task.cfg)
        self._name_handler = NameHandler()
        self._entry_block: Optional[BasicBlock] = None

        for instruction in self._cfg.instructions:
            for variable in instruction.definitions + instruction.requirements:
                self._name_handler.register_ssa_var(variable)

    def _insert_before_branch(self, instructions: List[Instruction], instruction: Instruction) -> None:
        """Inserts an instruction right before the terminating branch, if one exists."""
        if instructions and isinstance(instructions[-1], GenericBranch):
            branch = instructions.pop()
            instructions.append(instruction)
            instructions.append(branch)
        else:
            instructions.append(instruction)

    def perform(self) -> None:
        """Lift the constants of all Phi functions."""
        for block in list(self._cfg):
            for phi in [instruction for instruction in block.instructions if isinstance(instruction, Phi)]:
                self._lift_constants_from_phi(phi)

    def _create_entry_block(self, root: BasicBlock) -> BasicBlock:
        """Create an empty entry block before the root and move the function-entry origin (None) of its Phis to it."""
        entry_block = self._cfg.create_block([])
        self._cfg.add_edge(UnconditionalEdge(entry_block, root))
        self._cfg.root = entry_block
        for instruction in root.instructions:
            if isinstance(instruction, Phi) and None in instruction.origin_block:
                instruction.origin_block[entry_block] = instruction.origin_block.pop(None)
        return entry_block

    def _lift_constants_from_phi(self, phi: Phi) -> None:
        """Replace each constant argument of the Phi by a new variable, which is assigned the constant at the end of the origin block."""
        for predecessor, argument in list(phi.origin_block.items()):
            if not isinstance(argument, Constant):
                continue

            # We use tags here as a small workaround rather than modifying the
            # Variable class solely to support this algorithm.
            lifted_variable = Variable(
                name=self._CONST_LIFT_NAME,
                vartype=argument.type,
                ssa_label=self._name_handler.get_ssa_label(self._CONST_LIFT_NAME),
                tags=(Tag(name="sreedhar_var_tag", data="wild"),),
            )

            if predecessor is None:  # argument from function entry, only possible in the root block
                if self._entry_block is None:
                    self._entry_block = self._create_entry_block(cast(BasicBlock, self._cfg.root))
                predecessor = self._entry_block
            self._insert_before_branch(predecessor.instructions, Assignment(lifted_variable, argument.copy()))
            phi.substitute_for_block(predecessor, lifted_variable)


class PhiCongruenceClass(InsertionOrderedSet[Variable]):
    """A set of variables that are renamed to the same variable, with its representative and kind."""

    __slots__ = ("representative", "kind")

    def __init__(
        self,
        iterable: Optional[Iterable[Variable]] = None,
        representative: Optional[Variable] = None,
        kind: Optional[int] = None,
        **kwargs: Any,
    ):
        self.representative = representative
        self.kind = kind if kind is not None else _KIND_LOCAL
        super().__init__(iterable, **kwargs)

    # This is required to enable the use of source_class - {source} during copy removal.
    def __sub__(self, other):
        result = type(self)(super().__sub__(other))
        result.representative = self.representative
        result.kind = self.kind
        return result


class PhiCongruenceMap:
    """Maps each variable to its Phi congruence class and creates the renaming of the variables from the classes."""

    def __init__(self, function_arg_names: Set[str]):
        self._function_arg_names = function_arg_names
        self._element_to_class: Dict[Variable, PhiCongruenceClass] = {}

    def get_elements(self) -> Iterable[Variable]:
        """Return all variables that have a class."""
        return self._element_to_class.keys()

    def get_class(self, element: Variable) -> PhiCongruenceClass:
        """Return the class of the variable."""
        return self._element_to_class[element]

    def _get_var_kind(self, variable: Variable) -> int:
        """Return the kind of the variable, which restricts the merging of its class."""
        if isinstance(variable, GlobalVariable):
            return _KIND_GLOBAL
        if getattr(variable, "is_aliased", False):
            return _KIND_ALIASED
        if variable.name in self._function_arg_names:
            return _KIND_FUNC_ARG

        tags = getattr(variable, "tags", None)
        if tags and tags[0].name == "sreedhar_var_tag" and tags[0].data == "wild":
            return _KIND_WILD

        return _KIND_LOCAL

    def create_class(self, variable: Variable) -> None:
        """Create a class containing only the variable, if it does not have a class yet."""
        if variable not in self._element_to_class:
            kind = self._get_var_kind(variable)
            has_representative = kind >= _KIND_FUNC_ARG
            self._element_to_class[variable] = PhiCongruenceClass(
                [variable], representative=variable if has_representative else None, kind=kind
            )

    def nullify_singletons(self) -> None:
        """Empty all classes with a single element, so they count as not being part of a Phi function."""
        for congruence_class in self._element_to_class.values():
            if len(congruence_class) == 1:
                congruence_class.clear()

    def merge_classes(self, elements: Iterable[Variable]) -> Optional[PhiCongruenceClass]:
        """Merge the classes of all given variables into the largest one and return it."""
        elements_list = list(elements)
        if not elements_list:
            return None

        classes = list({id(self.get_class(element)): self.get_class(element) for element in elements_list}.values())
        master_class = max(classes, key=len)
        for current_class in classes:
            if current_class is master_class:
                continue

            for member in current_class:
                self._element_to_class[member] = master_class

            master_class.update(current_class)
            if current_class.kind > master_class.kind:
                master_class.kind = current_class.kind
                master_class.representative = current_class.representative

        for element in elements_list:
            self._element_to_class[element] = master_class
            master_class.add(element)

        return master_class

    def generate_renaming_map(self, name_handler: NameHandler, param_entry_vars: Iterable[Variable]) -> Dict[Variable, Variable]:
        """Create for each class a new variable named after its representative and map every member of the class to it."""
        groups: Dict[int, Tuple[Optional[Variable], List[Variable]]] = {}
        # The class holding the entry version of a function parameter must carry exactly the parameter's name,
        # otherwise the body reads a different variable than the one declared in the signature.
        # Insert these groups first so they are named before any other class can take the name.
        for variable in param_entry_vars:
            if variable in self._element_to_class:
                groups[id(self._element_to_class[variable])] = (variable, [])

        for element, congruence_class in self._element_to_class.items():
            group = groups.get(id(congruence_class))
            if group is None:
                groups[id(congruence_class)] = group = (congruence_class.representative, [])

            group[1].append(element)

        renaming_map: Dict[Variable, Variable] = {}
        for representative, members in groups.values():
            representative = members[0] if representative is None else representative
            group_name = name_handler.get_name(representative.name)
            representative_type = representative.type
            representative_aliased = representative.is_aliased

            if isinstance(representative, GlobalVariable):
                representative_initial_value = representative.initial_value
                representative_constant = representative.is_constant
                for variable in members:
                    renaming_map[variable] = GlobalVariable(
                        name=group_name,
                        vartype=representative_type,
                        initial_value=representative_initial_value,
                        is_aliased=representative_aliased,
                        ssa_name=variable,
                        is_constant=representative_constant,
                        tags=variable.tags,
                    )
            else:
                for variable in members:
                    renaming_map[variable] = Variable(
                        name=group_name,
                        vartype=representative_type,
                        is_aliased=representative_aliased,
                        ssa_name=variable,
                        tags=variable.tags,
                    )
        return renaming_map


class AssignmentHelper:
    """The assignments of a block: the copies after its Phi functions, its own copies and the copies before its branch."""

    __slots__ = ("after_phis", "block_assigns", "before_branch")

    def __init__(self):
        self.after_phis: InsertionOrderedSet[Assignment] = InsertionOrderedSet()
        self.block_assigns: InsertionOrderedSet[Assignment] = InsertionOrderedSet()
        self.before_branch: InsertionOrderedSet[Assignment] = InsertionOrderedSet()

    def get_all_assigns(self) -> Generator[Assignment, None, None]:
        """Yield all assignments in the order after_phis, block_assigns, before_branch."""
        yield from self.after_phis
        yield from self.block_assigns
        yield from self.before_branch


class OriginMap:
    """For a Phi function its block and for each of its arguments the blocks it comes from (None for the function entry)."""

    __slots__ = ("destination_block", "argument_origins")

    def __init__(self):
        self.destination_block: Optional[BasicBlock] = None
        self.argument_origins: DefaultDict[Union[Variable, Constant], List[Optional[BasicBlock]]] = defaultdict(list)

    def substitute_argument(self, old_argument: Union[Variable, Constant], argument: Union[Variable, Constant]) -> None:
        """Replace the argument by another one, keeping its origin blocks."""
        if old_argument != argument and old_argument in self.argument_origins:
            self.argument_origins[argument] = self.argument_origins.pop(old_argument)

    def substitute_block(self, old_block: Optional[BasicBlock], block: BasicBlock) -> None:
        """Replace the origin block old_block by another block."""
        for origin_blocks in self.argument_origins.values():
            origin_blocks[:] = [block if origin_block is old_block else origin_block for origin_block in origin_blocks]


class Resource(NamedTuple):
    """A variable of a Phi function together with the block where it is used: the Phi block for its destination, else an origin block."""

    variable: Variable
    block: Optional[BasicBlock]


class SreedharOutOfSSA:
    """Implements Sreedhar's Out-of-SSA algorithm to translate SSA form back to normal form."""

    _PHI_COPY_NAME = "v_phi"
    _TMP_COPY_NAME = "v_tmp"

    def __init__(self, task: DecompilerTask):
        self._task = task
        self._name_handler = NameHandler()
        self._cfg: ControlFlowGraph = cast(ControlFlowGraph, task.cfg)
        self._interference_graph = InterferenceGraph(self._cfg)
        self._phi_to_orig_map: Dict[int, OriginMap] = {}
        self._block_to_phi: DefaultDict[BasicBlock, List[Phi]] = defaultdict(list)
        self._assignment_helpers: DefaultDict[BasicBlock, AssignmentHelper] = defaultdict(AssignmentHelper)

        self._function_arg_names = {variable.name for variable in self._task.function_parameters}
        self._phi_congruence_map = PhiCongruenceMap(self._function_arg_names)
        self._func_args: Dict[str, Variable] = {}
        self._live_in: Dict[Optional[BasicBlock], Set[Variable]] = {}
        self._live_out: Dict[Optional[BasicBlock], Set[Variable]] = {}

    def perform(self) -> None:
        """Translate the cfg out of SSA form."""
        self._initialize_congruence_classes()
        self._collect_phi_origins()
        self._add_parameter_interference()
        self._compute_liveness()
        self._eliminate_phi_resource_interference()
        self._copy_removal()
        self._variable_rename()

    def _initialize_congruence_classes(self) -> None:
        """Create one class per variable, merge the operands of Relations and merge all global variables with the same name."""
        global_vars_by_name: DefaultDict[str, Set[Variable]] = defaultdict(set)
        for block in self._cfg:
            for instruction in block.instructions:
                for variable in instruction.definitions + instruction.requirements:
                    self._name_handler.register_ssa_var(variable)
                    self._phi_congruence_map.create_class(variable)

                    if isinstance(variable, GlobalVariable):
                        global_vars_by_name[variable.name].add(variable)

        for block in self._cfg:
            for instruction in block.instructions:
                if isinstance(instruction, Relation):
                    self._phi_congruence_map.merge_classes([instruction.destination, instruction.value])

        # Merge all globals with the same name
        for name_group in global_vars_by_name.values():
            if len(name_group) < 2:
                continue

            sorted_group = sorted(name_group, key=lambda variable: variable.ssa_label)
            anchor = sorted_group[0]
            merged_class = self._phi_congruence_map.get_class(anchor)

            for variable in sorted_group[1:]:
                variable_class = self._phi_congruence_map.get_class(variable)
                if variable_class is merged_class:
                    continue

                merged_class = self._phi_congruence_map.merge_classes([anchor, variable])

    def _collect_phi_origins(self) -> None:
        """Collect the Phi functions of each block, the origin blocks of their arguments and the copies already in the blocks."""
        for block in self._cfg:
            for instruction in block.instructions:
                match instruction:
                    case Phi() as phi:
                        self._block_to_phi[block].append(phi)

                        origin_map = OriginMap()
                        origin_map.destination_block = block

                        for origin_block, argument in phi.origin_block.items():
                            if argument:
                                origin_map.argument_origins[argument].append(origin_block)

                        for argument in phi.requirements:
                            if argument not in origin_map.argument_origins:
                                origin_map.argument_origins[argument] = [None]

                        self._phi_to_orig_map[id(phi)] = origin_map

                    case Assignment(destination=Variable(), value=Variable()):
                        self._assignment_helpers[block].block_assigns.add(instruction)

    def _add_parameter_interference(self) -> None:
        """Find the entry (smallest) SSA version of each function parameter. These versions interfere with each other."""
        all_variables = set()
        for block in self._cfg:
            for instruction in block.instructions:
                for variable in instruction.definitions + instruction.requirements:
                    all_variables |= {variable}

        for variable in all_variables:
            if variable.name in self._function_arg_names:
                if variable.name not in self._func_args or variable.ssa_label < self._func_args[variable.name].ssa_label:
                    self._func_args[variable.name] = variable

        self._interference_graph.add_edges_from((itertools.combinations(self._func_args.values(), 2)))

    def _compute_liveness(self) -> None:
        """Compute the live-in and live-out sets of all blocks, where None is treated like an entry block before the root."""
        liveness = LivenessAnalysis(self._cfg)

        # The liveness analysis only puts the phi arguments coming from the function entry into live_out[None].
        # Variables live through the root (e.g. parameters used later) are only in live_in[root], since None is
        # no predecessor in the cfg. Add them, so None is treated like a real entry block.
        root = self._cfg.root
        self._live_out[None] = liveness.live_out_of(None) | (liveness.live_in_of(root) - liveness.defs_phi_of(root))  # type: ignore
        for block in self._cfg:
            self._live_in[block] = liveness.live_in_of(block)  # type: ignore
            self._live_out[block] = liveness.live_out_of(block)  # type: ignore
            # Copies for phi arguments are placed before the branch that ends the block, so the variables that
            # branch reads are live where the copies are inserted, too.
            if block.instructions and isinstance(block.instructions[-1], GenericBranch):
                self._live_out[block].update(block.instructions[-1].requirements)

    def _is_live_in_context(self, congruence_class: PhiCongruenceClass, block: Optional[BasicBlock], is_destination: bool) -> bool:
        """Check whether a variable of the class is live-in (for a Phi destination) or live-out (for an argument) at the block."""
        liveness_set = self._live_in.get(block, set()) if is_destination else self._live_out.get(block, set())
        return not congruence_class.isdisjoint(liveness_set)

    def _can_merge_classes(self, first_class: PhiCongruenceClass, second_class: PhiCongruenceClass) -> bool:
        """Check whether the kinds of the two classes allow them to be merged."""
        if not (_ALLOWED_MERGES[first_class.kind] & second_class.kind):
            return False

        if first_class.kind == second_class.kind and (first_class.kind & _NAME_CHECK_MASK):
            return first_class.representative.name == second_class.representative.name  # type: ignore

        return True

    def _classes_interfere(self, first_class: PhiCongruenceClass, second_class: PhiCongruenceClass) -> bool:
        """Check whether two classes cannot be merged, because of their kinds or because variables of them interfere."""
        if first_class is second_class:
            return False

        if not self._can_merge_classes(first_class, second_class):
            return True

        for variable in first_class:
            if not self._interference_graph.has_node(variable):
                continue

            neighbors = self._interference_graph[variable]
            if not second_class.isdisjoint(neighbors):
                return True

        return False

    def _classify_pair(
        self,
        resource_i: Resource,
        resource_j: Resource,
        destination: Resource,
        candidates: InsertionOrderedSet[Resource],
        unresolved: Dict[Resource, Set[Resource]],
    ) -> None:
        """
        Handle one pair of resources of a Phi function whose classes interfere (the four cases of Section 4.3, Method III).

        This follows the notation of the paper: x_i, x_j are the variables of the resources, l_i, l_j their blocks
        and c_i, c_j the congruence classes of the variables.
        If only one of the classes is live in the context of the other, the resource of the live class is a candidate for a copy.
        If both are, both resources are candidates. If neither is, the pair is unresolved.
        """
        x_i, x_j = resource_i.variable, resource_j.variable
        l_i, l_j = resource_i.block, resource_j.block
        c_i, c_j = self._phi_congruence_map.get_class(x_i), self._phi_congruence_map.get_class(x_j)

        if not self._classes_interfere(c_i, c_j):
            return

        c_j_live_at_l_i = self._is_live_in_context(c_j, l_i, resource_i is destination)
        c_i_live_at_l_j = self._is_live_in_context(c_i, l_j, resource_j is destination)

        if not c_j_live_at_l_i and c_i_live_at_l_j:
            candidates.add(resource_i)
        elif c_j_live_at_l_i and not c_i_live_at_l_j:
            candidates.add(resource_j)
        elif c_j_live_at_l_i and c_i_live_at_l_j:
            candidates.update((resource_i, resource_j))
        else:
            unresolved[resource_i].add(resource_j)
            unresolved[resource_j].add(resource_i)

    def _resolve_unresolved_neighbors(self, candidates: InsertionOrderedSet[Resource], unresolved: Dict[Resource, Set[Resource]]) -> None:
        """
        Choose further copy candidates for the unresolved pairs (Section 4.3, Method III).

        Resources with many unresolved neighbors are made candidates first, if not all their neighbors are candidates already.
        Afterwards, candidates added this way are dropped again if all their unresolved neighbors are candidates.
        """
        added: List[Resource] = []
        for resource in sorted(unresolved.keys(), key=lambda unresolved_resource: len(unresolved[unresolved_resource]), reverse=True):
            if resource not in candidates and not unresolved[resource].issubset(candidates):
                candidates.add(resource)
                added.append(resource)

        for resource in added:
            if unresolved[resource].issubset(candidates):
                candidates.discard(resource)

    def _create_copy_var(self, original: Variable) -> Variable:
        """Create a new variable for a copy of the original variable."""
        copy_variable = Variable(
            name=self._PHI_COPY_NAME,
            vartype=original.type,
            ssa_label=self._name_handler.get_ssa_label(self._PHI_COPY_NAME),
            is_aliased=False,
            tags=(Tag("sreedhar_var_tag", data="wild"),),
        )

        return copy_variable

    def _insert_dest_copy(self, phi: Phi, variable: Variable, new_variable: Variable) -> None:
        """Make the Phi define new_variable instead of its destination and copy new_variable to the destination after the Phi functions."""
        phi_block = self._phi_to_orig_map[id(phi)].destination_block
        if phi_block is None:
            return

        phi.rename_destination(variable, new_variable)
        self._assignment_helpers[phi_block].after_phis.add(Assignment(variable, new_variable))

        self._live_in[phi_block].discard(variable)
        self._live_in[phi_block].add(new_variable)
        self._interference_graph.add_edges_from((new_variable, live) for live in self._live_in[phi_block] if new_variable is not live)

    def _create_entry_block(self, phi_block: BasicBlock) -> BasicBlock:
        """Create a new entry block before the root for the Phi arguments from the function entry (origin block None)."""
        if phi_block is not self._cfg.root:
            raise AssertionError(
                f"Phi argument without origin block in non-root block {phi_block.name}: a copy for it would be unreachable"
            )

        entry_block = self._cfg.create_block([])
        self._cfg.add_edge(UnconditionalEdge(entry_block, phi_block))
        self._cfg.root = entry_block

        # The new block takes over the role of None as the function entry, including its live-out set
        self._live_out[entry_block] = self._live_out.pop(None)

        for phi in self._block_to_phi.get(phi_block, ()):
            if None in phi.origin_block:
                phi.origin_block[entry_block] = phi.origin_block.pop(None)
            self._phi_to_orig_map[id(phi)].substitute_block(None, entry_block)

        return entry_block

    def _insert_req_copy(self, phi: Phi, variable: Variable, new_variable: Variable) -> None:
        """Make the Phi use new_variable instead of the argument and copy the argument to new_variable before the branch of each origin block."""
        for origin_block in self._phi_to_orig_map[id(phi)].argument_origins[variable]:
            if origin_block is None:
                origin_block = self._create_entry_block(cast(BasicBlock, self._phi_to_orig_map[id(phi)].destination_block))

            phi.substitute(variable, new_variable)
            self._phi_to_orig_map[id(phi)].substitute_argument(variable, new_variable)
            self._assignment_helpers[origin_block].before_branch.add(Assignment(new_variable, variable))

            self._live_out[origin_block].add(new_variable)

            # Remove the variable from live_out if it's no longer needed in successors
            if all(
                variable not in self._live_in[successor]
                and all(successor_phi.origin_block.get(origin_block) != variable for successor_phi in self._block_to_phi.get(successor, ()))
                for successor in self._cfg.get_successors(origin_block)
            ):
                self._live_out[origin_block].discard(variable)

            self._interference_graph.add_edges_from(
                (new_variable, live) for live in self._live_out[origin_block] if new_variable is not live
            )

    def _eliminate_phi_resource_interference(self) -> None:
        """
        Insert copies so that the resources of each Phi function do not interfere and merge their classes (Section 4.3, Method III).
        """
        for phi in itertools.chain.from_iterable(self._block_to_phi.values()):
            unresolved: Dict[Resource, Set[Resource]] = {}
            candidates: InsertionOrderedSet[Resource] = InsertionOrderedSet()
            destination = Resource(cast(Variable, phi.destination), self._phi_to_orig_map[id(phi)].destination_block)

            unresolved[destination] = set()
            for argument in phi.requirements:
                for origin_block in self._phi_to_orig_map[id(phi)].argument_origins[argument]:
                    unresolved[Resource(argument, origin_block)] = set()

            for resource_i, resource_j in itertools.combinations(unresolved.keys(), 2):
                self._classify_pair(resource_i, resource_j, destination, candidates, unresolved)

            self._resolve_unresolved_neighbors(candidates, unresolved)

            for resource in candidates:
                variable = resource.variable
                new_variable = self._create_copy_var(variable)
                self._phi_congruence_map.create_class(new_variable)

                if resource is destination:
                    self._insert_dest_copy(phi, variable, new_variable)
                else:
                    self._insert_req_copy(phi, variable, new_variable)

            phi_variables = [cast(Variable, phi.destination)] + [argument for argument in phi.requirements]

            merged_class = self._phi_congruence_map.merge_classes(phi_variables)
            if merged_class and not merged_class.representative:
                merged_class.representative = cast(Variable, phi.destination)

        self._phi_congruence_map.nullify_singletons()

    def _can_remove_copy(
        self, destination: Variable, source: Variable, destination_class: PhiCongruenceClass, source_class: PhiCongruenceClass
    ) -> bool:
        """Check whether the copy destination = source can be removed, i.e. whether their classes can be merged without interference."""
        # we return false so we skip an unecessary merge
        if destination_class is source_class:
            return False

        if not destination_class and not source_class:
            return self._can_merge_classes(destination_class, source_class)

        # Note we keep representative and kind for the PhiCongruenceClass here on purpose since they are used for _can_merge_classes
        if not destination_class:
            return not self._classes_interfere(
                source_class - {source},
                PhiCongruenceClass({destination}, representative=destination_class.representative, kind=destination_class.kind),
            )

        if not source_class:
            return not self._classes_interfere(
                destination_class - {destination},
                PhiCongruenceClass({source}, representative=source_class.representative, kind=source_class.kind),
            )

        source_class_rest, destination_class_rest = source_class - {source}, destination_class - {destination}
        return not self._classes_interfere(destination_class, source_class_rest) and not self._classes_interfere(
            source_class, destination_class_rest
        )

    def _copy_removal(self) -> None:
        """Merge the classes of the destination and the source of every copy for which this is possible (Section 5)."""
        for helper in self._assignment_helpers.values():
            for assignment in helper.get_all_assigns():
                if isinstance(assignment.destination, Variable) and isinstance(assignment.value, Variable):
                    destination_class = self._phi_congruence_map.get_class(assignment.destination)
                    source_class = self._phi_congruence_map.get_class(assignment.value)
                    if self._can_remove_copy(assignment.destination, assignment.value, destination_class, source_class):
                        self._phi_congruence_map.merge_classes([assignment.destination, assignment.value])

    def _process_and_rename(self, instructions: Iterable[Instruction], renaming_map: Dict[Variable, Variable]) -> Iterator[Instruction]:
        """Rename the variables of the instructions, dropping Phi functions, Relations and assignments of a variable to itself."""
        for instruction in instructions:
            if isinstance(instruction, (Phi, Relation)):
                continue

            for variable in instruction.definitions + instruction.requirements:
                if renamed_variable := renaming_map.get(variable):
                    instruction.substitute(variable, renamed_variable)

            # Skip tautological assignments (e.g. x = x)
            if (
                isinstance(instruction, Assignment)
                and isinstance(instruction.destination, Variable)
                and isinstance(instruction.value, Variable)
            ):
                if instruction.destination.name == instruction.value.name:
                    continue

            yield instruction

    def _sequentialize_parallel_copies(self, copies: Iterable[Assignment]) -> Iterator[Assignment]:
        """
        Turn parallel copies into a sequence of assignments.

        A copy is emitted once no other pending copy reads its destination. If only cycles remain, the value of one destination
        is saved into a temporary variable, which the pending copies read instead.
        """
        copies = list(copies)
        pending: Dict[str, Assignment] = {cast(Variable, copy.destination).name: copy for copy in copies}
        while pending:
            used = {copy.value.name for copy in pending.values() if isinstance(copy.value, Variable)}
            ready = [destination_name for destination_name in pending if destination_name not in used]
            if ready:
                for destination_name in ready:
                    yield pending.pop(destination_name)
                continue

            victim = cast(Variable, next(iter(pending.values())).destination)
            temporary = Variable(self._name_handler.get_name(self._TMP_COPY_NAME), victim.type)
            yield Assignment(temporary, victim.copy())
            for copy in pending.values():
                if isinstance(copy.value, Variable) and copy.value.name == victim.name:
                    copy.substitute(copy.value, temporary.copy())

    def _variable_rename(self) -> None:
        """Rename the variables according to their classes, sequentialize the copies and remove the Phi functions and Relations."""
        renaming_map = self._phi_congruence_map.generate_renaming_map(self._name_handler, self._func_args.values())

        for block in self._cfg:
            has_branch = bool(block.instructions) and isinstance(block.instructions[-1], GenericBranch)
            branch_instruction = block.instructions[-1] if has_branch else None
            core_instructions = block.instructions[:-1] if has_branch else block.instructions
            helper = self._assignment_helpers[block]

            new_instructions: List[Instruction] = []
            new_instructions.extend(
                self._sequentialize_parallel_copies(cast(Iterator[Assignment], self._process_and_rename(helper.after_phis, renaming_map)))
            )
            new_instructions.extend(self._process_and_rename(core_instructions, renaming_map))
            new_instructions.extend(
                self._sequentialize_parallel_copies(
                    cast(Iterator[Assignment], self._process_and_rename(helper.before_branch, renaming_map))
                )
            )

            if branch_instruction:
                # Branch instructions just need variables substituted, never discarded
                for variable in branch_instruction.definitions + branch_instruction.requirements:
                    if renamed_variable := renaming_map.get(variable):
                        branch_instruction.substitute(variable, renamed_variable)
                new_instructions.append(branch_instruction)

            block.instructions = new_instructions
