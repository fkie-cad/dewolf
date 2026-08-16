from __future__ import annotations

import itertools
from collections import defaultdict
from typing import Any, Generator, Iterable, List, NamedTuple, Optional, Set, cast

from decompiler.pipeline.commons.livenessanalysis import LivenessAnalysis
from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.graphs.branches import UnconditionalEdge
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo.expressions import Constant, GlobalVariable, Tag, Variable
from decompiler.structures.pseudo.instructions import Assignment, GenericBranch, Instruction, Phi, Relation
from decompiler.task import DecompilerTask
from decompiler.util.insertion_ordered_set import InsertionOrderedSet

"""Sreedhar et. al. "Translating Out Of Static Single Assignment Form"""

class NameHandler:
    """Manages the generation of unique names and SSA labels for variables."""
    def __init__(self):
        self._name_map: dict[str, int] = defaultdict(int)
        self._ssa_names: dict[str, int] = defaultdict(int)

    def register_ssa_var(self, v: Variable) -> None:
        if v.ssa_label and v.ssa_label > self._ssa_names[v.name]:
            self._ssa_names[v.name] = v.ssa_label

    def get_name(self, req_name: str) -> str:
        c = self._name_map[req_name]
        self._name_map[req_name] = c + 1
        return req_name if c == 0 else f"{req_name}_{c}"

    def get_ssa_label(self, name: str) -> int:
        self._ssa_names[name] += 1
        return self._ssa_names[name]


class ConstantLifter:
    """Pre-processing pass that lifts Constants out of Phi instructions into dedicated assignments."""

    _CONST_LIFT_NAME= "v_const"

    def __init__(self, task: DecompilerTask):
        self._task = task
        self._cfg: ControlFlowGraph = cast(ControlFlowGraph, self._task.cfg)
        self._name_handler = NameHandler()

        for instr in self._cfg.instructions:
            for var in instr.definitions + instr.requirements:
                self._name_handler.register_ssa_var(var)

    def _insert_before_branch(self, instrs: list[Instruction], instr: Instruction) -> None:
        """Inserts an instruction right before the terminating branch, if one exists."""
        if instrs and isinstance(instrs[-1], GenericBranch):
            branch = instrs.pop()
            instrs.append(instr)
            instrs.append(branch)
        else:
            instrs.append(instr)

    def perform(self) -> None:
        for bb in self._cfg:
            for phi in [i for i in bb.instructions if isinstance(i, Phi)]:
                self._lift_constants_from_phi(phi)

    def _lift_constants_from_phi(self, phi: Phi) -> None:
        for pred_bb, con in list(phi.origin_block.items()):
            if not isinstance(con, Constant):
                continue

            # We use tags here as a small workaround rather than modifying the
            # Variable class solely to support this algorithm.
            n_var = Variable(
                name=self._CONST_LIFT_NAME,
                vartype=con.type,
                ssa_label=self._name_handler.get_ssa_label(self._CONST_LIFT_NAME),
                tags=(Tag(name="sreedhar_var_tag", data="wild"),)
            )

            self._insert_before_branch(pred_bb.instructions, Assignment(n_var, con.copy()))
            # Manually substitute only for this block's entry
            phi.origin_block[pred_bb] = n_var
            phi.value._operands = [operand if id(operand) != id(con) else n_var for operand in phi.value.operands] #type ignore


class SreedharOutOfSSA:
    """Implements Sreedhar's Out-of-SSA algorithm to translate SSA form back to normal form."""

    _PHI_COPY_NAME = "v_phi"

    _KIND_GLOBAL   = 1 << 4  # 16
    _KIND_ALIASED  = 1 << 3  # 8
    _KIND_FUNC_ARG = 1 << 2  # 4
    _KIND_LOCAL    = 1 << 1  # 2
    _KIND_WILD    = 1 << 0  # 1

    _NAME_CHECK_MASK = _KIND_GLOBAL | _KIND_ALIASED

    _ALLOWED_MERGES = {
        _KIND_GLOBAL:   _KIND_GLOBAL | _KIND_WILD,
        _KIND_ALIASED:  _KIND_ALIASED | _KIND_WILD,
        _KIND_FUNC_ARG: _KIND_FUNC_ARG | _KIND_LOCAL |  _KIND_WILD,
        _KIND_LOCAL:    _KIND_FUNC_ARG | _KIND_LOCAL | _KIND_WILD,
        _KIND_WILD:    _KIND_GLOBAL | _KIND_ALIASED | _KIND_FUNC_ARG | _KIND_LOCAL | _KIND_WILD,
    }

    class PhiCongruenceClass(InsertionOrderedSet[Variable]):
        __slots__ = ("repr", "kind")

        def __init__(
            self,
            iterable: Optional[Iterable[Variable]] = None,
            repr: Optional[Variable] = None,
            kind: Optional[int] = None,
            **kwargs: Any,
        ):
            self.repr = repr
            self.kind = kind if kind is not None else SreedharOutOfSSA._KIND_LOCAL
            super().__init__(iterable, **kwargs)


        # This is required to enable the use of rpc - {rhs} during copy removal.
        def __sub__(self, other):
            result = type(self)(super().__sub__(other))
            result.repr = self.repr
            result.kind = self.kind  
            return result

    class PhiCongruenceMap:
        def __init__(self, function_arg_names: Set[str]):
            self._function_arg_names = function_arg_names
            self._element_to_class: dict[Variable, SreedharOutOfSSA.PhiCongruenceClass] = {}

        def get_elements(self) -> Iterable[Variable]:
            return self._element_to_class.keys()

        def get_class(self, element: Variable) -> SreedharOutOfSSA.PhiCongruenceClass:
            return self._element_to_class[element]

        def _get_var_kind(self, var: Variable) -> int:
            if isinstance(var, GlobalVariable):
                return SreedharOutOfSSA._KIND_GLOBAL
            if getattr(var, "is_aliased", False):
                return SreedharOutOfSSA._KIND_ALIASED
            if var.name in self._function_arg_names:
                return SreedharOutOfSSA._KIND_FUNC_ARG

            tags = getattr(var, "tags", None)
            if tags and tags[0].name == "sreedhar_var_tag" and tags[0].data == "wild":
                return SreedharOutOfSSA._KIND_WILD

            return SreedharOutOfSSA._KIND_LOCAL

        def create_class(self, var: Variable) -> None:
            if var not in self._element_to_class:
                kind = self._get_var_kind(var)
                has_repr = kind >= SreedharOutOfSSA._KIND_FUNC_ARG
                self._element_to_class[var] = SreedharOutOfSSA.PhiCongruenceClass(
                    [var],
                    repr=var if has_repr else None,
                    kind=kind
                )

        def nullify_singletons(self) -> None:
            for v in self._element_to_class.values():
                if len(v) == 1:
                    v.clear()

        def merge_classes(self, elements: Iterable[Variable]) -> Optional[SreedharOutOfSSA.PhiCongruenceClass]:
            elements_list = list(elements)
            if not elements_list:
                return None

            classes = list({id(self.get_class(e)): self.get_class(e) for e in elements_list}.values())
            master_class = max(classes, key=lambda c: len(c))
            for current_class in classes:
                if current_class is master_class:
                    continue

                for member in current_class:
                    self._element_to_class[member] = master_class

                master_class.update(current_class)
                if current_class.kind > master_class.kind:
                    master_class.kind = current_class.kind
                    master_class.repr = current_class.repr

            for e in elements_list:
                self._element_to_class[e] = master_class
                master_class.add(e)

            return master_class

        def generate_renaming_map(self, name_handler: NameHandler) -> dict[Variable, Variable]:
            groups: dict[int, tuple[Optional[Variable], list[Variable]]] = {}
            for k, v in self._element_to_class.items():
                entry = groups.get(id(v))
                if entry is None:
                    groups[id(v)] = entry = (v.repr, [])

                entry[1].append(k)

            renaming_map: dict[Variable, Variable] = {}
            for repr, members in groups.values():
                repr = members[0] if repr is None else repr
                group_name = name_handler.get_name(repr.name)
                rep_type = repr.type
                rep_aliased = repr.is_aliased

                if isinstance(repr, GlobalVariable):
                    rep_initial_value = repr.initial_value
                    rep_constant = repr.is_constant
                    for var in members:
                        renaming_map[var] = GlobalVariable(
                            name=group_name, vartype=rep_type, initial_value=rep_initial_value,
                            is_aliased=rep_aliased, ssa_name=var, is_constant=rep_constant,
                            tags=var.tags, origin=var.origin,
                        )
                else:
                    for var in members:
                        renaming_map[var] = Variable(
                            name=group_name, vartype=rep_type, is_aliased=rep_aliased,
                            ssa_name=var, tags=var.tags, origin=var.origin,
                        )
            return renaming_map

    class AssignmentHelper:
        __slots__ = ("after_phis", "block_assigns", "before_branch")
        def __init__(self):
            self.after_phis: InsertionOrderedSet[Assignment] = InsertionOrderedSet()
            self.block_assigns: InsertionOrderedSet[Assignment] = InsertionOrderedSet()
            self.before_branch: InsertionOrderedSet[Assignment] = InsertionOrderedSet()

        def get_all_assigns(self) -> Generator[Assignment, None, None]:
            yield from self.after_phis
            yield from self.block_assigns
            yield from self.before_branch

    class OriginMap:
        __slots__ = ("dest_bb", "req_map")
        def __init__(self):
            self.dest_bb: BasicBlock | None = None
            self.req_map: dict[Variable | Constant, list[BasicBlock | None]] = defaultdict(list)

        def substitute_req(self, old_req: Variable | Constant, req: Variable | Constant) -> None:
            if old_req != req and old_req in self.req_map:
                self.req_map[req] = self.req_map.pop(old_req)

    class Resource(NamedTuple):
        var: Variable
        block: BasicBlock | None

    def __init__(self, task: DecompilerTask, debug_check = True):
        self._task = task
        self._debug_check = debug_check
        self._name_handler = NameHandler()
        self._cfg: ControlFlowGraph = cast(ControlFlowGraph, task.cfg)
        self._interference_graph = InterferenceGraph(self._cfg)
        self._phi_to_orig_map: dict[int, SreedharOutOfSSA.OriginMap] = {}
        self._block_to_phi: dict[BasicBlock, list[Phi]] = defaultdict(list)
        self._assignment_helpers: dict[BasicBlock, SreedharOutOfSSA.AssignmentHelper] = defaultdict(self.AssignmentHelper)
        
        function_arg_names = {var.name for var in self._task.function_parameters}
        self._phi_congruence_map = self.PhiCongruenceMap(function_arg_names)

        # Init maps
        all_vars = set()
        global_vars_by_name: dict[str, set[Variable]] = defaultdict(set)
        for block in self._cfg:
            for instr in block.instructions:
                for v in instr.definitions + instr.requirements:
                    all_vars |= {v}
                    self._name_handler.register_ssa_var(v)
                    self._phi_congruence_map.create_class(v)

                    if isinstance(v, GlobalVariable):
                        global_vars_by_name[v.name].add(v)

                match instr:
                    case Relation(destination=dest, value=val):
                        self._phi_congruence_map.merge_classes([dest, val])

                    case Phi() as phi:
                        self._block_to_phi[block].append(phi)

                        origin_map = self.OriginMap()
                        origin_map.dest_bb = block

                        for o_block, req in phi.origin_block.items():
                            if req:
                                origin_map.req_map[req].append(o_block)

                        for req in phi.requirements:
                            if req not in origin_map.req_map:
                                origin_map.req_map[req] = [None]

                        self._phi_to_orig_map[id(phi)] = origin_map

                    case Assignment(destination=Variable(), value=Variable()):
                        self._assignment_helpers[block].block_assigns.add(instr)
        
        # Merge all globals with the same name
        for name_group in global_vars_by_name.values():
           if len(name_group) < 2:
               continue

           sorted_group = sorted(name_group, key=lambda v: v.ssa_label)
           anchor = sorted_group[0]
           merged_class = self._phi_congruence_map.get_class(anchor)

           for var in sorted_group[1:]:
               var_class = self._phi_congruence_map.get_class(var)
               if var_class is merged_class:
                    continue

               merged_class = self._phi_congruence_map.merge_classes([anchor, var])

        # Find latest SSA version of function arguments
        func_args: dict[str, Variable] = {}
        for var in all_vars:
            if var.name in function_arg_names:
                if var.name not in func_args or var.ssa_label < func_args[var.name].ssa_label:
                    func_args[var.name] = var
 
        # Add edges between function args
        self._interference_graph.add_edges_from((
            itertools.combinations(func_args.values(),2)
        ))

        # Init liveness sets
        liveness = LivenessAnalysis(self._cfg)
        self._live_in: dict[BasicBlock | None, set[Variable]] = {}
        self._live_out: dict[BasicBlock | None, set[Variable]] = {}

        self._live_out[None] = liveness.live_out_of(None) #type: ignore
        for block in self._cfg:
            self._live_in[block] = liveness.live_in_of(block) #type: ignore
            self._live_out[block] = liveness.live_out_of(block) #type: ignore

        # debug tracker
        if self._debug_check:
            self._global_var_names = set()
            for var in all_vars:
                if isinstance(var, GlobalVariable):
                    self._global_var_names.add(var.name)

    def _is_live_in_context(self, var_class: PhiCongruenceClass, block: BasicBlock | None, is_dest: bool) -> bool:
        liveness_set = self._live_in.get(block, set()) if is_dest else self._live_out.get(block, set())
        return not var_class.isdisjoint(liveness_set)

    def _can_merge_classes(self, a: SreedharOutOfSSA.PhiCongruenceClass, b: SreedharOutOfSSA.PhiCongruenceClass) -> bool:
        if not (self._ALLOWED_MERGES[a.kind] & b.kind):
            return False
            
        if a.kind == b.kind and (a.kind & self._NAME_CHECK_MASK):
            return a.repr.name == b.repr.name #type: ignore
            
        return True

    def _classes_interfere(self, a: SreedharOutOfSSA.PhiCongruenceClass, b: SreedharOutOfSSA.PhiCongruenceClass) -> bool:
        if a is b:
            return False

        if not self._can_merge_classes(a, b):
            return True
    
        for y_i in a:
            if not self._interference_graph.has_node(y_i):
                return False

            neighbors = self._interference_graph[y_i]
            if not b.isdisjoint(neighbors):
                return True

        return False

    def _classify_pair(
        self, 
        r_i: SreedharOutOfSSA.Resource, r_j: SreedharOutOfSSA.Resource, 
        dest: SreedharOutOfSSA.Resource,
        candidates: InsertionOrderedSet[SreedharOutOfSSA.Resource], 
        unresolved: dict[SreedharOutOfSSA.Resource, set[SreedharOutOfSSA.Resource]]
    ) -> None:

        x_i, x_j = r_i.var, r_j.var
        l_i, l_j = r_i.block, r_j.block
        c_i, c_j = self._phi_congruence_map.get_class(x_i), self._phi_congruence_map.get_class(x_j)

        if not self._classes_interfere(c_i, c_j):
           return 

        cond_1 = self._is_live_in_context(c_j, l_i, x_i is dest)
        cond_2 = self._is_live_in_context(c_i, l_j, x_j is dest)

        if not cond_1 and cond_2:
            candidates.add(r_i)
        elif cond_1 and not cond_2:
            candidates.add(r_j)
        elif cond_1 and cond_2:
            candidates.update((r_i, r_j))
        else:
            unresolved[r_i].add(r_j)
            unresolved[r_j].add(r_i)

    def _resolve_unresolved_neighbors(self, 
        candidates: InsertionOrderedSet[SreedharOutOfSSA.Resource], 
        unresolved: dict[SreedharOutOfSSA.Resource, set[SreedharOutOfSSA.Resource]]) -> None:

        resolved: set[SreedharOutOfSSA.Resource] = set()
        for x in sorted(unresolved.keys(), key=lambda k: len(unresolved[k]), reverse=True):
            if not unresolved[x].issubset(resolved): # es gibt eine die ich durch einfügen von x löse
                candidates.add(x)
                resolved.add(x)

        for x in list(resolved):
            if unresolved[x].issubset(resolved):
                candidates.discard(x)

    def _create_copy_var(self, original: Variable) -> Variable:
        ret = Variable(
            name=self._PHI_COPY_NAME, vartype=original.type,
            ssa_label=self._name_handler.get_ssa_label(self._PHI_COPY_NAME), is_aliased=False,
            tags=(Tag("sreedhar_var_tag", data="wild"),)
        )

        return ret

    def _insert_dest_copy(self, phi: Phi, x: Variable, x_new: Variable) -> None:
        orig_block = self._phi_to_orig_map[id(phi)].dest_bb
        if orig_block is None:
            return

        phi.rename_destination(x, x_new)
        self._assignment_helpers[orig_block].after_phis.add(Assignment(x, x_new))

        self._live_in[orig_block].discard(x)
        self._live_in[orig_block].add(x_new)
        self._interference_graph.add_edges_from((x_new, v) for v in self._live_in[orig_block] if x_new is not v)

    def _insert_req_copy(self, phi: Phi, x: Variable, x_new: Variable) -> None:
        for orig_block in self._phi_to_orig_map[id(phi)].req_map[x]:
            if orig_block is None:
                orig_block = self._cfg.create_block([])
                self._live_in[orig_block] = set()
                self._live_out[orig_block] = set()
                phi_block = cast(BasicBlock, self._phi_to_orig_map[id(phi)].dest_bb)
                self._cfg.add_edge(UnconditionalEdge(orig_block, phi_block)) 
                if phi_block is self._cfg.root:
                    self._cfg.root = orig_block

            phi.substitute(x, x_new)
            self._phi_to_orig_map[id(phi)].substitute_req(x, x_new)
            self._assignment_helpers[orig_block].before_branch.add(Assignment(x_new, x))

            self._live_out[orig_block].add(x_new)
            
            # Remove x from live_out if it's no longer needed in successors
            if all(x not in self._live_in[succ] and 
                   all(p.origin_block.get(orig_block) != x for p in self._block_to_phi[succ]) 
                   for succ in self._cfg.get_successors(orig_block)):
                self._live_out[orig_block].discard(x)

            self._interference_graph.add_edges_from((x_new, v) for v in self._live_out[orig_block] if x_new is not v)

    def _eliminate_phi_resource_interference(self) -> None:
        for phi in itertools.chain.from_iterable(self._block_to_phi.values()): 
            unresolved = {}
            candidates = InsertionOrderedSet()
            dest = self.Resource(cast(Variable, phi.destination), self._phi_to_orig_map[id(phi)].dest_bb)

            unresolved[dest] = set()
            for req in phi.requirements:
                for b in self._phi_to_orig_map[id(phi)].req_map[req]:
                    unresolved[self.Resource(req, b)] = set()

            for r_i, r_j in itertools.combinations(unresolved.keys(), 2):
                self._classify_pair(r_i, r_j, dest, candidates, unresolved)

            self._resolve_unresolved_neighbors(candidates, unresolved)
            
            for r in candidates:
                x = r.var
                x_new = self._create_copy_var(x)
                self._phi_congruence_map.create_class(x_new)

                if r is dest:
                    self._insert_dest_copy(phi, x, x_new)
                else:
                    self._insert_req_copy(phi, x, x_new)

            k = [cast(Variable,phi.destination)] + [r for r in phi.requirements]
            self._debug_check_phi_classes_interference(k)

            m = self._phi_congruence_map.merge_classes(k)
            if m and not m.repr:
                m.repr = cast(Variable, phi.destination)

        self._phi_congruence_map.nullify_singletons()

    def _can_remove_copy(self, lhs: Variable, rhs: Variable, lpc: PhiCongruenceClass, rpc: PhiCongruenceClass) -> bool:
        # we return false so we skip an unecessary merge
        if lpc is rpc:
            return False 

        if not lpc and not rpc:
            return self._can_merge_classes(lpc, rpc)

        # Note we keep repr and kind for the PhiCongruenceClass here on purpose since they are used for _can_merge_classes
        if not lpc:
            return not self._classes_interfere(rpc - {rhs}, self.PhiCongruenceClass({lhs}, repr=lpc.repr, kind=lpc.kind))

        if not rpc:
            return not self._classes_interfere(lpc - {lhs}, self.PhiCongruenceClass({rhs}, repr=rpc.repr, kind=rpc.kind))

        c_rpc, c_lpc = rpc - {rhs}, lpc - {lhs}
        return not self._classes_interfere(lpc, c_rpc) and not self._classes_interfere(rpc, c_lpc)

    def _copy_removal(self) -> None:
        for helper in self._assignment_helpers.values():
            for assign in helper.get_all_assigns():
                if isinstance(assign.destination, Variable) and isinstance(assign.value, Variable):
                    lpc = self._phi_congruence_map.get_class(assign.destination)
                    rpc = self._phi_congruence_map.get_class(assign.value)
                    if self._can_remove_copy(assign.destination, assign.value, lpc, rpc):
                        self._phi_congruence_map.merge_classes([assign.destination, assign.value])


    def _process_and_rename(self, instrs: Iterable[Instruction], renaming_map: dict[Variable, Variable]) -> Generator[Instruction, None, None]:
        for instr in instrs:
            if isinstance(instr, (Phi, Relation)):
                continue

            for var in instr.definitions + instr.requirements:
                if r_var := renaming_map.get(var):
                    instr.substitute(var, r_var)

            # Skip tautological assignments (e.g. x = x)
            if isinstance(instr, Assignment) and isinstance(instr.destination, Variable) and isinstance(instr.value, Variable):
                if instr.destination.name == instr.value.name:
                    continue

            yield instr

    def _variable_rename(self) -> None:
        renaming_map = self._phi_congruence_map.generate_renaming_map(self._name_handler)

        for bb in self._cfg:
            has_branch = bool(bb.instructions) and isinstance(bb.instructions[-1], GenericBranch)
            branch_instr = bb.instructions[-1] if has_branch else None
            core_instrs = bb.instructions[:-1] if has_branch else bb.instructions
            helper = self._assignment_helpers[bb]
            
            new_instructions: list[Instruction] = []
            new_instructions.extend(self._process_and_rename(helper.after_phis, renaming_map))
            new_instructions.extend(self._process_and_rename(core_instrs, renaming_map))
            new_instructions.extend(self._process_and_rename(helper.before_branch, renaming_map))

            if branch_instr:
                # Branch instructions just need variables substituted, never discarded
                for var in branch_instr.definitions + branch_instr.requirements:
                    if r_var := renaming_map.get(var):
                        branch_instr.substitute(var, r_var)
                new_instructions.append(branch_instr)

            bb.instructions = new_instructions

    def _debug_check_phi_classes_interference(self, k: List[Variable]):
        if not self._debug_check:
            return 

        for a, b in itertools.combinations(k, 2):
            c_a = self._phi_congruence_map.get_class(a)
            c_b = self._phi_congruence_map.get_class(b)

            if self._classes_interfere(c_a, c_b):
                raise AssertionError(
                    f"The classes of two elements in a phi function interfere after lifting: {a} and {b}"
                )

    def _debug_check_phi_classes_content(self) -> None:
        if not self._debug_check:
            return

        classes_by_id: dict[int, list[Variable]] = defaultdict(list)
        for k, v in self._phi_congruence_map._element_to_class.items():
            tags = getattr(k, "tags", None)
            if not (tags and tags[0].name == "sreedhar_var_tag"):
                classes_by_id[id(v)].append(k)

        for phi_class in classes_by_id.values():
            if not phi_class:
                continue

            #  Validate Global Variables
            globals_in_class = [v for v in phi_class if isinstance(v, GlobalVariable)]
            if globals_in_class:
                first_global = globals_in_class[0]
                for v in phi_class:
                    if not isinstance(v, GlobalVariable):
                        raise AssertionError(
                            f"Global variable mixed with non-global variable in congruence class: {phi_class}"
                        )
                    if v.name != first_global.name:
                        raise AssertionError(
                            f"Different global names in same congruence class: {phi_class}"
                        )

            #  Validate Aliased Variables
            aliased_in_class = [v for v in phi_class if v.is_aliased]
            if aliased_in_class:
                first_aliased = aliased_in_class[0]
                for v in phi_class:
                    if not v.is_aliased:
                        raise AssertionError(
                            f"Aliased variable mixed with non-aliased variable in congruence class: {phi_class}"
                        )
                    if v.name != first_aliased.name:
                        raise AssertionError(
                            f"Different aliased names in same congruence class: {phi_class}"
                        )

    def _debug_check_global_var_count(self):
        if not self._debug_check:
            return

        global_var_names = set()

        for instr in self._cfg.instructions:
            for v in instr.definitions + instr.requirements:
                if isinstance(v, GlobalVariable):
                    global_var_names.add(v.name)

        if self._global_var_names != global_var_names:
            raise AssertionError(
                f"Amount of global variables changed {self._global_var_names} -> {global_var_names}"
            )

    def perform(self) -> None:
        self._eliminate_phi_resource_interference()
        self._copy_removal()
        self._debug_check_phi_classes_content()
        self._variable_rename()
        self._debug_check_global_var_count()
