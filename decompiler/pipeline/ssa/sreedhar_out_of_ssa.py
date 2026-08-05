from __future__ import annotations

import itertools
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Generator, Iterable, cast

from decompiler.pipeline.commons.livenessanalysis import LivenessAnalysis
from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.graphs.branches import UnconditionalEdge
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo.expressions import Constant, Expression, GlobalVariable, Tag, Variable
from decompiler.structures.pseudo.instructions import Assignment, GenericBranch, Instruction, Phi, Relation
from decompiler.task import DecompilerTask
from decompiler.util.insertion_ordered_set import InsertionOrderedSet

"""Sreedhar et. al. "Translating Out Of Static Single Assignment Form"""

@dataclass(slots=True)
class VarGroup:
    """Aggregates variable properties to generate mapped Out-of-SSA names and structures."""
    is_global: bool = False
    is_aliased: bool = False
    type: type | None = None
    name: str | None = None
    vars: list[Variable] = field(default_factory=list)
    initial_value: Expression | None = None
    tags: tuple[Tag, ...] | None = None 
    is_constant: bool | None = None


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
            instrs.insert(-1, instr)
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
            
            n_var = Variable(
                name="const",
                vartype=phi.destination.type,
                ssa_label=self._name_handler.get_ssa_label("const")
            )
            self._insert_before_branch(pred_bb.instructions, Assignment(n_var, con.copy()))
            phi.substitute(con, n_var)


class SreedharOutOfSSA:
    """Implements Sreedhar's Out-of-SSA algorithm to translate SSA form back to normal form."""

    _PHI_COPY_NAME = "phi_copy"

    class PhiCongruenceClass(InsertionOrderedSet[Variable]):
        pass

    class PhiCongruenceMap:
        def __init__(self):
            self._element_to_class: dict[Variable, SreedharOutOfSSA.PhiCongruenceClass] = {}

        def get_elements(self) -> Iterable[Variable]:
            return self._element_to_class.keys()

        def get_class(self, element: Variable) -> SreedharOutOfSSA.PhiCongruenceClass:
            return self._element_to_class[element]

        def create_class(self, representative: Variable) -> None:
            if representative not in self._element_to_class:
                self._element_to_class[representative] = SreedharOutOfSSA.PhiCongruenceClass([representative])

        def merge_classes(self, elements: Iterable[Variable]) -> SreedharOutOfSSA.PhiCongruenceClass | None:
            elements_list = list(elements)
            if not elements_list:
                return None

            master_class = self.get_class(elements_list[0])
            class_generator = (self.get_class(e) for e in elements_list)
            
            for current_class, e in zip(class_generator, elements_list, strict=True):
                if current_class is not master_class:
                    for member in current_class:
                        self._element_to_class[member] = master_class
                    master_class.update(current_class)
                
                self._element_to_class[e] = master_class
                master_class.add(e)

            return master_class

        def nullify_singletons(self) -> None:
            for v in self._element_to_class.values():
                if len(v) == 1:
                    v.clear()

        def generate_renaming_map(self, function_arg_names: set[str], name_handler: NameHandler) -> dict[Variable, Variable]:
            groups: dict[int, VarGroup] = defaultdict(VarGroup)
            
            for k, v in self._element_to_class.items():
                group = groups[id(v)]
                group.vars.append(k)
                
                if not group.name: 
                    if isinstance(k, GlobalVariable):
                        group.name, group.type = k.name, k.type
                        group.initial_value = k.initial_value
                        group.tags, group.is_constant = k.tags, k.is_constant
                        group.is_aliased, group.is_global = k.is_aliased, True

                    elif k.is_aliased:
                        group.name, group.type = k.name, k.type
                        group.is_aliased = k.is_aliased

                    elif k.name in function_arg_names:
                        group.name, group.type = k.name, k.type
                        group.is_aliased = k.is_aliased
                
            renaming_map: dict[Variable, Variable] = {}
            for group in groups.values():
                group.name = group.name or group.vars[0].name
                group.type = group.type or group.vars[0].type
                base_name = group.name if group.is_global or group.is_aliased else name_handler.get_name(group.name)
                    
                for v in group.vars:
                    if group.is_global:
                        new_var = GlobalVariable(
                            name=base_name, vartype=group.type, initial_value=group.initial_value, 
                            is_aliased=group.is_aliased, ssa_name=v, is_constant=group.is_constant, tags=group.tags,
                            origin=v.origin
                        )
                    else:
                        new_var = Variable(
                            name=base_name, vartype=group.type, is_aliased=group.is_aliased, ssa_name=v, tags=v.tags,
                            origin=v.origin
                        )
                    renaming_map[v] = new_var

            return renaming_map

    class AssignmentHelper:
        def __init__(self):
            self.after_phis: InsertionOrderedSet[Assignment] = InsertionOrderedSet()
            self.block_assigns: InsertionOrderedSet[Assignment] = InsertionOrderedSet()
            self.before_branch: InsertionOrderedSet[Assignment] = InsertionOrderedSet()

        def get_all_assigns(self) -> Generator[Assignment, None, None]:
            yield from self.after_phis
            yield from self.block_assigns
            yield from self.before_branch

    class OriginMap:
        def __init__(self):
            self.dest_bb: BasicBlock | None = None
            self.req_map: dict[Variable | Constant, list[BasicBlock | None]] = defaultdict(list)

        def substitute_req(self, old_req: Variable | Constant, req: Variable | Constant) -> None:
            if old_req != req and old_req in self.req_map:
                self.req_map[req] = self.req_map.pop(old_req)

    @dataclass(slots=True, frozen=True)
    class Resource:
        var: Variable
        block: BasicBlock | None

    def __init__(self, task: DecompilerTask, debug_check = True):
        self._task = task
        self._debug_check = debug_check
        self._cfg: ControlFlowGraph = cast(ControlFlowGraph, task.cfg)
        self._phi_congruence_map = self.PhiCongruenceMap()
        self._interference_graph = InterferenceGraph(self._cfg)
        self._live_in: dict[BasicBlock | None, set[Variable]] = {}
        self._live_out: dict[BasicBlock | None, set[Variable]] = {}
        
        self._phi_to_orig_map: dict[int, SreedharOutOfSSA.OriginMap] = {}
        self._block_to_phi: dict[BasicBlock, list[Phi]] = defaultdict(list)
        self._assignment_helpers: dict[BasicBlock, SreedharOutOfSSA.AssignmentHelper] = defaultdict(self.AssignmentHelper)
        
        self._name_handler = NameHandler()
        self._function_arg_names = {var.name for var in self._task.function_parameters}

        self._initialize_liveness()
        self._initialize_instructions_and_maps()


    def perform(self) -> None:
        self._init_interference_graph()
        self._eliminate_phi_resource_interference()
        self._copy_removal()
        self._debug_check_phi_classes()
        self._variable_rename()

    def _initialize_liveness(self) -> None:
        liveness = LivenessAnalysis(self._cfg)
        self._live_out[None] = liveness.live_out_of(None) 
        for block in self._cfg:
            self._live_in[block] = liveness.live_in_of(block)
            self._live_out[block] = liveness.live_out_of(block)

    def _initialize_instructions_and_maps(self) -> None:
        for block in self._cfg:
            for instr in block.instructions:

                for v in instr.definitions + instr.requirements:
                    self._name_handler.register_ssa_var(v)
                    self._phi_congruence_map.create_class(v)

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

    def _classes_interfere(self, a: PhiCongruenceClass, b: PhiCongruenceClass) -> bool:
        if a is b:
            return False

        return any(self._interference_graph.are_interfering(y_i, y_j) for y_i, y_j in itertools.product(a, b))

    def _init_interference_graph(self) -> None:
        all_vars = {
            var
            for instr in self._cfg.instructions
            for collection in (instr.definitions, instr.requirements)
            for var in collection
        }

        global_vars = [v for v in all_vars if isinstance(v, GlobalVariable)]
        local_vars = [v for v in all_vars if not isinstance(v, GlobalVariable)]

        aliased_vars = [v for v in all_vars if v.is_aliased]
        non_aliased_vars = [v for v in all_vars if not v.is_aliased]

        # Find latest SSA version of function arguments
        func_args: dict[str, Variable] = {}
        for var in all_vars:
            if var.name in self._function_arg_names:
                if var.name not in func_args or var.ssa_label < func_args[var.name].ssa_label:
                    func_args[var.name] = var

        edges = list(itertools.combinations(func_args.values(), 2))

        edges.extend(itertools.product(global_vars, local_vars))
        edges.extend((g1, g2) for g1, g2 in itertools.product(global_vars, global_vars) if g1 is not g2 and g1.name != g2.name)

        edges.extend(itertools.product(aliased_vars, non_aliased_vars))
        edges.extend((a1, a2) for a1, a2 in itertools.product(aliased_vars, aliased_vars) if a1 is not a2 and a1.name != a2.name)

        self._interference_graph.add_edges_from(edges)

    def _is_live_in_context(self, var_class: PhiCongruenceClass, block: BasicBlock | None, is_dest: bool) -> bool:
        """Returns True if the congruence class intersects with the block's relevant liveness set."""
        liveness_set = self._live_in.get(block, set()) if is_dest else self._live_out.get(block, set())
        return not var_class.isdisjoint(liveness_set)

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
            if not unresolved[x].issubset(resolved):
                candidates.add(x)
                resolved.add(x)

        for x in list(resolved):
            if unresolved[x].issubset(resolved):
                candidates.discard(x)

    def _create_copy_var(self, original: Variable) -> Variable:
        return Variable(
            name=self._PHI_COPY_NAME, vartype=original.type,
            ssa_label=self._name_handler.get_ssa_label(self._PHI_COPY_NAME), is_aliased=False
        )

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
                self._live_in[orig_block], self._live_out[orig_block] = set(), set()
                phi_block = self._phi_to_orig_map[id(phi)].dest_bb
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

        for phi in [i for i in self._cfg.instructions if isinstance(i, Phi)]:

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
            if self._debug_check:
                for a, b in itertools.combinations(k, 2):
                    if self._interference_graph.are_interfering(a, b):
                        raise AssertionError(
                            f"Two elements in a phi function interfere after lifting: {a} and {b}"
                        )

            self._phi_congruence_map.merge_classes(k)
        self._phi_congruence_map.nullify_singletons()

    def _can_remove_copy(self, lhs: Variable, rhs: Variable, lpc: PhiCongruenceClass, rpc: PhiCongruenceClass) -> bool:
        lhs_is_global = isinstance(lhs, GlobalVariable)
        rhs_is_global = isinstance(rhs, GlobalVariable)

        # If one is a GlobalVariable but the other isn't
        if lhs_is_global != rhs_is_global:
            return False

        # If both are GlobalVariables but names differ
        if lhs_is_global and rhs_is_global and lhs.name != rhs.name:
            return False

        # If one is a alisased but the other isn't
        if lhs.is_aliased != rhs.is_aliased:
            return False

        # If both are aliased but names differ
        if lhs.is_aliased and rhs.is_aliased and lhs.name != rhs.name:
            return False

        if lpc is rpc or (not lpc and not rpc):
            return True

        # Fast path single-empty class
        if not lpc:
            return not self._classes_interfere(SreedharOutOfSSA.PhiCongruenceClass(rpc - {rhs}), SreedharOutOfSSA.PhiCongruenceClass({lhs}))
        if not rpc:
            return not self._classes_interfere(SreedharOutOfSSA.PhiCongruenceClass(lpc - {lhs}), SreedharOutOfSSA.PhiCongruenceClass({rhs}))

        c_rpc, c_lpc = SreedharOutOfSSA.PhiCongruenceClass(rpc - {rhs}), SreedharOutOfSSA.PhiCongruenceClass(lpc - {lhs})
        return not self._classes_interfere(lpc, c_rpc) and not self._classes_interfere(rpc, c_lpc)

    def _copy_removal(self) -> None:
        for helper in self._assignment_helpers.values():
            for assign in helper.get_all_assigns():
                if isinstance(assign.destination, Variable) and isinstance(assign.value, Variable):
                    lpc = self._phi_congruence_map.get_class(assign.destination)
                    rpc = self._phi_congruence_map.get_class(assign.value)
                    if self._can_remove_copy(assign.destination, assign.value, lpc, rpc):
                        self._phi_congruence_map.merge_classes([assign.destination, assign.value])

    def _debug_check_phi_classes(self) -> None:
        if not self._debug_check:
            return

        classes_by_id: dict[int, list[Variable]] = defaultdict(list)
        for k, v in self._phi_congruence_map._element_to_class.items():
            classes_by_id[id(v)].append(k)

        for phi_class in classes_by_id.values():
            # Filter out phi_copy placeholders for strict identity checks
            real_vars = [v for v in phi_class if v.name != self._PHI_COPY_NAME]
            if not real_vars:
                continue

            # 1. Validate Globals
            globals_in_class = [v for v in real_vars if isinstance(v, GlobalVariable)]
            if globals_in_class:
                first_global = globals_in_class[0]
                for v in real_vars:
                    if not isinstance(v, GlobalVariable):
                        raise AssertionError(
                            f"Global variable mixed with non-global variable in congruence class: {phi_class}"
                        )
                    if v.name != first_global.name:
                        raise AssertionError(
                            f"Different global names in same congruence class: {phi_class}"
                        )

            # 2. Validate Aliased Variables
            aliased_in_class = [v for v in real_vars if v.is_aliased]
            if aliased_in_class:
                first_aliased = aliased_in_class[0]
                for v in real_vars:
                    if not v.is_aliased:
                        raise AssertionError(
                            f"Aliased variable mixed with non-aliased variable in congruence class: {phi_class}"
                        )
                    if v.name != first_aliased.name:
                        raise AssertionError(
                            f"Different aliased names in same congruence class: {phi_class}"
                        )

    def _process_and_rename(self, instrs: Iterable[Instruction], renaming_map: dict[Variable, Variable]) -> Generator[Instruction, None, None]:
        """Applies renaming in-place and yields instructions, skipping self-assignments and Phis/Relations."""
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
        renaming_map = self._phi_congruence_map.generate_renaming_map(self._function_arg_names, self._name_handler)

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
