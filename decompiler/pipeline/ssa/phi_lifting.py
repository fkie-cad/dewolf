"""Module for removing Phi-functions by lifting in Out of SSA."""

from typing import DefaultDict, Dict, Iterator, List, Optional, Set, Tuple

from decompiler.pipeline.commons.livenessanalysis import LivenessAnalysis
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, UnconditionalEdge
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo.expressions import Constant, Expression, Variable
from decompiler.structures.pseudo.instructions import Assignment, GenericBranch, Phi
from decompiler.util.insertion_ordered_set import InsertionOrderedSet


class PhiFunctionLifter:
    """This class is in charge of removing the Phi-functions by lifting."""

    def __init__(
        self,
        cfg: ControlFlowGraph,
        interference_graph: InterferenceGraph,
        phi_functions: DefaultDict[BasicBlock, List[Phi]],
        move_copies_before_branch: bool = False,
    ):
        """
        :param cfg: The control flow graph whose phi-functions we want to lift
        :param interference_graph: In interference graph of the given control-flow graph
        :param phi_functions: A dictionary that maps to each basic block its list of Phi-functions.
        :param move_copies_before_branch: If set, the copies of a conditional edge are placed before the branch of the predecessor
            instead of a new basic block on the edge, whenever this is correct. This needs an exact liveness analysis, i.e.,
            the program must still be in SSA-form.
        """
        self._cfg = cfg
        self.interference_graph = interference_graph
        self._phi_functions_of: DefaultDict[BasicBlock, List[Phi]] = phi_functions
        self._move_copies_before_branch = move_copies_before_branch

    def lift(self) -> None:
        """
        This function removes the Phi functions by lifting their information to the predecessors of the basic block that contains the
        Phi-function that we want to lift.

        - If the edge between the predecessor block and the basic block is unconditional, we add the copies at the end of the predecessor.
        - If the edge is conditional, we add the copies before the branch of the predecessor if this is correct
          (see _get_assignments_before_branch), and otherwise we insert a new basic block on the edge.
        - The same holds if the predecessor is an empty block on a conditional edge (e.g., an empty latch of a loop): then we add the copies
          before the branch of its predecessor if this is correct, and otherwise to the empty block.
        """
        self._liveness = LivenessAnalysis(self._cfg)
        self._live_in_of = {
            basic_block: self._live_after_phi_functions(basic_block, self._liveness) for basic_block in self._phi_functions_of
        }
        assignments_on_edge: Dict[Tuple[Optional[BasicBlock], BasicBlock], List[Assignment]] = {
            (predecessor, basic_block): self._compute_instructions_for(predecessor, basic_block)
            for basic_block in self._phi_functions_of
            for predecessor in self._get_predecessors(basic_block)
        }
        assignments_before_branch = self._get_assignments_before_branch(assignments_on_edge) if self._move_copies_before_branch else dict()
        moved_assignments_on_edge = {edge: moved for pairs in assignments_before_branch.values() for edge, moved in pairs}
        successors_of = {branch_block: list(self._cfg.get_successors(branch_block)) for branch_block in assignments_before_branch}

        live_on_split_edge: Dict[Tuple[Optional[BasicBlock], BasicBlock], InsertionOrderedSet[Variable]] = dict()
        for basic_block in self._phi_functions_of:
            for predecessor in self._get_predecessors(basic_block):
                new_instructions = [
                    copy
                    for copy in assignments_on_edge[(predecessor, basic_block)]
                    if copy not in moved_assignments_on_edge.get((predecessor, basic_block), [])
                ]
                if new_instructions:
                    live_on_split_edge[(predecessor, basic_block)] = self._lift_to_edge(predecessor, basic_block, new_instructions)
            self._remove_phi_instructions_of(basic_block)

        for branch_block, moved in assignments_before_branch.items():
            self._lift_before_branch(branch_block, moved, successors_of[branch_block], live_on_split_edge)

    def _lift_to_edge(
        self, predecessor: Optional[BasicBlock], basic_block: BasicBlock, new_instructions: List[Assignment]
    ) -> InsertionOrderedSet[Variable]:
        """
        Adds the copies of the edge predecessor -> basic_block at the end of the predecessor if the edge is unconditional, and otherwise
        to a new basic block on the edge. Adds the interferences of the copies and returns the set of variables live before the copies.
        """
        edge = self._cfg.get_edge(predecessor, basic_block)
        if predecessor is not None and isinstance(edge, UnconditionalEdge):
            predecessor.instructions.extend(new_instructions)
        else:
            new_basic_block = self._insert_basic_block_before(basic_block, new_instructions)
            if predecessor:
                self._cfg.substitute_edge(edge, edge.copy(sink=new_basic_block))
            else:
                self._cfg.root = new_basic_block
        return self.interference_graph.update_for_instruction_sequence(new_instructions, self._live_in_of[basic_block])

    def _get_assignments_before_branch(
        self, assignments_on_edge: Dict[Tuple[Optional[BasicBlock], BasicBlock], List[Assignment]]
    ) -> Dict[BasicBlock, List[Tuple[Tuple[BasicBlock, BasicBlock], List[Assignment]]]]:
        """
        Decides which copies we place before the branch of a block instead of on the edge (i.e., in a new basic block on the edge).

        :param assignments_on_edge: The sequentialized copies of each edge (P, B), where B contains the Phi-functions.
        :return: For each block Q whose branch gets copies, a list of pairs ((P, B), M): the copies M of the edge (P, B) are placed
            before the branch of Q. Usually Q = P; if P is an empty block, Q is its predecessor (see _get_branch_of).

        Which edges: only back-edges, i.e., B dominates Q. Then Q is the latch of the loop with head B, and with the copies before its
        branch the loop ends with its condition (do-while). We skip all other edges, because Q may be a loop head, whose branch should
        stay alone in its block to get a while-loop with condition. For the same reason, we skip Q if it is also the head of an inner loop.

        When it is correct: the copies before the branch are executed on every outgoing edge of Q, not only on the way to B. So
        - the branch condition of Q must not read a destination of the copies, and
        - no destination may be live on any other edge Q -> S', i.e., it is neither live-in of S' (except as a Phi-definition of S'),
          nor an argument of a Phi-function of S' for Q.
        Several edges can place their copies before the same branch if their destinations are disjoint (in SSA-form they always are).

        Which copies of an edge: usually all or none. If some copies have to stay on the edge, its basic block remains anyway, and
        moving the other copies would only add interferences. The exception are copies that stay on the edge only because moving them
        would prevent coalescing: they probably vanish during renaming, so the edge becomes empty. Then we move the other copies
        (see _get_copies_to_move).
        """
        assignments_before_branch: Dict[BasicBlock, List[Tuple[Tuple[BasicBlock, BasicBlock], List[Assignment]]]] = dict()
        moved_destinations: Dict[BasicBlock, Set[Variable]] = dict()
        for (predecessor, basic_block), copies in assignments_on_edge.items():
            if not copies or (branch_block := self._get_branch_of(predecessor, basic_block)) is None:
                continue
            successor_on_path = self._successor_on_path(branch_block, (predecessor, basic_block))
            if not self._cfg.is_dominating(basic_block, branch_block) or self._is_head_of_other_loop(branch_block, basic_block):
                continue
            live_at_branch = set(branch_block.instructions[-1].requirements).union(
                *(
                    self._live_on_edge(branch_block, successor)
                    for successor in self._cfg.get_successors(branch_block)
                    if successor != successor_on_path
                )
            )
            destinations = {copy.destination for copy in copies}
            if destinations & live_at_branch or destinations & moved_destinations.get(branch_block, set()):
                continue
            if not (moved_copies := self._get_copies_to_move(copies, live_at_branch)):
                continue
            assignments_before_branch.setdefault(branch_block, []).append(((predecessor, basic_block), moved_copies))
            moved_destinations.setdefault(branch_block, set()).update(copy.destination for copy in moved_copies)
        return assignments_before_branch

    def _get_copies_to_move(self, copies: List[Assignment], live_at_branch: Set[Variable]) -> List[Assignment]:
        """
        Returns the copies of the edge that we move before the branch: all copies except the ones that would prevent coalescing.
        The copies that stay on the edge are executed after the moved ones, so they must not read a destination of a moved copy. This holds
        because they read a variable that is live at the branch, and no destination of the edge is live at the branch.
        """
        return [copy for copy in copies if not self._prevents_coalescing(copy, live_at_branch)]

    def _is_head_of_other_loop(self, branch_block: BasicBlock, loop_head: BasicBlock) -> bool:
        """
        Checks whether branch_block is the head of a loop other than the loop of loop_head, i.e., it has an incoming back-edge (it dominates
        one of its predecessors). Then its branch is the condition of this (inner) loop, which should stay alone in the block.
        A single-block loop (branch_block == loop_head) is fine, its branch is the do-while condition.
        Irreducible loops are not detected; this only affects the structure of the output, not correctness.
        """
        if branch_block == loop_head:
            return False
        return any(self._cfg.is_dominating(branch_block, predecessor) for predecessor in self._cfg.get_predecessors(branch_block))

    def _prevents_coalescing(self, copy: Assignment, live_at_branch: Set[Variable]) -> bool:
        """
        Checks whether moving the copy 'd = s' before the branch would prevent that renaming removes it.

        The copy vanishes if renaming gives d and s the same name, which needs that they do not interfere. Before the branch, d
        interferes with every variable that is live at the branch. So if s is still live there and did not interfere with d before,
        moving the copy creates this interference. Example: in 'i#3 = i#2 + 1; if (i#3 < 10)' with the back-edge copy 'i#2 = i#3', the
        copy on the edge vanishes (both become i), but before the branch it stays, because the condition reads i#3 after the copy.
        Temporaries that break cycles are not in the interference graph yet; they always interfere with their source, so they are fine.
        """
        destination, source = copy.destination, copy.value
        if not isinstance(source, Variable) or source not in live_at_branch or destination not in self.interference_graph:
            return False
        return not self.interference_graph.has_edge(destination, source)

    def _get_branch_of(self, predecessor: Optional[BasicBlock], basic_block: BasicBlock) -> Optional[BasicBlock]:
        """
        Returns the block Q whose branch decides whether we take the edge predecessor -> basic_block, or None if there is no such branch:
        - If the edge is conditional, then Q is the predecessor.
        - If the predecessor is an empty block with one predecessor and one successor (e.g., an empty latch of a loop), then Q is the
          predecessor of the empty block, provided it ends with a branch.
        """
        if predecessor is None:
            return None
        if not isinstance(self._cfg.get_edge(predecessor, basic_block), UnconditionalEdge):
            branch_block = predecessor
        elif not predecessor.instructions and self._cfg.in_degree(predecessor) == 1 and self._cfg.out_degree(predecessor) == 1:
            branch_block = next(iter(self._cfg.get_predecessors(predecessor)))
            if branch_block == predecessor:
                return None
        else:
            return None
        if not branch_block.instructions or not isinstance(branch_block.instructions[-1], GenericBranch):
            return None
        return branch_block

    @staticmethod
    def _successor_on_path(branch_block: BasicBlock, edge: Tuple[BasicBlock, BasicBlock]) -> BasicBlock:
        """
        Returns the successor of branch_block on the way to the edge (P, B), where branch_block is the result of _get_branch_of:
        B if branch_block is P (conditional edge), and otherwise the empty block P.
        """
        predecessor, basic_block = edge
        return basic_block if predecessor == branch_block else predecessor

    def _live_on_edge(self, predecessor: BasicBlock, successor: BasicBlock) -> Set[Variable]:
        """Returns the variables that are live on the edge predecessor -> successor in SSA-form, including the Phi-arguments of successor."""
        live = set(self._liveness.live_in_of(successor)) - set(self._liveness.defs_phi_of(successor))
        for phi in self._phi_functions_of.get(successor, []):
            if isinstance(value := phi.origin_block.get(predecessor), Variable):
                live.add(value)
        return live

    def _lift_before_branch(
        self,
        branch_block: BasicBlock,
        moved: List[Tuple[Tuple[BasicBlock, BasicBlock], List[Assignment]]],
        successors: List[BasicBlock],
        live_on_split_edge: Dict[Tuple[Optional[BasicBlock], BasicBlock], InsertionOrderedSet[Variable]],
    ) -> None:
        """
        Places the moved copies of the given edges before the branch of branch_block and adds their interferences.
        After the copies, the requirements of the branch are live as well as everything that is live on any outgoing edge. On the edge
        of moved copies, this is the live set before the copies that stay on this edge, if any, and otherwise LiveIn of the Phi-block.
        """
        new_instructions = [copy for _, moved_copies in moved for copy in moved_copies]
        branch_block.instructions[-1:-1] = new_instructions

        edge_reached_by = {self._successor_on_path(branch_block, edge): edge for edge, _ in moved}
        live_after = InsertionOrderedSet(branch_block.instructions[-1].requirements)
        for successor in successors:
            if successor in edge_reached_by:
                key = edge_reached_by[successor]
                live_after.update(live_on_split_edge[key] if key in live_on_split_edge else self._live_in_of[key[1]])
            elif (branch_block, successor) in live_on_split_edge:
                live_after.update(live_on_split_edge[(branch_block, successor)])
            elif successor in self._phi_functions_of:
                live_after.update(self._live_in_of[successor])
            else:
                live_after.update(self._liveness.live_in_of(successor))
        self.interference_graph.update_for_instruction_sequence(new_instructions, live_after)

    @staticmethod
    def _live_after_phi_functions(basic_block: BasicBlock, liveness: LivenessAnalysis) -> InsertionOrderedSet[Variable]:
        """
        Returns the variables that are live directly after the Phi-functions of the basic block, i.e., after lifting, at the end of each
        predecessor. LiveIn contains all Phi-definitions, so we remove the ones that are never used (dead Phi-definitions).
        """
        used_in_block = InsertionOrderedSet(
            variable for instruction in basic_block.instructions if not isinstance(instruction, Phi) for variable in instruction.requirements
        )
        dead_phi_definitions = liveness.defs_phi_of(basic_block) - used_in_block - liveness.live_out_of(basic_block)
        return InsertionOrderedSet(liveness.live_in_of(basic_block)) - dead_phi_definitions

    def _get_predecessors(self, basic_block: BasicBlock) -> Iterator[Optional[BasicBlock]]:
        """
        Returns all predecessors of the given basic block, i.e., all vertices where we have to lift the Phi-functions.

        -> Note, if a Phi-function is on top of the head, then one predecessor is None.
        """
        yield from list(self._cfg.get_predecessors(basic_block))
        if self._phi_functions_of[basic_block] and None in self._phi_functions_of[basic_block][0].origin_block:
            yield None

    def _insert_basic_block_before(self, basic_block: BasicBlock, new_instructions: List[Assignment]) -> BasicBlock:
        """
        Inserts a basic block before 'basic_block' that contains as instructions the list 'new_instructions'.
        Besides, we return the new added basic block.
        """
        new_basic_block = self._cfg.create_block(new_instructions)
        self._cfg.add_edge(UnconditionalEdge(new_basic_block, basic_block))
        return new_basic_block

    def _compute_instructions_for(self, predecessor: Optional[BasicBlock], basic_block: BasicBlock) -> List[Assignment]:
        """
        Computes the Assignments that we have to add to the basic block 'predecessor' when we lift the list of Phi-functions basic block
        `basic_block`.
        -> If the assignment would be 'a#2 = a#2' than we do not add this assignment.
        -> If the Phi-function is on top of the head and only has one predecessor, then we have to insert a new node before the head.
           In this case, the predecessor is None.

        The Phi-functions of a basic block are a parallel copy; for the given edge, _ParallelCopySequentializer turns it into a sequence.
        Copies of constants do not read anything, so we emit them last.

        :param predecessor: The basic block where we want to insert the Assignments.
        :param basic_block: The Basic block that contains the Phi-functions that we want to lift.
        :return: The list of Assignments that we add to the basic block 'predecessor'.
        """
        # Phi-definition -> its (non-constant) argument on this edge.
        argument_of: Dict[Variable, Expression] = dict()
        constant_copies: List[Assignment] = list()
        for phi_inst in self._phi_functions_of[basic_block]:
            definition = phi_inst.definitions[0]
            value = phi_inst.origin_block[predecessor]
            if definition == value:
                continue
            if isinstance(value, Constant):
                constant_copies.append(Assignment(definition, value))
            else:
                argument_of[definition] = value
        return _ParallelCopySequentializer(argument_of).sequentialize() + constant_copies

    def _remove_phi_instructions_of(self, basic_block: BasicBlock) -> None:
        """
        This function removes the Phi-functions of basic block 'basic_block' from the list of instructions.
        """
        for phi_inst in self._phi_functions_of[basic_block]:
            basic_block.remove_instruction(phi_inst)


class _ParallelCopySequentializer:
    """
    Turns a parallel copy {destination: source} into a sequence of assignments with the same effect.

    In the dependency graph every destination reads exactly one source, so each connected component is at most one cycle with trees
    pointing into it. The algorithm:
    1. Emit every copy 'd = s' whose destination d is free, i.e., no pending copy still reads the old value of d. This handles the trees
       from the leaves inwards: emitting 'd = s' removes a read of s, so s may become free.
    2. When no destination is free, the remaining copies are disjoint cycles. Break one cycle (see _break_a_cycle) and continue with 1.
    """

    def __init__(self, copies: Dict[Variable, Expression]):
        # Copies that are not emitted yet, destination -> source.
        self._pending: Dict[Variable, Expression] = dict(copies)
        # For every destination: how many pending copies still read its old value. It may be overwritten once this is 0.
        self._pending_reads: Dict[Variable, int] = {destination: 0 for destination in copies}
        for source in copies.values():
            if source in self._pending_reads:
                self._pending_reads[source] += 1
        # Destinations that can be written now, in the order in which they became free.
        self._free: List[Variable] = [destination for destination, reads in self._pending_reads.items() if reads == 0]
        # v -> x for an emitted copy 'x = v': x still holds the old value of v, because x is never written again.
        self._old_value_kept_in: Dict[Variable, Variable] = dict()
        self._sequence: List[Assignment] = list()

    def sequentialize(self) -> List[Assignment]:
        """
        Returns the copies as a sequence of assignments with the same effect as the parallel copy: free copies are emitted first, and
        whenever only cycles remain, one cycle is broken, until all copies are emitted.
        """
        while self._pending:
            self._emit_free_copies()
            self._break_a_cycle()
        return self._sequence

    def _emit_free_copies(self) -> None:
        """
        Emits all copies whose destination is free, in the order in which they became free. Emitting 'd = s' removes one pending read
        of s; if this was the last one, s becomes free as well. If s is a variable of the same type as d, d now keeps the old value of s,
        which _break_a_cycle can use instead of a temporary.
        """
        while self._free:
            destination = self._free.pop(0)
            source = self._pending.pop(destination)
            self._sequence.append(Assignment(destination, source))
            if isinstance(source, Variable) and source.type == destination.type:
                self._old_value_kept_in.setdefault(source, destination)
            if source in self._pending:
                self._pending_reads[source] -= 1
                if self._pending_reads[source] == 0:
                    self._free.append(source)

    def _break_a_cycle(self) -> None:
        """
        Pick a variable c of a cycle and let the one copy that reads c read its old value from somewhere else, so c becomes free:
        - preferably from x of an already emitted copy 'x = c' (no extra copy needed),
        - otherwise from a new temporary 'copy_c = c' that we emit now.
        If no copies are pending, there is no cycle and we do nothing.
        """
        if not self._pending:
            return
        cycle_variable = next((variable for variable in self._pending if variable in self._old_value_kept_in), next(iter(self._pending)))
        old_value = self._old_value_kept_in.get(cycle_variable)
        if old_value is None:
            old_value = Variable("copy_" + cycle_variable.name, cycle_variable.type, cycle_variable.ssa_label, cycle_variable.is_aliased)
            self._sequence.append(Assignment(old_value, cycle_variable))
        reader = next(destination for destination, source in self._pending.items() if source == cycle_variable)
        self._pending[reader] = old_value
        self._pending_reads[cycle_variable] = 0
        self._free.append(cycle_variable)
