"""Tests for the per-edge sequentialization of Phi-functions when lifting them (PhiFunctionLifter), and for the resulting interferences."""

import random
from typing import Dict, List, Optional, Union

import pytest
from decompiler.pipeline.ssa.phi_lifting import PhiFunctionLifter
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, TrueCase, UnconditionalEdge
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo import (
    Assignment,
    BinaryOperation,
    Branch,
    Call,
    Condition,
    Constant,
    ImportedFunctionSymbol,
    Integer,
    ListOperation,
    OperationType,
    Phi,
    Return,
    Variable,
)


def _var(name: str, label: int = 1, vartype=Integer.int32_t()) -> Variable:
    return Variable(name, vartype, label)


def _use(*variables) -> Assignment:
    return Assignment(ListOperation([]), Call(ImportedFunctionSymbol("use", 0), list(variables)))


def _reference_interferences(cfg: ControlFlowGraph):
    """
    Interferences of a program without Phi-functions that is not in SSA-form, computed by iterative liveness analysis per instruction:
    two variables interfere if they are live at the same point, or if one is defined while the other is live afterwards.
    (LivenessAnalysis assumes SSA-form, so it can not be used after lifting.)
    """
    blocks = list(cfg)
    live_in = {block: set() for block in blocks}
    changed = True
    while changed:
        changed = False
        for block in blocks:
            live = set().union(*(live_in[successor] for successor in cfg.get_successors(block)))
            for instruction in reversed(block.instructions):
                live = (live - set(instruction.definitions)) | set(instruction.requirements)
            if live != live_in[block]:
                live_in[block], changed = live, True

    edges = set()
    for block in blocks:
        live = set().union(*(live_in[successor] for successor in cfg.get_successors(block)))
        edges.update(frozenset((u, v)) for u in live for v in live if u != v)
        for instruction in reversed(block.instructions):
            edges.update(frozenset((d, v)) for d in instruction.definitions for v in live if d != v)
            live = (live - set(instruction.definitions)) | set(instruction.requirements)
            edges.update(frozenset((u, v)) for u in live for v in live if u != v)
    return {tuple(edge) for edge in edges}


class Loop:
    """
    The loop

        entry -> head, head -(true)-> body, head -(false)-> exit, body -> head

    where head contains the given Phi-functions. If 'conditional_back_edge' is set, body ends with a branch and has the edges
    body -(true)-> head and body -(false)-> exit_2, so the copies of the back-edge are placed in a new basic block or before the branch.
    The branch of the body compares 'back_condition' (default: the first phi-definition), and exit_2 uses 'used_at_exit_2'.
    If 'empty_latch' is set as well, the back-edge goes body -(true)-> latch -> head, where latch is an empty block.
    'live_through' variables are defined in entry and used in exit, so they are live during the whole loop.
    """

    def __init__(
        self,
        phis: Dict[Variable, tuple],
        body_instructions: Optional[List] = None,
        live_through: Optional[List[Variable]] = None,
        used_at_exit: Optional[List[Variable]] = None,
        conditional_back_edge: bool = False,
        back_condition: Optional[Variable] = None,
        used_at_exit_2: Optional[List[Variable]] = None,
        empty_latch: bool = False,
    ):
        self.live_through = live_through or []
        self.entry, self.head, self.body, self.exit = (BasicBlock(i) for i in range(4))
        self.entry.instructions = [Assignment(variable, Constant(7)) for variable in self.live_through] + [_use()]
        self.body.instructions = list(body_instructions or [])
        self.exit.instructions = [_use(*(used_at_exit if used_at_exit is not None else list(phis)), *self.live_through), Return([Constant(0)])]
        self.latch = BasicBlock(5, []) if conditional_back_edge and empty_latch else None
        self.back_predecessor = self.latch if self.latch is not None else self.body
        self.phis = list()
        for definition, (entry_value, back_value) in phis.items():
            phi = Phi(definition, [entry_value, back_value])
            phi._origin_block = {self.entry: entry_value, self.back_predecessor: back_value}
            self.phis.append(phi)
        first = next(iter(phis))
        self.head.instructions = self.phis + [Branch(Condition(OperationType.less, [first, Constant(10)]))]

        self.cfg = ControlFlowGraph()
        self.cfg.add_edges_from([UnconditionalEdge(self.entry, self.head), TrueCase(self.head, self.body), FalseCase(self.head, self.exit)])
        if conditional_back_edge:
            self.exit_2 = BasicBlock(4, [_use(*(used_at_exit_2 or [])), Return([Constant(1)])])
            self.body.instructions.append(Branch(Condition(OperationType.less, [back_condition or first, Constant(5)])))
            self.cfg.add_edge(FalseCase(self.body, self.exit_2))
            if self.latch is not None:
                self.cfg.add_edges_from([TrueCase(self.body, self.latch), UnconditionalEdge(self.latch, self.head)])
            else:
                self.cfg.add_edge(TrueCase(self.body, self.head))
        else:
            self.cfg.add_edge(UnconditionalEdge(self.body, self.head))

    def lift(self, move_copies_before_branch: bool = True) -> InterferenceGraph:
        self.original_variables = {v for instruction in self.cfg.instructions for v in instruction.requirements + instruction.definitions}
        self._original_length = {block: len(block.instructions) for block in self.cfg}
        self._original_instructions = {block: [id(instruction) for instruction in block.instructions] for block in self.cfg}
        self.interference_graph = InterferenceGraph(self.cfg)
        PhiFunctionLifter(self.cfg, self.interference_graph, {self.head: list(self.phis)}, move_copies_before_branch).lift()
        return self.interference_graph

    def new_blocks(self) -> List[BasicBlock]:
        return [block for block in self.cfg if block not in self._original_length]

    def copies_on_edge_from(self, predecessor: BasicBlock) -> List[Assignment]:
        """
        The copies that were inserted for the edge predecessor -> head, in execution order: first the ones before the branch that decides
        the edge, then the ones on the edge (at the end of predecessor or in a new block).
        """
        before_branch, on_edge = [], []
        for block in self.cfg.get_predecessors(self.head):
            if block not in self._original_length and predecessor in self.cfg.get_predecessors(block):
                on_edge = list(block.instructions)
        if predecessor.instructions and isinstance(predecessor.instructions[-1], Branch):
            before_branch = self.added_to(predecessor)
        else:
            on_edge = on_edge or self.added_to(predecessor)
            # an empty predecessor, e.g., an empty latch: copies may also be before the branch of its only predecessor
            if not self._original_instructions[predecessor] and len(predecessors := list(self.cfg.get_predecessors(predecessor))) == 1:
                before_branch = self.added_to(predecessors[0])
        return before_branch + on_edge

    def added_to(self, block: BasicBlock) -> List[Assignment]:
        """The instructions that lifting added to an existing block."""
        original = set(self._original_instructions[block])
        return [instruction for instruction in block.instructions if id(instruction) not in original]

    def temporaries(self) -> List[Variable]:
        return [
            instruction.destination
            for instruction in self.cfg.instructions
            if isinstance(instruction, Assignment)
            and isinstance(instruction.destination, Variable)
            and instruction.destination not in self.original_variables
        ]

    def check(self) -> None:
        """Checks the semantics of the copies on every edge and that the maintained interference graph is complete and exact for temporaries."""
        assert not any(isinstance(instruction, Phi) for instruction in self.cfg.instructions)
        assert isinstance(self.head.instructions[-1], Branch)
        phi_definitions = {phi.definitions[0] for phi in self.phis}
        for predecessor in (self.entry, self.back_predecessor):
            copies = self.copies_on_edge_from(predecessor)
            environment = dict()
            for copy in copies:
                assert copy.destination in phi_definitions or copy.destination not in self.original_variables, f"{copy} destroys a value"
                value = copy.value
                environment[copy.destination] = environment.get(value, value) if isinstance(value, Variable) else value
            for phi in self.phis:
                definition = phi.definitions[0]
                assert environment.get(definition, definition) == phi.origin_block[predecessor], f"{phi} on edge {predecessor}: {copies}"

        # Copies before a branch are executed on all outgoing edges: they must not change the branch condition or anything that the
        # exits (exit, exit_2) read.
        exits = [block for block in (self.exit, getattr(self, "exit_2", None)) if block is not None]
        for block in (self.head, self.body):
            if not block.instructions or not isinstance(branch := block.instructions[-1], Branch) or not (moved := self.added_to(block)):
                continue
            assert block.instructions[-len(moved) - 1 : -1] == moved
            read_after = set(branch.requirements) | {
                v for successor in self.cfg.get_successors(block) if successor in exits for i in successor.instructions for v in i.requirements
            }
            assert not {copy.destination for copy in moved} & read_after, f"moved copies {moved} change {read_after}"

        reference = _reference_interferences(self.cfg)
        missing = [(u, v) for u, v in reference if not self.interference_graph.has_edge(u, v)]
        assert not missing, f"missing interferences {missing}"
        # The interferences of temporaries are exact, except for variables that are never read after lifting, e.g., d = phi(a, d) that
        # is only used by itself (dead code, which is removed before out-of-SSA). SSA-liveness considers them live, which is conservative.
        read_variables = {variable for instruction in self.cfg.instructions for variable in instruction.requirements}
        for temporary in self.temporaries():
            expected_neighbors = {v for u, v in reference if u == temporary} | {u for u, v in reference if v == temporary}
            neighbors = set(self.interference_graph.neighbors(temporary))
            assert expected_neighbors <= neighbors
            assert neighbors - expected_neighbors <= set(self.original_variables) - read_variables


def _random_loop(seed: int, conditional_back_edge: bool, empty_latch: bool = False) -> Loop:
    """Random phi-functions on the loop head. The back-edge arguments are phi-definitions (creating trees and cycles), body variables,
    constants or the phi-definition itself."""
    rng = random.Random(seed)
    k = rng.randint(1, 7)
    phi_defs = [_var("d", i) for i in range(k)]
    body_vars = [_var("l", i) for i in range(rng.randint(0, 3))]
    body = [Assignment(l, BinaryOperation(OperationType.plus, [rng.choice(phi_defs), Constant(1)])) for l in body_vars]
    phis = {
        d: (rng.choice([_var("a", i), Constant(100 + i)]), rng.choice(phi_defs + phi_defs + body_vars + [Constant(200 + i), d]))
        for i, d in enumerate(phi_defs)
    }
    entry_args = [value for value, _ in phis.values() if isinstance(value, Variable)]
    loop = Loop(
        phis,
        body_instructions=body,
        live_through=[_var("g", i) for i in range(rng.randint(0, 2))],
        used_at_exit=rng.sample(phi_defs, rng.randint(0, k)),
        conditional_back_edge=conditional_back_edge,
        back_condition=rng.choice(phi_defs + body_vars),
        used_at_exit_2=rng.sample(phi_defs + body_vars, rng.randint(0, min(2, k))),
        empty_latch=empty_latch,
    )
    loop.entry.instructions[:0] = [Assignment(a, Constant(1)) for a in entry_args]
    return loop


@pytest.mark.parametrize("move_copies_before_branch", [False, True])
@pytest.mark.parametrize("back_edge", ["unconditional", "conditional", "empty_latch"])
@pytest.mark.parametrize("seed", range(300))
def test_random_loops(seed, back_edge, move_copies_before_branch):
    loop = _random_loop(seed, back_edge != "unconditional", empty_latch=back_edge == "empty_latch")
    loop.lift(move_copies_before_branch)
    loop.check()
    if back_edge == "empty_latch" and not move_copies_before_branch:
        assert loop.added_to(loop.body) == []


def test_random_loops_move_copies_before_branch_sometimes():
    """Make sure that the random loops cover both cases: copies before the branch and copies in a new block."""
    for empty_latch in (False, True):
        moved, kept = 0, 0
        for seed in range(300):
            loop = _random_loop(seed, conditional_back_edge=True, empty_latch=empty_latch)
            loop.lift()
            moved += bool(loop.added_to(loop.body))
            kept += bool(loop.new_blocks() or (loop.latch is not None and loop.added_to(loop.latch)))
        assert moved > 20 and kept > 20


@pytest.mark.parametrize("conditional_back_edge", [False, True])
def test_swap_needs_temporary_only_at_end_of_back_edge(conditional_back_edge):
    """n#2 = phi(2, w#2), w#2 = phi(1, n#2): the temporary lives only for the swap at the end of the loop body."""
    n, w, g = _var("n", 2), _var("w", 2), _var("g", 1)
    loop = Loop({n: (Constant(2), w), w: (Constant(1), n)}, live_through=[g], conditional_back_edge=conditional_back_edge)
    interference_graph = loop.lift()
    loop.check()

    copy_n = _var("copy_n", 2)
    assert loop.copies_on_edge_from(loop.entry) == [Assignment(n, Constant(2)), Assignment(w, Constant(1))]
    assert loop.copies_on_edge_from(loop.body) == [Assignment(copy_n, n), Assignment(n, w), Assignment(w, copy_n)]
    # The temporary interferes exactly with the swapped variables and the variable that is live through the loop.
    assert set(interference_graph.neighbors(copy_n)) == {n, w, g}


def test_temporary_does_not_interfere_with_dead_variables():
    """A variable that is dead at the end of the body does not interfere with the temporary."""
    n, w, l = _var("n", 2), _var("w", 2), _var("l", 1)
    loop = Loop({n: (Constant(2), w), w: (Constant(1), n)}, body_instructions=[Assignment(l, n), _use(l)])
    interference_graph = loop.lift()
    loop.check()
    assert set(interference_graph.neighbors(_var("copy_n", 2))) == {n, w}


def test_three_cycle():
    """a = phi(.., b), b = phi(.., c), c = phi(.., a): one temporary for the whole cycle."""
    a, b, c = _var("a"), _var("b"), _var("c")
    loop = Loop({a: (Constant(1), b), b: (Constant(2), c), c: (Constant(3), a)})
    loop.lift()
    loop.check()
    assert len(loop.copies_on_edge_from(loop.body)) == 4
    assert loop.temporaries() == [_var("copy_a")]


def test_two_cycles_without_trees_need_two_temporaries():
    """Two disjoint swaps on the same edge; each gets its own temporary, which do not interfere with each other."""
    a, b, c, d = _var("a"), _var("b"), _var("c"), _var("d")
    loop = Loop({a: (Constant(1), b), b: (Constant(2), a), c: (Constant(3), d), d: (Constant(4), c)})
    interference_graph = loop.lift()
    loop.check()
    copy_a, copy_c = _var("copy_a"), _var("copy_c")
    assert loop.copies_on_edge_from(loop.body) == [
        Assignment(copy_a, a),
        Assignment(a, b),
        Assignment(b, copy_a),
        Assignment(copy_c, c),
        Assignment(c, d),
        Assignment(d, copy_c),
    ]
    # Both temporaries can be renamed to the same variable.
    assert not interference_graph.has_edge(copy_a, copy_c)
    assert set(interference_graph.neighbors(copy_a)) == {a, b, c, d}
    assert set(interference_graph.neighbors(copy_c)) == {a, b, c, d}


def test_cycle_uses_tree_variable_instead_of_temporary():
    """a = phi(.., b), b = phi(.., a), x = phi(.., a): x holds the old value of a, so no temporary is needed."""
    a, b, x = _var("a"), _var("b"), _var("x")
    loop = Loop({a: (Constant(1), b), b: (Constant(2), a), x: (Constant(3), a)}, used_at_exit=[x])
    interference_graph = loop.lift()
    loop.check()
    assert loop.copies_on_edge_from(loop.body) == [Assignment(x, a), Assignment(a, b), Assignment(b, x)]
    assert loop.temporaries() == []
    # x is now live until b = x, so it interferes with a, which is written in between.
    assert interference_graph.has_edge(x, a)


def test_cycle_uses_tree_variable_of_a_chain():
    """y = phi(.., x), x = phi(.., a), a = phi(.., b), b = phi(.., a): y is copied before x is overwritten, then x saves a."""
    a, b, x, y = _var("a"), _var("b"), _var("x"), _var("y")
    loop = Loop({y: (Constant(0), x), x: (Constant(1), a), a: (Constant(2), b), b: (Constant(3), a)})
    loop.lift()
    loop.check()
    assert loop.copies_on_edge_from(loop.body) == [Assignment(y, x), Assignment(x, a), Assignment(a, b), Assignment(b, x)]
    assert loop.temporaries() == []


def test_one_cycle_with_tree_and_one_without():
    """Only the cycle without a tree variable needs a temporary."""
    a, b, x, c, d = _var("a"), _var("b"), _var("x"), _var("c"), _var("d")
    loop = Loop({a: (Constant(1), b), b: (Constant(2), a), x: (Constant(3), b), c: (Constant(4), d), d: (Constant(5), c)})
    loop.lift()
    loop.check()
    assert loop.temporaries() == [_var("copy_c")]
    assert Assignment(x, b) in loop.copies_on_edge_from(loop.body)


def test_tree_variable_with_other_type_is_not_used_as_temporary():
    """If the tree variable has another type than the cycle variable, we use a temporary of the right type instead."""
    a, b = _var("a"), _var("b")
    x = _var("x", vartype=Integer.int64_t())
    loop = Loop({a: (Constant(1), b), b: (Constant(2), a), x: (Constant(3), a)}, used_at_exit=[x])
    loop.lift()
    loop.check()
    assert loop.temporaries() == [_var("copy_a")]


def _counting_loop(used_after_loop: bool = False, condition_reads_destination: bool = False, empty_latch: bool = False):
    """
    for (i = 1; ...; i++) { printf(i); } as a do-while:
        head: i#2 = phi(1, i#3)                body: i#3 = i#2 + 1; use(i#2); if (i#3 < 5 / i#2 < 5) -> head else exit_2
    """
    i2, i3 = _var("i", 2), _var("i", 3)
    loop = Loop(
        {i2: (Constant(1), i3)},
        body_instructions=[Assignment(i3, BinaryOperation(OperationType.plus, [i2, Constant(1)])), _use(i2)],
        used_at_exit=[],
        conditional_back_edge=True,
        back_condition=i2 if condition_reads_destination else i3,
        used_at_exit_2=[i2] if used_after_loop else [],
        empty_latch=empty_latch,
    )
    return loop, i2, i3


def test_copy_before_branch_of_back_edge():
    """The copy i#2 = i#3 goes before the branch of the body, so no new block is needed and the loop can become a do-while."""
    loop, i2, i3 = _counting_loop()
    interference_graph = loop.lift()
    loop.check()
    assert loop.new_blocks() == []
    assert loop.body.instructions[-2:] == [Assignment(i2, i3), Branch(Condition(OperationType.less, [i3, Constant(5)]))]
    assert interference_graph.has_edge(i2, i3)


def test_copy_not_before_branch_if_used_on_other_edge():
    """i#2 is used after the loop (exit_2), so i#2 = i#3 must not be executed on that edge."""
    loop, i2, i3 = _counting_loop(used_after_loop=True)
    loop.lift()
    loop.check()
    assert len(loop.new_blocks()) == 1 and loop.new_blocks()[0].instructions == [Assignment(i2, i3)]


def test_copy_not_before_branch_if_condition_reads_destination():
    """The branch condition reads i#2, so i#2 = i#3 must not be executed before it."""
    loop, i2, i3 = _counting_loop(condition_reads_destination=True)
    loop.lift()
    loop.check()
    assert len(loop.new_blocks()) == 1 and loop.new_blocks()[0].instructions == [Assignment(i2, i3)]


def test_copy_not_before_branch_without_option():
    """Without the option (out-of-SSA strategy 'min', where the variables are already renamed), we always split the edge."""
    loop, i2, i3 = _counting_loop()
    loop.lift(move_copies_before_branch=False)
    loop.check()
    assert len(loop.new_blocks()) == 1


def test_all_or_nothing_per_edge():
    """a can be moved, but b is used after the loop. Since the new block stays anyway, both copies stay on the edge."""
    a1, a2, b1, b2 = _var("a", 1), _var("a", 2), _var("b", 1), _var("b", 2)
    loop = Loop(
        {a1: (Constant(1), a2), b1: (Constant(2), b2)},
        body_instructions=[
            Assignment(a2, BinaryOperation(OperationType.plus, [a1, Constant(1)])),
            Assignment(b2, BinaryOperation(OperationType.plus, [b1, Constant(1)])),
        ],
        conditional_back_edge=True,
        back_condition=a2,
        used_at_exit_2=[b1],
    )
    loop.lift()
    loop.check()
    assert loop.added_to(loop.body) == []
    assert loop.new_blocks()[0].instructions == [Assignment(a1, a2), Assignment(b1, b2)]


def test_swap_before_branch():
    """A cycle with temporary can be moved before the branch as a whole."""
    n, w, c = _var("n", 2), _var("w", 2), _var("c", 1)
    loop = Loop(
        {n: (Constant(2), w), w: (Constant(1), n)},
        body_instructions=[Assignment(c, BinaryOperation(OperationType.plus, [n, w]))],
        conditional_back_edge=True,
        back_condition=c,
    )
    interference_graph = loop.lift()
    loop.check()
    copy_n = _var("copy_n", 2)
    assert loop.new_blocks() == []
    assert loop.added_to(loop.body) == [Assignment(copy_n, n), Assignment(n, w), Assignment(w, copy_n)]
    # c is read by the branch after the swap, so it interferes with the temporary
    assert set(interference_graph.neighbors(copy_n)) == {n, w, c}


def test_two_outgoing_edges_with_copies_before_branch():
    """
    P is the latch of two nested loops with heads B1 (inner) and B2 (outer). Both outgoing edges of P are back-edges with copies,
    and both go before the branch of P.
        entry -> B2;  B2 -(true)-> B1 -> P;  B2 -(false)-> exit;  P -(true)-> B1;  P -(false)-> B2
    """
    x1, x2, y1, c, e, f = (_var(name, label) for name, label in (("x", 1), ("x", 2), ("y", 1), ("c", 1), ("e", 1), ("f", 1)))
    entry, p, b1, b2, exit_block = (BasicBlock(i) for i in range(5))
    entry.instructions = [_use()]
    b2.instructions = [Branch(Condition(OperationType.less, [y1, Constant(3)]))]
    b1.instructions = [Assignment(x2, BinaryOperation(OperationType.plus, [x1, Constant(1)])), _use(x2)]
    p.instructions = [
        Assignment(c, BinaryOperation(OperationType.plus, [x2, Constant(1)])),
        Assignment(e, BinaryOperation(OperationType.plus, [c, Constant(1)])),
        Assignment(f, BinaryOperation(OperationType.plus, [c, Constant(2)])),
        Branch(Condition(OperationType.less, [c, Constant(1)])),
    ]
    phi_x = Phi(x1, [Constant(0), e])
    phi_x._origin_block = {b2: Constant(0), p: e}
    phi_y = Phi(y1, [Constant(0), f])
    phi_y._origin_block = {entry: Constant(0), p: f}
    b1.instructions.insert(0, phi_x)
    b2.instructions.insert(0, phi_y)
    exit_block.instructions = [_use(), Return([Constant(0)])]
    cfg = ControlFlowGraph()
    cfg.add_edges_from(
        [
            UnconditionalEdge(entry, b2),
            TrueCase(b2, b1),
            FalseCase(b2, exit_block),
            UnconditionalEdge(b1, p),
            TrueCase(p, b1),
            FalseCase(p, b2),
        ]
    )

    interference_graph = InterferenceGraph(cfg)
    PhiFunctionLifter(cfg, interference_graph, {b1: [phi_x], b2: [phi_y]}, move_copies_before_branch=True).lift()

    assert p.instructions[3:] == [Assignment(x1, e), Assignment(y1, f), Branch(Condition(OperationType.less, [c, Constant(1)]))]
    # The copy x1 = 0 on the edge B2 -> B1 is not on a back-edge, so it gets a new block.
    new_blocks = [block for block in cfg if block not in (entry, p, b1, b2, exit_block)]
    assert len(new_blocks) == 1 and new_blocks[0].instructions == [Assignment(x1, Constant(0))]
    reference = _reference_interferences(cfg)
    assert not [(u, v) for u, v in reference if not interference_graph.has_edge(u, v)]


def test_no_copies_before_branch_of_loop_head():
    """
    The edge head -> exit2 of a loop head is not a back-edge: the copy must not go before the branch of the head, otherwise the
    head would not be a pure condition block any more and we would not get a while-loop with condition.
        entry -> head;  head -(true)-> body -> head;  head -(false)-> after;  entry -> after
    """
    i1, i2, r1 = _var("i", 1), _var("i", 2), _var("r", 1)
    entry, head, body, after = (BasicBlock(i) for i in range(4))
    phi_i = Phi(i1, [Constant(0), i2])
    phi_i._origin_block = {entry: Constant(0), body: i2}
    phi_r = Phi(r1, [Constant(5), i1])
    entry.instructions = [_use(), Branch(Condition(OperationType.less, [Constant(1), Constant(2)]))]
    head.instructions = [phi_i, Branch(Condition(OperationType.less, [i1, Constant(10)]))]
    body.instructions = [Assignment(i2, BinaryOperation(OperationType.plus, [i1, Constant(1)]))]
    after.instructions = [phi_r, Return([r1])]
    phi_r._origin_block = {entry: Constant(5), head: i1}
    cfg = ControlFlowGraph()
    cfg.add_edges_from(
        [TrueCase(entry, head), FalseCase(entry, after), TrueCase(head, body), UnconditionalEdge(body, head), FalseCase(head, after)]
    )

    PhiFunctionLifter(cfg, InterferenceGraph(cfg), {head: [phi_i], after: [phi_r]}, move_copies_before_branch=True).lift()

    assert head.instructions == [Branch(Condition(OperationType.less, [i1, Constant(10)]))]

def test_copy_before_branch_instead_of_empty_latch():
    """The back-edge goes through an empty latch block (as Binary Ninja produces it). The copy goes before the branch of the body."""
    loop, i2, i3 = _counting_loop(empty_latch=True)
    loop.lift()
    loop.check()
    assert loop.latch.instructions == []
    assert loop.body.instructions[-2:] == [Assignment(i2, i3), Branch(Condition(OperationType.less, [i3, Constant(5)]))]


@pytest.mark.parametrize("used_after_loop, condition_reads_destination", [(True, False), (False, True)])
def test_copy_stays_in_empty_latch(used_after_loop, condition_reads_destination):
    """If the copy can not go before the branch, it goes to the empty latch, as before."""
    loop, i2, i3 = _counting_loop(used_after_loop, condition_reads_destination, empty_latch=True)
    loop.lift()
    loop.check()
    assert loop.latch.instructions == [Assignment(i2, i3)]
    assert loop.added_to(loop.body) == []


def test_copy_not_before_branch_if_it_prevents_coalescing():
    """
    i#3 = i#2 + 1; if (i#3 < 5): i#2 and i#3 do not interfere, so renaming can give them the same name and the copy i#2 = i#3 vanishes.
    Before the branch, i#2 would interfere with i#3 (read by the condition), so we keep the copy on the edge.
    """
    i2, i3 = _var("i", 2), _var("i", 3)
    loop = Loop(
        {i2: (Constant(1), i3)},
        body_instructions=[Assignment(i3, BinaryOperation(OperationType.plus, [i2, Constant(1)]))],
        used_at_exit=[],
        conditional_back_edge=True,
        back_condition=i3,
        empty_latch=True,
    )
    interference_graph = loop.lift()
    loop.check()
    assert loop.latch.instructions == [Assignment(i2, i3)]
    assert not interference_graph.has_edge(i2, i3)


def test_only_copy_that_prevents_coalescing_stays_on_edge():
    """
    As above, but with a second copy s#2 = t#1: it can be moved before the branch, while i#2 = i#3 stays in the latch, where it vanishes
    during renaming.
    """
    i2, i3, s2, t1 = _var("i", 2), _var("i", 3), _var("s", 2), _var("t", 1)
    loop = Loop(
        {i2: (Constant(1), i3), s2: (Constant(0), t1)},
        body_instructions=[
            Assignment(i3, BinaryOperation(OperationType.plus, [i2, Constant(1)])),
            Assignment(t1, BinaryOperation(OperationType.plus, [s2, Constant(2)])),
        ],
        used_at_exit=[],
        conditional_back_edge=True,
        back_condition=i3,
        empty_latch=True,
    )
    interference_graph = loop.lift()
    loop.check()
    assert loop.body.instructions[-2:] == [Assignment(s2, t1), loop.body.instructions[-1]]
    assert loop.latch.instructions == [Assignment(i2, i3)]
    assert not interference_graph.has_edge(i2, i3)


def test_swap_moves_while_coalescing_copy_stays_on_edge():
    """
    The copy i#2 = i#3 stays on the edge (coalescing), the swap s#2 <-> u#2 (temporary + two copies) moves before the branch.
    """
    i2, i3, s2, u2 = _var("i", 2), _var("i", 3), _var("s", 2), _var("u", 2)
    loop = Loop(
        {i2: (Constant(1), i3), s2: (Constant(0), u2), u2: (Constant(5), s2)},
        body_instructions=[Assignment(i3, BinaryOperation(OperationType.plus, [i2, Constant(1)]))],
        used_at_exit=[s2, u2],
        conditional_back_edge=True,
        back_condition=i3,
        empty_latch=True,
    )
    interference_graph = loop.lift()
    loop.check()
    assert loop.latch.instructions == [Assignment(i2, i3)]
    assert len(loop.added_to(loop.body)) == 3
    assert not interference_graph.has_edge(i2, i3)


def test_no_copies_before_branch_of_inner_loop_head():
    """
    The exit edge of the inner loop head J goes directly back to the outer head H, so J -> H is a back-edge of the outer loop.
    The copy i1 = i2 must not go before the branch of J, otherwise the inner while-loop loses its condition.
        entry -> H;  H -(true)-> J;  H -(false)-> exit;  J -(true)-> inner -> J;  J -(false)-> H
    """
    i1, i2, j1, j2 = _var("i", 1), _var("i", 2), _var("j", 1), _var("j", 2)
    entry, head, inner_head, inner, exit_block = (BasicBlock(k) for k in range(5))
    phi_i = Phi(i1, [Constant(0), i2])
    phi_i._origin_block = {entry: Constant(0), inner_head: i2}
    phi_j = Phi(j1, [Constant(0), j2])
    phi_j._origin_block = {head: Constant(0), inner: j2}
    entry.instructions = [_use()]
    head.instructions = [phi_i, Assignment(i2, BinaryOperation(OperationType.plus, [i1, Constant(1)])), Branch(Condition(OperationType.less, [i1, Constant(10)]))]
    inner_head.instructions = [phi_j, Branch(Condition(OperationType.less, [j1, Constant(5)]))]
    inner.instructions = [Assignment(j2, BinaryOperation(OperationType.plus, [j1, Constant(1)]))]
    exit_block.instructions = [Return([Constant(0)])]
    cfg = ControlFlowGraph()
    cfg.add_edges_from(
        [
            UnconditionalEdge(entry, head),
            TrueCase(head, inner_head),
            FalseCase(head, exit_block),
            TrueCase(inner_head, inner),
            UnconditionalEdge(inner, inner_head),
            FalseCase(inner_head, head),
        ]
    )

    PhiFunctionLifter(cfg, InterferenceGraph(cfg), {head: [phi_i], inner_head: [phi_j]}, move_copies_before_branch=True).lift()

    assert inner_head.instructions == [Branch(Condition(OperationType.less, [j1, Constant(5)]))]
