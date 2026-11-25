"""Classic out-of-SSA problem cases (Briggs et al., Boissinot et al. 2008) run through every implemented mode.

Correctness is checked semantically: a small interpreter executes the CFG before and after out-of-SSA translation.
"""
import operator
from copy import deepcopy

import pytest
from decompiler.pipeline.ssa.outofssatranslation import OutOfSsaTranslation, SSAOptions
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, TrueCase, UnconditionalEdge
from decompiler.structures.pseudo import BinaryOperation, Condition, Constant, OperationType, Variable
from decompiler.structures.pseudo.instructions import Assignment, Branch, Phi, Return
from decompiler.structures.pseudo.typing import Integer

from tests.pipeline.SSA.utils_out_of_ssa_tests import decompiler_task

MODES = [m for m in SSAOptions if m != SSAOptions.sreedhar]
OPS = {
    OperationType.plus: operator.add,
    OperationType.minus: operator.sub,
    OperationType.multiply: operator.mul,
    OperationType.less: operator.lt,
    OperationType.greater: operator.gt,
    OperationType.equal: operator.eq,
}


def var(name, label=None):
    return Variable(name, Integer.int32_t(), ssa_label=label)


def plus(a, b):
    return BinaryOperation(OperationType.plus, [a, b])


def minus(a, b):
    return BinaryOperation(OperationType.minus, [a, b])


def lt(a, b):
    return Condition(OperationType.less, [a, b])


def interpret(cfg, params, max_steps=1000):
    """Execute the CFG with the given {Variable: int} parameter bindings, return the returned value."""

    def ev(e, env):
        if isinstance(e, Constant):
            return e.value
        if isinstance(e, Variable):
            assert e in env, f"read of undefined variable {e}"
            return env[e]
        assert e.operation in OPS, f"unsupported operation {e}"
        return OPS[e.operation](*(ev(o, env) for o in e.operands))

    env, block, previous, steps = dict(params), cfg.root, None, 0
    while True:
        phis = [i for i in block.instructions if isinstance(i, Phi)]
        values = [ev(p.origin_block[previous], env) for p in phis]  # parallel semantics
        for p, v in zip(phis, values):
            env[p.destination] = v
        for instr in block.instructions:
            steps += 1
            assert steps < max_steps, "step limit exceeded"
            if isinstance(instr, Phi):
                continue
            if isinstance(instr, Assignment):
                env[instr.destination] = ev(instr.value, env)
            elif isinstance(instr, Return):
                return ev(instr.values[0], env)
            elif isinstance(instr, Branch):
                taken = ev(instr.condition, env)
                cls = TrueCase if taken else FalseCase
                nxt = next(e.sink for e in cfg.get_out_edges(block) if isinstance(e, cls))
                break
            else:
                raise AssertionError(f"unsupported instruction {instr}")
        else:
            (edge,) = cfg.get_out_edges(block)
            nxt = edge.sink
        previous, block = block, nxt


def _cfg(blocks, edges, root=None):
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(blocks)
    cfg.root = root or blocks[0]
    cfg.add_edges_from(edges)
    return cfg


def lost_copy():
    """
    n0: x1 = a0
    n1: x2 = phi(x1, x3); x3 = x2 + 1; if (x3 < 5) n1 else n2
    n2: return x2
    """
    n0 = BasicBlock(0, [Assignment(var("x", 1), var("a", 0))])
    phi = Phi(var("x", 2), [var("x", 1), var("x", 3)])
    n1 = BasicBlock(1, [phi, Assignment(var("x", 3), plus(var("x", 2), Constant(1))), Branch(lt(var("x", 3), Constant(5)))])
    n2 = BasicBlock(2, [Return([var("x", 2)])])
    phi._origin_block = {n0: var("x", 1), n1: var("x", 3)}
    return _cfg([n0, n1, n2], [UnconditionalEdge(n0, n1), TrueCase(n1, n1), FalseCase(n1, n2)]), [var("a", 0)]


def swap():
    """
    n0: x0 = a0; y0 = b0; i0 = 0
    n1: x1 = phi(x0, y1); y1 = phi(y0, x1); i1 = phi(i0, i2); i2 = i1 + 1; if (i2 < 3) n1 else n2
    n2: return x1 - y1
    """
    n0 = BasicBlock(0, [Assignment(var("x", 0), var("a", 0)), Assignment(var("y", 0), var("b", 0)), Assignment(var("i", 0), Constant(0))])
    p1 = Phi(var("x", 1), [var("x", 0), var("y", 1)])
    p2 = Phi(var("y", 1), [var("y", 0), var("x", 1)])
    p3 = Phi(var("i", 1), [var("i", 0), var("i", 2)])
    n1 = BasicBlock(1, [p1, p2, p3, Assignment(var("i", 2), plus(var("i", 1), Constant(1))), Branch(lt(var("i", 2), Constant(3)))])
    n2 = BasicBlock(2, [Return([minus(var("x", 1), var("y", 1))])])
    p1._origin_block = {n0: var("x", 0), n1: var("y", 1)}
    p2._origin_block = {n0: var("y", 0), n1: var("x", 1)}
    p3._origin_block = {n0: var("i", 0), n1: var("i", 2)}
    return _cfg([n0, n1, n2], [UnconditionalEdge(n0, n1), TrueCase(n1, n1), FalseCase(n1, n2)]), [var("a", 0), var("b", 0)]


def parameter_in_loop():
    """
    n0: (empty)
    n1: a1 = phi(a0, a2); a2 = a1 + 1; if (a2 < 10) n1 else n2
    n2: return a2
    """
    n0 = BasicBlock(0, [])
    phi = Phi(var("a", 1), [var("a", 0), var("a", 2)])
    n1 = BasicBlock(1, [phi, Assignment(var("a", 2), plus(var("a", 1), Constant(1))), Branch(lt(var("a", 2), Constant(10)))])
    n2 = BasicBlock(2, [Return([var("a", 2)])])
    phi._origin_block = {n0: var("a", 0), n1: var("a", 2)}
    return _cfg([n0, n1, n2], [UnconditionalEdge(n0, n1), TrueCase(n1, n1), FalseCase(n1, n2)]), [var("a", 0)]


def parameter_name_collision():
    """
    n0: (empty)
    n1: a1 = phi(a0, a2); a2 = a1 + a0; a3 = a2 + 1; if (a3 < 10) n1 else n2
    n2: return a3 + a0
    """
    n0 = BasicBlock(0, [])
    phi = Phi(var("a", 1), [var("a", 0), var("a", 3)])
    n1 = BasicBlock(
        1,
        [
            phi,
            Assignment(var("a", 2), plus(var("a", 1), var("a", 0))),
            Assignment(var("a", 3), plus(var("a", 2), Constant(1))),
            Branch(lt(var("a", 3), Constant(10))),
        ],
    )
    n2 = BasicBlock(2, [Return([plus(var("a", 3), var("a", 0))])])
    phi._origin_block = {n0: var("a", 0), n1: var("a", 3)}
    return _cfg([n0, n1, n2], [UnconditionalEdge(n0, n1), TrueCase(n1, n1), FalseCase(n1, n2)]), [var("a", 0)]


def unreachable_predecessor():
    """
    n0: x1 = a0
    n9 (unreachable): -> n1
    n1: x2 = phi(x1, x3, 5); x3 = x2 + 1; if (x3 < 5) n1 else n2
    n2: return x2
    """
    n0 = BasicBlock(0, [Assignment(var("x", 1), var("a", 0))])
    n9 = BasicBlock(9, [])
    phi = Phi(var("x", 2), [var("x", 1), var("x", 3), Constant(5)])
    n1 = BasicBlock(1, [phi, Assignment(var("x", 3), plus(var("x", 2), Constant(1))), Branch(lt(var("x", 3), Constant(5)))])
    n2 = BasicBlock(2, [Return([var("x", 2)])])
    phi._origin_block = {n0: var("x", 1), n1: var("x", 3), n9: Constant(5)}
    edges = [UnconditionalEdge(n0, n1), TrueCase(n1, n1), FalseCase(n1, n2), UnconditionalEdge(n9, n1)]
    return _cfg([n0, n1, n2, n9], edges, root=n0), [var("a", 0)]


def _diamond(ret):
    n0 = BasicBlock(0, [Branch(lt(var("a", 0), var("b", 0)))])
    n1 = BasicBlock(1, [])
    n2 = BasicBlock(2, [])
    phi = Phi(var("x", 1), [var("a", 0), var("b", 0)])
    n3 = BasicBlock(3, [phi, Return([ret])])
    phi._origin_block = {n1: var("a", 0), n2: var("b", 0)}
    edges = [TrueCase(n0, n1), FalseCase(n0, n2), UnconditionalEdge(n1, n3), UnconditionalEdge(n2, n3)]
    return _cfg([n0, n1, n2, n3], edges), [var("a", 0), var("b", 0)]


def two_params_diamond():
    """
    n0: if (a0 < b0) n1 else n2;  n1, n2 empty
    n3: x1 = phi(a0 [n1], b0 [n2]); return x1 + a0 + b0
    """
    return _diamond(plus(plus(var("x", 1), var("a", 0)), var("b", 0)))


def two_params_diamond_only_phi():
    """Same as two_params_diamond, but n3 returns only x1."""
    return _diamond(var("x", 1))


def constant_over_critical_edge():
    """
    n0: if (a0 < 5) n1 else n2
    n1: y1 = a0 + 1; if (y1 < 8) n2 else n3
    n2: x1 = phi(7 [n0], y1 [n1]); return x1 + a0     (n0->n2 and n1->n2 are critical edges)
    n3: return 0
    """
    n0 = BasicBlock(0, [Branch(lt(var("a", 0), Constant(5)))])
    n1 = BasicBlock(1, [Assignment(var("y", 1), plus(var("a", 0), Constant(1))), Branch(lt(var("y", 1), Constant(8)))])
    phi = Phi(var("x", 1), [Constant(7), var("y", 1)])
    n2 = BasicBlock(2, [phi, Return([plus(var("x", 1), var("a", 0))])])
    n3 = BasicBlock(3, [Return([Constant(0)])])
    phi._origin_block = {n0: Constant(7), n1: var("y", 1)}
    edges = [TrueCase(n0, n1), FalseCase(n0, n2), TrueCase(n1, n2), FalseCase(n1, n3)]
    return _cfg([n0, n1, n2, n3], edges), [var("a", 0)]


CASES = {
    "lost_copy": (lost_copy, [-3, 0, 4, 9]),
    "swap": (swap, [(1, 2), (5, 5), (-1, 7)]),
    "parameter_in_loop": (parameter_in_loop, [-2, 0, 9, 15]),
    "parameter_name_collision": (parameter_name_collision, [0, 1, 3, 12]),
    "unreachable_predecessor": (unreachable_predecessor, [-3, 0, 4, 9]),
    "two_params_diamond": (two_params_diamond, [(1, 2), (2, 1), (3, 3)]),
    "two_params_diamond_only_phi": (two_params_diamond_only_phi, [(1, 2), (2, 1), (3, 3)]),
    "constant_over_critical_edge": (constant_over_critical_edge, [-1, 3, 5, 6, 9]),
}

XFAIL = {}  # (case, mode value) -> reason


def _params(vars_, values, renamed):
    values = values if isinstance(values, tuple) else (values,)
    return {(Variable(v.name, v.type) if renamed else v): val for v, val in zip(vars_, values)}


@pytest.mark.parametrize("mode", MODES, ids=lambda m: m.value)
@pytest.mark.parametrize("case", CASES)
def test_out_of_ssa_preserves_semantics(case, mode, request):
    if (case, mode.value) in XFAIL:
        request.applymarker(pytest.mark.xfail(reason=XFAIL[(case, mode.value)], strict=True))
    builder, inputs = CASES[case]
    for values in inputs:
        cfg, args = builder()
        expected = interpret(cfg, _params(args, values, renamed=False))
        cfg, args = builder()
        OutOfSsaTranslation().run(decompiler_task(cfg, mode, deepcopy(args)))
        assert interpret(cfg, _params(args, values, renamed=True)) == expected
