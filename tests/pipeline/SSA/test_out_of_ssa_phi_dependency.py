# pytest for Resolve Circular dependency
from decompiler.pipeline.ssa.phi_dependency_resolver import PhiDependencyResolver

from tests.pipeline.SSA.utils_out_of_ssa_tests import *


def remove_circular_dependency(cfg: ControlFlowGraph) -> None:
    circular_dependency_remover = PhiDependencyResolver(init_phi_functions_of_block(cfg))
    circular_dependency_remover.resolve()


def test_remove_circular_dependency_no(graph_no_dependency):
    """There is no dependency on the Phi-functions"""
    nodes, _, cfg = graph_no_dependency
    instructions = [inst.copy() for inst in cfg.instructions]
    remove_circular_dependency(cfg)

    assert (
        nodes[0].instructions == [instructions[0]]
        and set(nodes[1].instructions[:4]) == set(instructions[1:5])
        and nodes[1].instructions[4:] == instructions[5:7]
        and nodes[2].instructions == instructions[7:]
    )


def test_remove_circular_dependency_no_circular(variable_x, variable_v, variable_u, aliased_variable_y):
    """There is a dependency on the Phi-functions, but no circular, but we still have to sort them."""
    instructions = [
        Phi(variable_x[3], [variable_x[2], variable_x[4]]),
        Phi(variable_v[2], [variable_v[1], variable_x[3]]),
        Phi(variable_u[2], [variable_u[1], variable_u[2]]),
        Phi(aliased_variable_y[4], [aliased_variable_y[3], aliased_variable_y[5]]),
        Phi(aliased_variable_y[5], [aliased_variable_y[2], aliased_variable_y[6]]),
    ]

    # Set of nodes:
    nodes = [BasicBlock(i) for i in range(3)]
    # Add instructions:
    nodes[0].instructions = []
    nodes[1].instructions = instructions[:3].copy()
    nodes[2].instructions = instructions[3:].copy()

    cfg = ControlFlowGraph()
    cfg.add_edges_from(
        [
            TrueCase(nodes[0], nodes[1]),
            UnconditionalEdge(nodes[1], nodes[1]),
            FalseCase(nodes[0], nodes[2]),
            UnconditionalEdge(nodes[2], nodes[2]),
        ]
    )

    remove_circular_dependency(cfg)

    assert (
        nodes[0].instructions == []
        and nodes[1].instructions == [instructions[1], instructions[2], instructions[0]]
        and nodes[2].instructions == instructions[3:]
    )


def test_remove_circular_dependency(variable_x, variable_u, variable_v, aliased_variable_y, copy_variable_v):
    """There are circular dependency on the Phi-functions."""
    instructions = [
        Phi(variable_x[2], [variable_x[1], variable_v[2]]),
        Phi(variable_v[2], [variable_v[1], variable_x[2]]),
        Phi(variable_u[2], [Constant(1), variable_u[1]]),
        Phi(variable_x[3], [aliased_variable_y[4], variable_x[4]]),
        Phi(variable_x[4], [variable_v[1], variable_v[4]]),
        Phi(variable_v[4], [variable_u[1], variable_x[3]]),
        Phi(aliased_variable_y[4], [aliased_variable_y[3], variable_v[4]]),
        Phi(aliased_variable_y[5], [aliased_variable_y[2], aliased_variable_y[4]]),
    ]

    # Set of nodes:
    nodes = [BasicBlock(i) for i in range(3)]
    # Add instructions:
    nodes[0].instructions = []
    nodes[1].instructions = instructions[:3].copy()
    nodes[2].instructions = instructions[3:].copy()

    cfg = ControlFlowGraph()
    cfg.add_edges_from(
        [
            TrueCase(nodes[0], nodes[1]),
            UnconditionalEdge(nodes[1], nodes[1]),
            FalseCase(nodes[0], nodes[2]),
            UnconditionalEdge(nodes[2], nodes[2]),
        ]
    )

    remove_circular_dependency(cfg)

    assert (
        nodes[0].instructions == []
        and nodes[1].instructions
        == [
            instructions[2],
            Phi(copy_variable_v[2], [variable_v[1], variable_x[2]]),
            instructions[0],
            Assignment(variable_v[2], copy_variable_v[2]),
        ]
        and nodes[2].instructions
        == [
            instructions[7],
            Phi(copy_variable_v[4], [variable_u[1], variable_x[3]]),
            instructions[3],
            instructions[6],
            instructions[4],
            Assignment(variable_v[4], copy_variable_v[4]),
        ]
    )


def test_sored_phi_functions_wrong_length(variable_x, variable_v, variable_u, aliased_variable_y):
    """The list of sorted_phi_functions is too short or too long"""
    phi_instructions = [
        Phi(variable_x[3], [variable_x[2], variable_x[4]]),
        Phi(variable_v[2], [variable_v[1], variable_x[3]]),
        Phi(variable_u[2], [variable_u[1], variable_u[2]]),
        Phi(aliased_variable_y[4], [aliased_variable_y[3], aliased_variable_y[5], aliased_variable_y[3]]),
    ]

    sorted_phi_functions = phi_instructions[1:3] + [
        phi_instructions[0],
        phi_instructions[3],
        Phi(variable_u[5], [variable_u[3], variable_u[4]]),
    ]
    node = BasicBlock(1, phi_instructions)
    cfg = ControlFlowGraph()
    cfg.add_node(node)

    circular_dependency_remover = PhiDependencyResolver(init_phi_functions_of_block(cfg))
    node.instructions.append(Assignment(variable_x[4], aliased_variable_y[4]))

    with pytest.raises(ValueError):
        circular_dependency_remover._sort_phi_functions_using(sorted_phi_functions[:3], node)

    with pytest.raises(ValueError):
        circular_dependency_remover._sort_phi_functions_using(sorted_phi_functions, node)
