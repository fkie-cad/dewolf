# test for remove unnecessary phi functions from a graph or basic block.

from dewolf.pipeline.ssa.phi_cleaner import PhiFunctionCleaner

from tests.pipeline.SSA.utils_out_of_ssa_tests import *


def after_cleanup(phi_instructions: List[Phi]) -> List[Assignment]:
    node = BasicBlock(1, phi_instructions)
    PhiFunctionCleaner({node: phi_instructions.copy()}).clean_up()
    return node.instructions


def test_remove_unnecessary_phi_no(variable_x, variable_u, variable_v, aliased_variable_y):
    """There is no unnecessary Phi-function."""
    phi_instructions = [
        Phi(variable_x[3], [variable_x[2], variable_x[4]]),
        Phi(variable_v[2], [variable_v[1], variable_v[3]]),
        Phi(variable_u[2], [variable_u[1], variable_u[2]]),
        Phi(aliased_variable_y[4], [aliased_variable_y[3], aliased_variable_y[5], aliased_variable_y[3]]),
    ]

    assert after_cleanup(phi_instructions.copy()) == phi_instructions


def test_remove_unnecessary_phi_remove_all(variable_x, variable_u, variable_v, aliased_variable_y):
    """There are unnecessary Phi-function, of both types and we can remove both them all."""
    phi_instructions = [
        Phi(variable_x[3], [variable_x[2], variable_x[2]]),
        Phi(variable_v[2], [variable_v[1], variable_v[3]]),
        Phi(variable_u[2], [variable_u[2], variable_u[2]]),
        Phi(aliased_variable_y[4], [aliased_variable_y[3], aliased_variable_y[3], aliased_variable_y[5]]),
    ]

    assert after_cleanup(phi_instructions.copy()) == [
        Phi(variable_v[2], [variable_v[1], variable_v[3]]),
        Phi(aliased_variable_y[4], [aliased_variable_y[3], aliased_variable_y[3], aliased_variable_y[5]]),
        Assignment(variable_x[3], variable_x[2]),
    ]


def test_remove_unnecessary_phi_remove_all_but_dependent(variable_x, variable_u, variable_v, aliased_variable_y):
    """There are unnecessary Phi-function, of both types and we can remove both them all, but not all at the beginning."""
    phi_instructions = [
        Phi(variable_x[3], [variable_x[2], variable_x[2]]),
        Phi(variable_v[2], [variable_x[5], variable_x[5]]),
        Phi(variable_u[2], [variable_v[2], variable_u[2]]),
        Phi(variable_u[1], [variable_u[1], variable_u[1], variable_u[1]]),
        Phi(variable_x[5], [variable_x[3], variable_x[3]]),
        Phi(aliased_variable_y[4], [aliased_variable_y[3], aliased_variable_y[3], Constant(2)]),
    ]

    assert after_cleanup(phi_instructions.copy()) == [
        Phi(variable_u[2], [variable_v[2], variable_u[2]]),
        Phi(aliased_variable_y[4], [aliased_variable_y[3], aliased_variable_y[3], Constant(2)]),
        Assignment(variable_v[2], variable_x[5]),
        Assignment(variable_x[5], variable_x[3]),
        Assignment(variable_x[3], variable_x[2]),
    ]


def test_remove_unnecessary_phi_remove_not_all(variable_x, variable_u, variable_v, aliased_variable_y):
    """There are unnecessary Phi-functions, of both types but we can not remove all due to dependencies."""
    phi_instructions = [
        Phi(variable_x[3], [variable_x[1], variable_x[2]]),
        Phi(variable_v[2], [variable_v[1], variable_v[1]]),
        Phi(variable_u[2], [variable_v[2], variable_u[2]]),
        Phi(variable_u[1], [variable_u[1], variable_u[1], variable_u[1]]),
        Phi(variable_x[5], [variable_x[3], variable_x[3]]),
        Phi(aliased_variable_y[4], [aliased_variable_y[3], aliased_variable_y[3], Constant(2)]),
    ]

    assert after_cleanup(phi_instructions.copy()) == [
        Phi(variable_x[3], [variable_x[1], variable_x[2]]),
        Phi(variable_u[2], [variable_v[2], variable_u[2]]),
        Phi(variable_x[5], [variable_x[3], variable_x[3]]),
        Phi(aliased_variable_y[4], [aliased_variable_y[3], aliased_variable_y[3], Constant(2)]),
        Assignment(variable_v[2], variable_v[1]),
    ]
