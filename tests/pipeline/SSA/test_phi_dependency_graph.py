"""Pytest for Dependency Graph in Out of SSA."""
from typing import List

import pytest
from decompiler.pipeline.ssa.phi_dependency_graph import PhiDependencyGraph
from decompiler.structures.pseudo.expressions import Constant, Variable
from decompiler.structures.pseudo.instructions import Phi
from decompiler.structures.pseudo.typing import Integer
from decompiler.util.insertion_ordered_set import InsertionOrderedSet


@pytest.fixture()
def variable_x():
    return [Variable("x", Integer.int32_t(), i) for i in range(10)]


@pytest.fixture()
def variable_u():
    return [Variable("u", Integer.int32_t(), i) for i in range(10)]


@pytest.fixture()
def variable_v():
    return [Variable("v", Integer.int32_t(), i) for i in range(10)]


@pytest.fixture()
def no_dependency_phi_functions(variable_x, variable_u, variable_v) -> List[Phi]:
    list_of_phi_functions = [
        Phi(variable_x[3], [variable_x[2], variable_x[4]]),
        Phi(variable_v[2], [variable_v[1], variable_v[3]]),
        Phi(variable_u[2], [variable_u[1], variable_u[3]]),
        Phi(variable_v[4], [variable_v[1], variable_u[3]]),
    ]

    return list_of_phi_functions


def test_no_dependency_init(no_dependency_phi_functions):
    list_of_phi_functions = no_dependency_phi_functions
    graph = PhiDependencyGraph(list_of_phi_functions)

    assert list(graph.edges) == [] and set(graph.nodes) == set(list_of_phi_functions)


def test_no_dependency_dfvs(no_dependency_phi_functions):
    list_of_phi_functions = no_dependency_phi_functions
    graph = PhiDependencyGraph(list_of_phi_functions)

    assert graph.compute_directed_feedback_vertex_set_of() == InsertionOrderedSet()


def test_no_dependency_update(no_dependency_phi_functions, variable_x):
    list_of_phi_functions = no_dependency_phi_functions
    graph = PhiDependencyGraph(list_of_phi_functions)
    new_phi_function = Phi(variable_x[5], [variable_x[2], variable_x[4]])

    graph.update_dependency_graph(list_of_phi_functions[0], new_phi_function)

    assert list(graph.edges) == [] and set(graph.nodes) == set(list_of_phi_functions[1:] + [new_phi_function])


@pytest.fixture()
def dependency_phi_functions(variable_x, variable_u, variable_v) -> List[Phi]:
    list_of_phi_functions = [
        Phi(variable_u[3], [variable_x[1], variable_x[4]]),
        Phi(variable_x[4], [variable_x[1], variable_x[7], variable_v[4]]),
        Phi(variable_v[1], [variable_v[2], variable_v[3]]),
        Phi(variable_u[1], [variable_x[1], variable_v[1]]),
        Phi(variable_u[5], [variable_u[1], variable_v[1]]),
    ]

    return list_of_phi_functions


def test_dependency_init(dependency_phi_functions):
    list_of_phi_functions = dependency_phi_functions
    graph = PhiDependencyGraph(list_of_phi_functions)

    assert set(graph.edges) == {
        (list_of_phi_functions[0], list_of_phi_functions[1]),
        (list_of_phi_functions[4], list_of_phi_functions[3]),
        (list_of_phi_functions[4], list_of_phi_functions[2]),
        (list_of_phi_functions[3], list_of_phi_functions[2]),
    } and set(graph.nodes) == set(list_of_phi_functions)


def test_dependency_dfvs(dependency_phi_functions):
    list_of_phi_functions = dependency_phi_functions
    graph = PhiDependencyGraph(list_of_phi_functions)

    assert graph.compute_directed_feedback_vertex_set_of() == InsertionOrderedSet()


def test_dependency_update(dependency_phi_functions, variable_x, variable_v):
    list_of_phi_functions = dependency_phi_functions
    graph = PhiDependencyGraph(list_of_phi_functions)
    new_phi_function = Phi(variable_x[5], [variable_x[1], variable_v[1]])

    graph.update_dependency_graph(list_of_phi_functions[3], new_phi_function)

    assert set(graph.edges) == {
        (list_of_phi_functions[0], list_of_phi_functions[1]),
        (list_of_phi_functions[4], list_of_phi_functions[2]),
        (new_phi_function, list_of_phi_functions[2]),
    } and set(graph.nodes) == set(list_of_phi_functions[:3] + [list_of_phi_functions[4], new_phi_function])


@pytest.fixture()
def circular_dependency_phi_functions(variable_x, variable_u, variable_v) -> List[Phi]:
    list_of_phi_functions = [
        Phi(variable_x[2], [variable_x[1], variable_v[2]]),
        Phi(variable_v[2], [variable_v[1], variable_x[2]]),
        Phi(variable_u[2], [Constant(1), variable_u[1]]),
        Phi(variable_v[3], [variable_v[4], variable_v[5]]),
        Phi(variable_u[1], [variable_x[1], variable_v[3]]),
        Phi(variable_u[5], [variable_u[1], variable_v[3]]),
        Phi(variable_u[3], [variable_x[1], variable_v[6]]),
        Phi(variable_v[4], [variable_x[1], variable_u[3], variable_v[6]]),
    ]

    return list_of_phi_functions


def test_circular_dependency_init(circular_dependency_phi_functions):
    list_of_phi_functions = circular_dependency_phi_functions
    graph = PhiDependencyGraph(list_of_phi_functions)

    assert set(graph.edges) == {
        (list_of_phi_functions[1], list_of_phi_functions[0]),
        (list_of_phi_functions[0], list_of_phi_functions[1]),
        (list_of_phi_functions[4], list_of_phi_functions[3]),
        (list_of_phi_functions[5], list_of_phi_functions[3]),
        (list_of_phi_functions[2], list_of_phi_functions[4]),
        (list_of_phi_functions[5], list_of_phi_functions[4]),
        (list_of_phi_functions[7], list_of_phi_functions[6]),
        (list_of_phi_functions[3], list_of_phi_functions[7]),
    } and set(graph.nodes) == set(list_of_phi_functions)


def test_circular_dependency_dfvs(circular_dependency_phi_functions):
    list_of_phi_functions = circular_dependency_phi_functions
    graph = PhiDependencyGraph(list_of_phi_functions)

    directed_fvs = graph.compute_directed_feedback_vertex_set_of()
    assert directed_fvs == InsertionOrderedSet([list_of_phi_functions[0]]) or directed_fvs == InsertionOrderedSet(
        [list_of_phi_functions[1]]
    )


def test_circular_dependency_update(circular_dependency_phi_functions, variable_x, variable_v, variable_u):
    list_of_phi_functions = circular_dependency_phi_functions
    graph = PhiDependencyGraph(list_of_phi_functions)
    new_phi_function_1 = Phi(variable_x[5], [variable_x[1], variable_v[2]])
    new_phi_function_2 = Phi(variable_u[7], [variable_u[1], variable_v[3]])

    graph.update_dependency_graph(list_of_phi_functions[0], new_phi_function_1)

    assert set(graph.edges) == {
        (new_phi_function_1, list_of_phi_functions[1]),
        (list_of_phi_functions[4], list_of_phi_functions[3]),
        (list_of_phi_functions[5], list_of_phi_functions[3]),
        (list_of_phi_functions[2], list_of_phi_functions[4]),
        (list_of_phi_functions[5], list_of_phi_functions[4]),
        (list_of_phi_functions[7], list_of_phi_functions[6]),
        (list_of_phi_functions[3], list_of_phi_functions[7]),
    } and set(graph.nodes) == set(list_of_phi_functions[1:] + [new_phi_function_1])

    graph.update_dependency_graph(list_of_phi_functions[5], new_phi_function_2)

    assert set(graph.edges) == {
        (new_phi_function_1, list_of_phi_functions[1]),
        (list_of_phi_functions[4], list_of_phi_functions[3]),
        (new_phi_function_2, list_of_phi_functions[3]),
        (list_of_phi_functions[2], list_of_phi_functions[4]),
        (new_phi_function_2, list_of_phi_functions[4]),
        (list_of_phi_functions[7], list_of_phi_functions[6]),
        (list_of_phi_functions[3], list_of_phi_functions[7]),
    } and set(graph.nodes) == set(list_of_phi_functions[1:5] + list_of_phi_functions[6:] + [new_phi_function_1, new_phi_function_2])


def test_circular_dependency_2_init(circular_dependency_phi_functions, variable_v, variable_u):
    list_of_phi_functions = circular_dependency_phi_functions
    list_of_phi_functions[6].substitute(variable_v[6], variable_u[5])
    graph = PhiDependencyGraph(list_of_phi_functions)

    assert set(graph.edges) == {
        (list_of_phi_functions[1], list_of_phi_functions[0]),
        (list_of_phi_functions[0], list_of_phi_functions[1]),
        (list_of_phi_functions[4], list_of_phi_functions[3]),
        (list_of_phi_functions[5], list_of_phi_functions[3]),
        (list_of_phi_functions[2], list_of_phi_functions[4]),
        (list_of_phi_functions[5], list_of_phi_functions[4]),
        (list_of_phi_functions[6], list_of_phi_functions[5]),
        (list_of_phi_functions[7], list_of_phi_functions[6]),
        (list_of_phi_functions[3], list_of_phi_functions[7]),
    } and set(graph.nodes) == set(list_of_phi_functions)


def test_circular_dependency_dfvs_2(circular_dependency_phi_functions, variable_v, variable_u):
    list_of_phi_functions = circular_dependency_phi_functions
    list_of_phi_functions[6].substitute(variable_v[6], variable_u[5])
    graph = PhiDependencyGraph(list_of_phi_functions)

    directed_fvs = graph.compute_directed_feedback_vertex_set_of()
    assert directed_fvs == InsertionOrderedSet([list_of_phi_functions[5], list_of_phi_functions[1]])


def test_circular_dependency_update_2(circular_dependency_phi_functions, variable_x, variable_v, variable_u):
    list_of_phi_functions = circular_dependency_phi_functions
    list_of_phi_functions[6].substitute(variable_v[6], variable_u[5])
    graph = PhiDependencyGraph(list_of_phi_functions)
    new_phi_function_1 = Phi(variable_x[5], [variable_x[1], variable_v[2]])
    new_phi_function_2 = Phi(variable_u[7], [variable_u[1], variable_v[3]])

    graph.update_dependency_graph(list_of_phi_functions[0], new_phi_function_1)

    assert set(graph.edges) == {
        (new_phi_function_1, list_of_phi_functions[1]),
        (list_of_phi_functions[4], list_of_phi_functions[3]),
        (list_of_phi_functions[5], list_of_phi_functions[3]),
        (list_of_phi_functions[2], list_of_phi_functions[4]),
        (list_of_phi_functions[5], list_of_phi_functions[4]),
        (list_of_phi_functions[6], list_of_phi_functions[5]),
        (list_of_phi_functions[7], list_of_phi_functions[6]),
        (list_of_phi_functions[3], list_of_phi_functions[7]),
    } and set(graph.nodes) == set(list_of_phi_functions[1:] + [new_phi_function_1])

    graph.update_dependency_graph(list_of_phi_functions[5], new_phi_function_2)

    assert set(graph.edges) == {
        (new_phi_function_1, list_of_phi_functions[1]),
        (list_of_phi_functions[4], list_of_phi_functions[3]),
        (new_phi_function_2, list_of_phi_functions[3]),
        (list_of_phi_functions[2], list_of_phi_functions[4]),
        (new_phi_function_2, list_of_phi_functions[4]),
        (list_of_phi_functions[7], list_of_phi_functions[6]),
        (list_of_phi_functions[3], list_of_phi_functions[7]),
    } and set(graph.nodes) == set(list_of_phi_functions[1:5] + list_of_phi_functions[6:] + [new_phi_function_1, new_phi_function_2])


def test_no_input_dependency_graph():
    graph = PhiDependencyGraph()

    assert list(graph.nodes) == []
