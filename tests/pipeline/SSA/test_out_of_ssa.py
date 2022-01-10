"""Pytest for Out of SSA."""
from decompiler.pipeline.ssa.outofssatranslation import OutOfSsaTranslation
from decompiler.structures.graphs.cfg import BasicBlockEdgeCondition
from decompiler.structures.pseudo import Expression, Type, UnknownExpression

from tests.pipeline.SSA.utils_out_of_ssa_tests import *


def run_out_of_ssa(cfg: ControlFlowGraph, mode: Union[str, SSAOptions], arguments: List = None):
    """Run of-of-ssa-translation on the given cfg with the given mode and function arguments."""
    OutOfSsaTranslation().run(decompiler_task(cfg, mode, arguments))


# test if optimization does not exist or is not implemented.
def test_optimization_does_not_exist(graph_no_dependency):
    """Here we test that we raise an error if the optimization does not exists."""

    nodes, instructions, cfg = graph_no_dependency
    with pytest.raises(NameError):
        run_out_of_ssa(cfg, "simpel")


def test_optimization_is_not_implemented(graph_no_dependency):
    """Here we test that we raise an error if the optimization does not exists."""

    nodes, instructions, cfg = graph_no_dependency
    with pytest.raises(NotImplementedError):
        run_out_of_ssa(cfg, "sreedhar")


# test for "simple" Out-of-SSA:
def test_no_dependency_conditional_edges_simple(graph_no_dependency):
    """Here we test whether Phi-functions, without dependency and where the ingoing edges are unconditional, are lifted correctly.
    +------------------------+  +------------------------+
    |           0.           |  |           0.           |
    | printf(0x804b00c)      |  | printf(0x804b00c)      |
    +------------------------+  | y_4 = y_3              |
      |                         | u_2 = u_1              |
      |                         | v_2 = v_1              |
      v                         | x_3 = x_2              |
    +------------------------+  +------------------------+
    |           1.           |    |
    | x#3 = ϕ(x#2,x#4)       |    |
    | v#2 = ϕ(v#1,v#3)       |    v
    | u#2 = ϕ(u#1,u#3)       |  +------------------------+
    | y#4 = ϕ(y#3,y#5)       |  |           1.           |
    | u#3 = y#4              |  | u_3 = y_4              |
    | if(v#2 <= u#3)         |  | if(v_2 <= u_3)         |
    +------------------------+  +------------------------+
      ^                           ^
      |                           |
      |                           |
    +------------------------+  +------------------------+
    |           2.           |  |           2.           |
    | x#4 = v#2              |  | x_4 = v_2              |
    | printf(0x804b045, x#4) |  | printf(0x804b045, x_4) |
    +------------------------+  | y_4 = y_5              |
                                | u_2 = u_3              |
                                | v_2 = v_3              |
                                | x_3 = x_4              |
                                +------------------------+
    """
    nodes, instructions, cfg = graph_no_dependency
    run_out_of_ssa(cfg, SSAOptions.simple)

    assert (
        nodes[0].instructions[0] == instructions[0]
        and nodes[1].instructions == instructions[5:7]
        and nodes[2].instructions[0:2] == instructions[7:9]
    )

    assert set(nodes[0].instructions[1:]) == {
        Assignment(phi.definitions[0], phi.origin_block[nodes[0]]) for phi in instructions[1:5]
    } and set(nodes[2].instructions[2:]) == {Assignment(phi.definitions[0], phi.origin_block[nodes[2]]) for phi in instructions[1:5]}

    assert (
        len(cfg.edges) == 2
        and isinstance(cfg.get_edge(nodes[0], nodes[1]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[2], nodes[1]), UnconditionalEdge)
    )


def test_no_dependency_unconditional_edge_simple(graph_no_dependency, variable_x, variable_x_new):
    """Here we test whether Phi-functions, without dependency and where one ingoing edge is not unconditional, are lifted correctly.
    +------------------------+  +------------------------+
    |           0.           |  |           0.           |
    | printf(0x804b00c)      |  | printf(0x804b00c)      |
    +------------------------+  | y_4 = y_3              |
      |                         | u_2 = u_1              |
      |                         | v_2 = v_1              |
      v                         | x_3 = x_2              |
    +------------------------+  +------------------------+
    |           1.           |    |
    | x#3 = ϕ(x#2,x#4)       |    |
    | v#2 = ϕ(v#1,v#3)       |    v
    | u#2 = ϕ(u#1,u#3)       |  +------------------------+
    | y#4 = ϕ(y#3,y#5)       |  |           1.           |
    | u#3 = y#4              |  | u_3 = y_4              |
    | if(v#2 <= u#3)         |  | if(v_2 <= u_3)         | <+
    +------------------------+  +------------------------+  |
      ^                         +------------------------+  |
      |                         |           2.           |  |
      |                         | x_4 = v_2              |  |
    +------------------------+  | printf(0x804b045, x_4) |  |
    |           2.           |  | if(x#4 == 5)           |  |
    | x#4 = v#2              |  +------------------------+  |
    | printf(0x804b045, x#4) |    |                         |
    | if(x#4 == 5)           |    v                         |
    +------------------------+  +------------------------+  |
                                |           3.           |  |
                                | y_4 = y_5              |  |
                                | u_2 = u_3              |  |
                                | v_2 = v_3              |  |
                                | x_3 = x_4              | -+
                                +------------------------+
    """
    nodes, instructions, cfg = graph_no_dependency
    cfg.substitute_edge(cfg.get_edge(nodes[2], nodes[1]), TrueCase(nodes[2], nodes[1]))
    nodes[2].instructions.append(Branch(Condition(OperationType.equal, [variable_x[4], Constant(5)])))
    run_out_of_ssa(cfg, SSAOptions.simple)

    new_node = [node for node in cfg.nodes if node not in set(nodes)][0]
    assert (
        nodes[0].instructions[0] == instructions[0]
        and nodes[1].instructions == instructions[5:7]
        and nodes[2].instructions == instructions[7:9] + [Branch(Condition(OperationType.equal, [variable_x_new[4], Constant(5)]))]
    )

    assert set(nodes[0].instructions[1:]) == {
        Assignment(phi.definitions[0], phi.origin_block[nodes[0]]) for phi in instructions[1:5]
    } and set(new_node.instructions) == {Assignment(phi.definitions[0], phi.origin_block[nodes[2]]) for phi in instructions[1:5]}

    assert (
        len(cfg.edges) == 3
        and isinstance(cfg.get_edge(nodes[0], nodes[1]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[2], new_node), TrueCase)
        and isinstance(cfg.get_edge(new_node, nodes[1]), UnconditionalEdge)
    )


def test_no_dependency_unnecessary_phi_simple(graph_no_dependency, variable_v, variable_v_new):
    """Here we test whether unnecessary Phi-function will be removed from the graph.
    +------------------------+  +------------------------+
    |           0.           |  |           0.           |
    | printf(0x804b00c)      |  | printf(0x804b00c)      |
    +------------------------+  | y_4 = y_3              |
      |                         | u_2 = u_1              |
      |                         | x_3 = x_2              |
      v                         +------------------------+
    +------------------------+    |
    |           1.           |    |
    | x#3 = ϕ(x#2,x#4)       |    v
    | v#2 = ϕ(v#1,v#1)       |  +------------------------+
    | u#2 = ϕ(u#1,u#3)       |  |           1.           |
    | y#4 = ϕ(y#3,y#5)       |  | v_2 = v_1              |
    | u#3 = y#4              |  | u_3 = y_4              |
    | if(v#2 <= u#3)         |  | if(v_2 <= u_3)         |
    +------------------------+  +------------------------+
      ^                           ^
      |                           |
      |                           |
    +------------------------+  +------------------------+
    |           2.           |  |           2.           |
    | x#4 = v#2              |  | x_4 = v_2              |
    | printf(0x804b045, x#4) |  | printf(0x804b045, x_4) |
    +------------------------+  | y_4 = y_5              |
                                | u_2 = u_3              |
                                | x_3 = x_4              |
                                +------------------------+
    """
    nodes, instructions, cfg = graph_no_dependency
    nodes[1].instructions[1].substitute(variable_v[3], variable_v[1])
    run_out_of_ssa(cfg, SSAOptions.simple)

    assert (
        nodes[0].instructions[0] == instructions[0]
        and nodes[1].instructions == [Assignment(variable_v_new[2], variable_v_new[1])] + instructions[5:7]
        and nodes[2].instructions[0:2] == instructions[7:9]
    )
    assert set(nodes[0].instructions[1:]) == {
        Assignment(phi.definitions[0], phi.origin_block[nodes[0]]) for phi in [instructions[1]] + instructions[3:5]
    } and set(nodes[2].instructions[2:]) == {
        Assignment(phi.definitions[0], phi.origin_block[nodes[2]]) for phi in [instructions[1]] + instructions[3:5]
    }

    assert (
        len(cfg.edges) == 2
        and isinstance(cfg.get_edge(nodes[0], nodes[1]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[2], nodes[1]), UnconditionalEdge)
    )


def test_no_dependency_phi_target_value_same_simple(graph_no_dependency, variable_v):
    """Here we test whether we do not insert the definition when the Phi-function target is the same as a Phi-function value.
    +------------------------+  +------------------------+
    |           0.           |  |           0.           |
    | printf(0x804b00c)      |  | printf(0x804b00c)      |
    +------------------------+  | y_4 = y_3              |
      |                         | u_2 = u_1              |
      |                         | v_2 = v_1              |
      v                         | x_3 = x_2              |
    +------------------------+  +------------------------+
    |           1.           |    |
    | x#3 = ϕ(x#2,x#4)       |    |
    | v#2 = ϕ(v#1,v#2)       |    v
    | u#2 = ϕ(u#1,u#3)       |  +------------------------+
    | y#4 = ϕ(y#3,y#5)       |  |           1.           |
    | u#3 = y#4              |  | u_3 = y_4              |
    | if(v#2 <= u#3)         |  | if(v_2 <= u_3)         |
    +------------------------+  +------------------------+
      ^                           ^
      |                           |
      |                           |
    +------------------------+  +------------------------+
    |           2.           |  |           2.           |
    | x#4 = v#2              |  | x_4 = v_2              |
    | printf(0x804b045, x#4) |  | printf(0x804b045, x_4) |
    +------------------------+  | y_4 = y_5              |
                                | u_2 = u_3              |
                                | x_3 = x_4              |
                                +------------------------+
    """
    nodes, instructions, cfg = graph_no_dependency
    nodes[1].instructions[1].substitute(variable_v[3], variable_v[2])
    run_out_of_ssa(cfg, SSAOptions.simple)

    assert (
        nodes[0].instructions[0] == instructions[0]
        and nodes[1].instructions == instructions[5:7]
        and nodes[2].instructions[0:2] == instructions[7:9]
    )
    assert set(nodes[0].instructions[1:]) == {
        Assignment(phi.definitions[0], phi.origin_block[nodes[0]]) for phi in instructions[1:5]
    } and set(nodes[2].instructions[2:]) == {
        Assignment(phi.definitions[0], phi.origin_block[nodes[2]]) for phi in [instructions[1]] + instructions[3:5]
    }

    assert (
        len(cfg.edges) == 2
        and isinstance(cfg.get_edge(nodes[0], nodes[1]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[2], nodes[1]), UnconditionalEdge)
    )


def test_dependency_but_no_circle_simple(graph_dependency_but_not_circular):
    """Here we test whether Phi-functions, with dependency, but no circular dependency and where one ingoing edge is not unconditional,
        are lifted correctly.
                                   +--------------------------+                                           +--------------------------+
                                   |            0.            |                                           |            0.            |
                                   | printf(0x804a00c)        |                                           | printf(0x804a00c)        |
                                   | scanf(0x804a025, &(y#1)) |                                           | scanf(0x804a025, &(y_1)) |
                                   | printf(0x804a028, y#1)   |                                           | printf(0x804a028, y_1)   |
                                   +--------------------------+                                           | u_3 = y_1                |
                                     |                                                                    | y_4 = y_1                |
                                     |                                                                    +--------------------------+
                                     v                                                                      |
    +------------------------+     +------------------------------------+                                   |
    |           2.           |     |                 1.                 |                                   v
    | printf(0x804a049, u#3) |     | u#3 = ϕ(y#1,y#4)                   |  +------------------------+     +------------------------------------+
    | return 0x0             |     | y#4 = ϕ(y#1,y#7,v#4)               |  |           2.           |     |                 1.                 |
    |                        | <-- | if(y#4 <= 0x0)                     |  | printf(0x804a049, u_3) |     | if(y_4 <= 0x0)                     |
    +------------------------+     +------------------------------------+  | return 0x0             | <-- |                                    |
                                     |                           ^    ^    +------------------------+     +------------------------------------+
                                     |                           |    |                                     |                           ^    ^
                                     v                           |    |                                     |                           |    |
                                   +--------------------------+  |    |                                     v                           |    |
                                   |            3.            |  |    |    +------------------------+     +--------------------------+  |    |
                                   | printf(0x804a045, y#4)   |  |    |    |                        |     |            3.            |  |    |
                                   | y#7 = y#4 - 0x2          |  |    |    |           5.           |     | printf(0x804a045, y_4)   |  |    |
                                   | v#2 = is_odd(y#7)        |  |    |    | u_3 = y_4              |     | y_7 = y_4 - 0x2          |  |    |
                                   | if((v#2 & 0xff) == 0x0)  | -+    |    | y_4 = y_7              |     | v_2 = is_odd(y_7)        |  |    |
                                   +--------------------------+       |    |                        | <-- | if((v_2 & 0xff) == 0x0)  |  |    |
                                     |                                |    +------------------------+     +--------------------------+  |    |
                                     |                                |      |                              |                           |    |
                                     v                                |      |                              |                           |    |
                                   +--------------------------+       |      |                              v                           |    |
                                   |            4.            |       |      |                            +--------------------------+  |    |
                                   | v#4 = y#7 - 0x1          | ------+      |                            |            4.            |  |    |
                                   +--------------------------+              |                            | v_4 = y_7 - 0x1          |  |    |
                                                                             |                            | u_3 = y_4                |  |    |
                                                                             |                            | y_4 = v_4                | -+    |
                                                                             |                            +--------------------------+       |
                                                                             |                                                               |
                                                                             +---------------------------------------------------------------+
    """
    nodes, instructions, cfg = graph_dependency_but_not_circular
    run_out_of_ssa(cfg, SSAOptions.simple)

    new_node = [node for node in cfg.nodes if node not in set(nodes)][0]

    assert (
        nodes[0].instructions[0:3] == instructions[0:3]
        and nodes[1].instructions == [instructions[5]]
        and nodes[2].instructions == instructions[6:8]
        and nodes[3].instructions[0:5] == instructions[8:12]
        and nodes[4].instructions[0] == instructions[12]
    )

    assert (
        nodes[0].instructions[3:] == [Assignment(phi.definitions[0], phi.origin_block[nodes[0]]) for phi in instructions[3:5]]
        and new_node.instructions == [Assignment(phi.definitions[0], phi.origin_block[nodes[3]]) for phi in instructions[3:5]]
        and nodes[4].instructions[1:] == [Assignment(phi.definitions[0], phi.origin_block[nodes[4]]) for phi in instructions[3:5]]
    )

    assert (
        len(cfg.edges) == 7
        and isinstance(cfg.get_edge(nodes[0], nodes[1]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[1], nodes[2]), FalseCase)
        and isinstance(cfg.get_edge(nodes[1], nodes[3]), TrueCase)
        and isinstance(cfg.get_edge(nodes[3], new_node), TrueCase)
        and isinstance(cfg.get_edge(new_node, nodes[1]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[3], nodes[4]), FalseCase)
        and isinstance(cfg.get_edge(nodes[4], nodes[1]), UnconditionalEdge)
    )


def test_dependency_but_no_circle_some_same_values_simple(graph_dependency_but_not_circular, aliased_variable_y, variable_u):
    """Here we test whether Phi-functions, with dependency, but no circular dependency and where one ingoing edge is not unconditional,
        are lifted correctly.
                                   +--------------------------+                                           +--------------------------+
                                   |            0.            |                                           |            0.            |
                                   | printf(0x804a00c)        |                                           | printf(0x804a00c)        |
                                   | scanf(0x804a025, &(y#1)) |                                           | scanf(0x804a025, &(y_1)) |
                                   | printf(0x804a028, y#1)   |                                           | printf(0x804a028, y_1)   |
                                   +--------------------------+                                           | u_3 = y_1                |
                                     |                                                                    | y_4 = y_1                |
                                     |                                                                    +--------------------------+
                                     v                                                                      |
    +------------------------+     +------------------------------------+                                   |
    |           2.           |     |                 1.                 |                                   v
    | printf(0x804a049, u#3) |     | u#3 = ϕ(y#1,y#4,y#4)               |  +------------------------+     +------------------------------------+
    | return 0x0             |     | y#4 = ϕ(y#1,y#7,v#4)               |  |           2.           |     |                 1.                 |
    |                        | <-- | if(y#4 <= 0x0)                     |  | printf(0x804a049, u_3) |     | if(y_4 <= 0x0)                     |
    +------------------------+     +------------------------------------+  | return 0x0             | <-- |                                    |
                                     |                           ^    ^    +------------------------+     +------------------------------------+
                                     |                           |    |                                     |                           ^    ^
                                     v                           |    |                                     |                           |    |
                                   +--------------------------+  |    |                                     v                           |    |
                                   |            3.            |  |    |    +------------------------+     +--------------------------+  |    |
                                   | printf(0x804a045, y#4)   |  |    |    |                        |     |            3.            |  |    |
                                   | y#7 = y#4 - 0x2          |  |    |    |           5.           |     | printf(0x804a045, y_4)   |  |    |
                                   | v#2 = is_odd(y#7)        |  |    |    | u_3 = y_4              |     | y_7 = y_4 - 0x2          |  |    |
                                   | if((v#2 & 0xff) == 0x0)  | -+    |    | y_4 = y_7              |     | v_2 = is_odd(y_7)        |  |    |
                                   +--------------------------+       |    |                        | <-- | if((v_2 & 0xff) == 0x0)  |  |    |
                                     |                                |    +------------------------+     +--------------------------+  |    |
                                     |                                |      |                              |                           |    |
                                     v                                |      |                              |                           |    |
                                   +--------------------------+       |      |                              v                           |    |
                                   |            4.            |       |      |                            +--------------------------+  |    |
                                   | v#4 = y#7 - 0x1          | ------+      |                            |            4.            |  |    |
                                   +--------------------------+              |                            | v_4 = y_7 - 0x1          |  |    |
                                                                             |                            | u_3 = y_4                |  |    |
                                                                             |                            | y_4 = v_4                | -+    |
                                                                             |                            +--------------------------+       |
                                                                             |                                                               |
                                                                             +---------------------------------------------------------------+
    """
    nodes, instructions, cfg = graph_dependency_but_not_circular
    new_phi = Phi(variable_u[3], [aliased_variable_y[1], aliased_variable_y[4], aliased_variable_y[4]])
    new_phi._origin_block = {nodes[0]: aliased_variable_y[1], nodes[3]: aliased_variable_y[4], nodes[4]: aliased_variable_y[4]}
    nodes[1].instructions[0] = new_phi

    run_out_of_ssa(cfg, SSAOptions.simple)

    new_node = [node for node in cfg.nodes if node not in set(nodes)][0]

    assert (
        nodes[0].instructions[0:3] == instructions[0:3]
        and nodes[1].instructions == [instructions[5]]
        and nodes[2].instructions == instructions[6:8]
        and nodes[3].instructions[0:5] == instructions[8:12]
        and nodes[4].instructions[0] == instructions[12]
    )

    assert (
        nodes[0].instructions[3:] == [Assignment(phi.definitions[0], phi.origin_block[nodes[0]]) for phi in instructions[3:5]]
        and new_node.instructions == [Assignment(phi.definitions[0], phi.origin_block[nodes[3]]) for phi in instructions[3:5]]
        and nodes[4].instructions[1:] == [Assignment(phi.definitions[0], phi.origin_block[nodes[4]]) for phi in instructions[3:5]]
    )

    assert (
        len(cfg.edges) == 7
        and isinstance(cfg.get_edge(nodes[0], nodes[1]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[1], nodes[2]), FalseCase)
        and isinstance(cfg.get_edge(nodes[1], nodes[3]), TrueCase)
        and isinstance(cfg.get_edge(nodes[3], new_node), TrueCase)
        and isinstance(cfg.get_edge(new_node, nodes[1]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[3], nodes[4]), FalseCase)
        and isinstance(cfg.get_edge(nodes[4], nodes[1]), UnconditionalEdge)
    )


def test_circular_dependency_simple(graph_circular_dependency):
    """Here we test whether Phi-functions, with circular dependency and where all ingoing edges are unconditional, are lifted correctly.
                                   +-----------------------+                                    +-----------------------+
                                   |          0.           |                                    |          0.           |
                                   | printf(0x804b00c)     |                                    | printf(0x804b00c)     |
                                   | x#1 = &(y#1)          |                                    | x_1 = &(y_1)          |
                                   | scanf(0x804b01f, x#1) |                                    | scanf(0x804b01f, x_1) |
                                   | y#2 = y#1             |                                    | y_2 = y_1             |
                                   | printf(0x804bb0c)     |                                    | printf(0x804bb0c)     |
                                   | v#1 = &(z#3)          |                                    | v_1 = &(z_3)          |
                                   | scanf(0x804bb1f, v#1) |                                    | scanf(0x804bb1f, v_1) |
                                   +-----------------------+                                    | copy_v_2 = v_1        |
                                     |                                                          | x_2 = x_1             |
                                     |                                                          | u_2 = 0x1             |
                                     v                                                          +-----------------------+
    +------------------------+     +-----------------------+                                      |
    |                        |     |          1.           |                                      |
    |           3.           |     | x#2 = ϕ(x#1,v#2)      |                                      v
    | printf(0x804bb0c, x#2) |     | v#2 = ϕ(v#1,x#2)      |     +------------------------+     +-----------------------+
    |                        |     | u#2 = ϕ(0x1,u#1)      |     |           3.           |     |          1.           |
    |                        | <-- | if(u#2 <= 0x14)       | <+  | printf(0x804bb0c, x_2) |     | v_2 = copy_v_2        |
    +------------------------+     +-----------------------+  |  |                        | <-- | if(u_2 <= 0x14)       | <+
                                     |                        |  +------------------------+     +-----------------------+  |
                                     |                        |                                   |                        |
                                     v                        |                                   |                        |
                                   +-----------------------+  |                                   v                        |
                                   |          2.           |  |                                 +-----------------------+  |
                                   | u#1 = u#2 + 0x1       | -+                                 |          2.           |  |
                                   +-----------------------+                                    | u_1 = u_2 + 0x1       |  |
                                                                                                | copy_v_2 = x_2        |  |
                                                                                                | x_2 = v_2             |  |
                                                                                                | u_2 = u_1             | -+
                                                                                                +-----------------------+
    """
    nodes, instructions, cfg = graph_circular_dependency
    run_out_of_ssa(cfg, SSAOptions.simple)

    assert (
        nodes[0].instructions[0:7] == instructions[0:7]
        and nodes[1].instructions[-1] == instructions[10]
        and nodes[2].instructions[0] == instructions[11]
        and nodes[3].instructions == [instructions[12]]
    )

    assert (
        set(nodes[0].instructions[7:])
        == {Assignment(Variable("copy_x_2", Integer.int32_t()), instructions[7].origin_block[nodes[0]])}
        | {Assignment(phi.definitions[0], phi.origin_block[nodes[0]]) for phi in instructions[8:10]}
        and nodes[0].instructions.index(Assignment(Variable("copy_x_2", Integer.int32_t()), instructions[7].origin_block[nodes[0]]))
        < nodes[0].instructions.index(Assignment(instructions[8].definitions[0], instructions[8].origin_block[nodes[0]]))
        and nodes[1].instructions[:-1] == [Assignment(instructions[7].definitions[0], Variable("copy_x", Integer.int32_t(), 2))]
        and set(nodes[2].instructions[1:])
        == {Assignment(Variable("copy_x_2", Integer.int32_t()), instructions[7].origin_block[nodes[2]])}
        | {Assignment(phi.definitions[0], phi.origin_block[nodes[2]]) for phi in instructions[8:10]}
        and nodes[2].instructions.index(Assignment(Variable("copy_x_2", Integer.int32_t()), instructions[7].origin_block[nodes[2]]))
        < nodes[2].instructions.index(Assignment(instructions[8].definitions[0], instructions[8].origin_block[nodes[2]]))
    ) or (
        set(nodes[0].instructions[7:])
        == {Assignment(Variable("copy_v_2", Integer.int32_t()), instructions[8].origin_block[nodes[0]])}
        | {Assignment(phi.definitions[0], phi.origin_block[nodes[0]]) for phi in [instructions[7], instructions[9]]}
        and nodes[0].instructions.index(Assignment(Variable("copy_v_2", Integer.int32_t()), instructions[8].origin_block[nodes[0]]))
        < nodes[0].instructions.index(Assignment(instructions[7].definitions[0], instructions[7].origin_block[nodes[0]]))
        and nodes[1].instructions[:-1] == [Assignment(instructions[8].definitions[0], Variable("copy_v_2", Integer.int32_t()))]
        and set(nodes[2].instructions[1:])
        == {Assignment(Variable("copy_v_2", Integer.int32_t()), instructions[8].origin_block[nodes[2]])}
        | {Assignment(phi.definitions[0], phi.origin_block[nodes[2]]) for phi in [instructions[7], instructions[9]]}
        and nodes[2].instructions.index(Assignment(Variable("copy_v_2", Integer.int32_t()), instructions[8].origin_block[nodes[2]]))
        < nodes[2].instructions.index(Assignment(instructions[7].definitions[0], instructions[7].origin_block[nodes[2]]))
    )

    assert (
        len(cfg.edges) == 4
        and isinstance(cfg.get_edge(nodes[0], nodes[1]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[1], nodes[2]), TrueCase)
        and isinstance(cfg.get_edge(nodes[1], nodes[3]), FalseCase)
        and isinstance(cfg.get_edge(nodes[2], nodes[1]), UnconditionalEdge)
    )


def test_graph_with_input_arguments_more_variable_types_circular_dependency_simple(
    graph_with_input_arguments_different_variable_types_2, variable_v_new, variable_u_new, variable_x_new, variable_y_new
):
    """Graph where we have input arguments and where there is more than one variable type.
                       +----------------------------------+     +---------------+     +----------------------------------+
                       |                0.                |     |      8.       |     |                0.                |
                       | if(arg2#0 < arg1#0)              | -+  | arg2_2 = arg1 | <-- | if(arg2 < arg1)                  |
                       +----------------------------------+  |  +---------------+     +----------------------------------+
                         |                                   |    |                     |
                         |                                   |    |                     |
                         v                                   |    |                     v
                       +----------------------------------+  |    |                   +----------------------------------+
                       |                1.                |  |    |                   |                1.                |
                       +----------------------------------+  |    |                   | arg2_2 = arg2                    |
                         |                                   |    |                   +----------------------------------+
                         |                                   |    |                     |
                         v                                   |    |                     |
                       +----------------------------------+  |    |                     v
                       |                2.                |  |    |                   +----------------------------------+     +-----------------+
                       | arg2#2 = ϕ(arg2#0,arg1#0)        |  |    |                   |                2.                |     |       9.        |
                    +- | if(arg1#0 > (arg2#2 + arg2#2))   | <+    +-----------------> | if(arg1 > (arg2_2 + arg2_2))     | --> | arg2_4 = arg2_2 |
                    |  +----------------------------------+                           +----------------------------------+     +-----------------+
                    |    |                                                              |                                        |
                    |    |                                                              |                                        |
                    |    v                                                              v                                        |
                    |  +----------------------------------+                           +----------------------------------+       |
                    |  |                3.                |                           |                3.                |       |
                    |  | arg2#3 = arg1#0 - arg2#2         |                           | arg2_3 = arg1 - arg2_2           |       |
                    |  +----------------------------------+                           | arg2_4 = arg2_3                  |       |
                    |    |                                                            +----------------------------------+       |
                    |    |                                                              |                                        |
                    |    v                                                              |                                        |
                    |  +----------------------------------+                             v                                        |
                    |  |                4.                |                           +----------------------------------+       |
                    |  | arg2#4 = ϕ(arg2#2,arg2#3)        |                           |                4.                |       |
                    +> | v#1 = (arg1#0 - arg2#4) + 0x1    |                           | v_1 = (arg1 - arg2_4) + 0x1      |       |
                       +----------------------------------+                           | v_2 = v_1                        |       |
                         |                                                            | u_2 = 0x1                        |       |
                         |                                                            | x_2 = 0x1                        | <-----+
                         v                                                            +----------------------------------+
    +------------+     +----------------------------------+                             |
    |            |     |                5.                |                             |
    |     7.     |     | u#2 = ϕ(0x1,u#5)                 |                             v
    | return x#2 |     | v#2 = ϕ(v#1,v#2)                 |     +---------------+     +----------------------------------+
    |            |     | x#2 = ϕ(0x1,y#1)                 |     |      7.       |     |                5.                |
    |            | <-- | if(u#2 <= arg2#4)                | <+  | return x_2    | <-- | if(u_2 <= arg2_4)                | <+
    +------------+     +----------------------------------+  |  +---------------+     +----------------------------------+  |
                         |                                   |                          |                                   |
                         |                                   |                          |                                   |
                         v                                   |                          v                                   |
                       +----------------------------------+  |                        +----------------------------------+  |
                       |                6.                |  |                        |                6.                |  |
                       | u#5 = u#2 + 0x1                  |  |                        | u_5 = u_2 + 0x1                  |  |
                       | y#1 = (((long) v#2) * x#2) / u#2 | -+                        | y_1 = (((long) v_2) * x_2) / u_2 |  |
                       +----------------------------------+                           | u_2 = u_5                        |  |
                                                                                      | x_2 = y_1                        | -+
                                                                                      +----------------------------------+
    """
    nodes, cfg = graph_with_input_arguments_different_variable_types_2
    run_out_of_ssa(
        cfg,
        SSAOptions.simple,
        arguments=[argument1 := Variable("arg1", Integer.int32_t()), argument2 := Variable("arg2", Integer.int32_t())],
    )

    arg2_new = [Variable(f"arg2_{i}", Integer.int32_t()) for i in range(6)]

    new_node = [node for node in cfg.nodes if node not in set(nodes)]

    assert (
        nodes[0].instructions == [Branch(Condition(OperationType.less, [argument2, argument1]))]
        and nodes[1].instructions == [Assignment(arg2_new[2], argument2)]
        and nodes[2].instructions
        == [Branch(Condition(OperationType.greater, [argument1, BinaryOperation(OperationType.plus, [arg2_new[2], arg2_new[2]])]))]
        and nodes[3].instructions
        == [Assignment(arg2_new[3], BinaryOperation(OperationType.minus, [argument1, arg2_new[2]])), Assignment(arg2_new[4], arg2_new[3])]
        and nodes[4].instructions
        == [
            Assignment(
                variable_v_new[1],
                BinaryOperation(OperationType.plus, [BinaryOperation(OperationType.minus, [argument1, arg2_new[4]]), Constant(0x1)]),
            ),
            Assignment(variable_v_new[2], variable_v_new[1]),
            Assignment(variable_u_new[2], Constant(0x1)),
            Assignment(variable_x_new[2], Constant(0x1)),
        ]
        and nodes[5].instructions == [Branch(Condition(OperationType.less_or_equal, [variable_u_new[2], arg2_new[4]]))]
        and nodes[6].instructions
        == [
            Assignment(variable_u_new[5], BinaryOperation(OperationType.plus, [variable_u_new[2], Constant(0x1)])),
            Assignment(
                variable_y_new[1],
                BinaryOperation(
                    OperationType.divide,
                    [
                        BinaryOperation(
                            OperationType.multiply,
                            [UnaryOperation(OperationType.cast, [variable_v_new[2]], vartype=Integer.int64_t()), variable_x_new[2]],
                        ),
                        variable_u_new[2],
                    ],
                ),
            ),
            Assignment(variable_u_new[2], variable_u_new[5]),
            Assignment(variable_x_new[2], variable_y_new[1]),
        ]
        and nodes[7].instructions == [Return([variable_x_new[2]])]
        and new_node[0].instructions == [Assignment(arg2_new[2], argument1)]
        and new_node[1].instructions == [Assignment(arg2_new[4], arg2_new[2])]
        and len(cfg) == 10
    )

    assert (
        len(cfg.edges) == 12
        and isinstance(cfg.get_edge(nodes[0], nodes[1]), TrueCase)
        and isinstance(cfg.get_edge(nodes[0], new_node[0]), FalseCase)
        and isinstance(cfg.get_edge(new_node[0], nodes[2]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[1], nodes[2]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[2], nodes[3]), FalseCase)
        and isinstance(cfg.get_edge(nodes[2], new_node[1]), TrueCase)
        and isinstance(cfg.get_edge(new_node[1], nodes[4]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[3], nodes[4]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[4], nodes[5]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[5], nodes[6]), TrueCase)
        and isinstance(cfg.get_edge(nodes[5], nodes[7]), FalseCase)
        and isinstance(cfg.get_edge(nodes[6], nodes[5]), UnconditionalEdge)
    )


def test_graph_with_graph_with_edge_condition(
    graph_with_edge_condition, aliased_variable_y_new, aliased_variable_z_new, aliased_variable_x_new, variable_v_new
):
    """Graph, where we have conditions on some edges."""
    nodes, cfg = graph_with_edge_condition
    run_out_of_ssa(cfg, SSAOptions.simple)

    assert (
        nodes[0].instructions
        == [
            Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("Enter your choice = ")])),
            Assignment(
                ListOperation([]),
                Call(
                    imp_function_symbol("scanf"), [Constant(0x804A025), UnaryOperation(OperationType.address, [aliased_variable_y_new[0]])]
                ),
            ),
            Assignment(ListOperation([]), Call(imp_function_symbol("puts"), [Constant("Enter a number ")])),
            Assignment(
                ListOperation([]),
                Call(
                    imp_function_symbol("scanf"), [Constant(0x804A025), UnaryOperation(OperationType.address, [aliased_variable_z_new[0]])]
                ),
            ),
            Assignment(ListOperation([]), Call(imp_function_symbol("puts"), [Constant("Enter a second number ")])),
            Assignment(
                ListOperation([]),
                Call(
                    imp_function_symbol("scanf"), [Constant(0x804A025), UnaryOperation(OperationType.address, [aliased_variable_x_new[0]])]
                ),
            ),
            Branch(Condition(OperationType.greater, [aliased_variable_y_new[0], Constant(0x5)])),
        ]
        and nodes[1].instructions == [IndirectBranch(aliased_variable_y_new[0])]
        and nodes[2].instructions
        == [
            Assignment(ListOperation([]), Call(imp_function_symbol("puts"), [Constant("default !")])),
            Assignment(variable_v_new[6], Constant(0x0)),
        ]
        and nodes[3].instructions
        == [
            Assignment(
                variable_v_new[1],
                BinaryOperation(
                    OperationType.multiply,
                    [BinaryOperation(OperationType.plus, [aliased_variable_z_new[0], Constant(0x1)]), aliased_variable_x_new[0]],
                ),
            ),
            Assignment(variable_v_new[6], variable_v_new[1]),
        ]
        and nodes[4].instructions
        == [
            Assignment(
                variable_v_new[2],
                BinaryOperation(
                    OperationType.plus,
                    [BinaryOperation(OperationType.plus, [aliased_variable_z_new[0], Constant(0x2)]), aliased_variable_x_new[0]],
                ),
            ),
            Assignment(variable_v_new[6], variable_v_new[2]),
        ]
        and nodes[5].instructions
        == [
            Assignment(
                variable_v_new[3],
                BinaryOperation(
                    OperationType.minus,
                    [aliased_variable_x_new[0], BinaryOperation(OperationType.plus, [aliased_variable_z_new[0], Constant(0x3)])],
                ),
            ),
            Assignment(variable_v_new[6], variable_v_new[3]),
        ]
        and nodes[6].instructions
        == [
            Assignment(
                variable_v_new[4],
                BinaryOperation(
                    OperationType.minus,
                    [BinaryOperation(OperationType.plus, [aliased_variable_z_new[0], Constant(0x4)]), aliased_variable_x_new[0]],
                ),
            ),
            Assignment(variable_v_new[6], variable_v_new[4]),
        ]
        and nodes[7].instructions
        == [
            Assignment(
                variable_v_new[5],
                BinaryOperation(
                    OperationType.multiply,
                    [
                        Constant(2),
                        BinaryOperation(
                            OperationType.plus,
                            [BinaryOperation(OperationType.plus, [aliased_variable_z_new[0], Constant(0x4)]), aliased_variable_x_new[0]],
                        ),
                    ],
                ),
            ),
            Assignment(variable_v_new[6], variable_v_new[5]),
        ]
        and nodes[8].instructions
        == [
            Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("a = %d "), variable_v_new[6]])),
            Return(Constant(0x0)),
        ]
        and len(cfg) == 9
    )

    assert (
        len(cfg.edges) == 14
        and isinstance(cfg.get_edge(nodes[0], nodes[3]), TrueCase)
        and isinstance(cfg.get_edge(nodes[0], nodes[1]), FalseCase)
        and isinstance(cfg.get_edge(nodes[3], nodes[8]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[1], nodes[2]), SwitchCase)
        and isinstance(cfg.get_edge(nodes[1], nodes[3]), SwitchCase)
        and isinstance(cfg.get_edge(nodes[1], nodes[4]), SwitchCase)
        and isinstance(cfg.get_edge(nodes[1], nodes[5]), SwitchCase)
        and isinstance(cfg.get_edge(nodes[1], nodes[6]), SwitchCase)
        and isinstance(cfg.get_edge(nodes[1], nodes[7]), SwitchCase)
        and isinstance(cfg.get_edge(nodes[2], nodes[8]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[4], nodes[8]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[5], nodes[8]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[6], nodes[8]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[7], nodes[8]), UnconditionalEdge)
        and cfg.get_edge(nodes[1], nodes[2]).cases == [Constant(0)]
        and cfg.get_edge(nodes[1], nodes[3]).cases == [Constant(1)]
        and cfg.get_edge(nodes[1], nodes[4]).cases == [Constant(2)]
        and cfg.get_edge(nodes[1], nodes[5]).cases == [Constant(3)]
        and cfg.get_edge(nodes[1], nodes[6]).cases == [Constant(4)]
        and cfg.get_edge(nodes[1], nodes[7]).cases == [Constant(5)]
    )


# tests for "minimization" Out-of-SSA:
def test_no_dependency_unconditional_edge_minimization(graph_no_dependency, variable_x, variable, copy_variable):
    """Here we test whether Phi-functions, without dependency and where one ingoing edge is not unconditional, are lifted correctly.
    +------------------------+      +--------------------------+
    |       0.               |      |        0.                |
    |   printf(0x804b00c)    |      |    printf(0x804b00c)     |
    +------------------------+      |    copy_var_1 = var_1    |
      |                             +--------------------------+
      |                               |
      v                               |
    +------------------------+        v
    |       1.               |      +--------------------------+
    |    x#3 = ϕ(x#2,x#4)    |      |        1.                |
    |    v#2 = ϕ(v#1,v#3)    |      |    var_1 = copy_var_1    |
    |    u#2 = ϕ(u#1,u#3)    |      |    var_2 = var_3         |
    |    y#4 = ϕ(y#3,y#5)    |      |    if(var_1 <= var_2)    | <+
    |    u#3 = y#4           |      +--------------------------+  |
    |     if(v#2 <= u#3)     |      +--------------------------+  |
    +------------------------+      |        2.                |  |
      ^                             | printf(0x804b045, var_1) |  |
      |                             |     if(var_1 == 0x5)     |  |
      |                             +--------------------------+  |
    +------------------------+        |                           |
    |       2.               |        |                           |
    |   x#4 = v#2            |        v                           |
    | printf(0x804b045, x#4) |      +--------------------------+  |
    |     if(x#4 == 0x5)     |      |        3.                |  |
    +------------------------+      |    copy_var_1 = var_0    |  |
                                    |    var_0 = var_1         | -+
                                    +--------------------------+
    """
    nodes, instructions, cfg = graph_no_dependency
    cfg.substitute_edge(cfg.get_edge(nodes[2], nodes[1]), TrueCase(nodes[2], nodes[1]))
    nodes[2].instructions.append(Branch(Condition(OperationType.equal, [variable_x[4], Constant(5)])))

    run_out_of_ssa(cfg, SSAOptions.minimization)

    new_node = [node for node in cfg.nodes if node not in set(nodes)][0]
    # variable y is aliased, to variable[3] must be aliased
    variable[3].is_aliased = True

    assert (
        nodes[0].instructions == [instructions[0], Assignment(copy_variable[1], variable[1])]
        and nodes[1].instructions
        == [
            Assignment(variable[1], copy_variable[1]),
            Assignment(variable[2], variable[3]),
            Branch(Condition(OperationType.less_or_equal, [variable[1], variable[2]])),
        ]
        and nodes[2].instructions
        == [
            Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804B045), variable[1]])),
            Branch(Condition(OperationType.equal, [variable[1], Constant(5)])),
        ]
        and new_node.instructions == [Assignment(copy_variable[1], variable[0]), Assignment(variable[0], variable[1])]
    )

    assert (
        len(cfg.edges) == 3
        and isinstance(cfg.get_edge(nodes[0], nodes[1]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[2], new_node), TrueCase)
        and isinstance(cfg.get_edge(new_node, nodes[1]), UnconditionalEdge)
    )


def test_dependency_but_no_circle_minimization(graph_dependency_but_not_circular, aliased_variable_y, variable_u, variable, copy_variable):
    """Here we test whether Phi-functions, with dependency, but no circular dependency and where one ingoing edge is not unconditional,
        are lifted correctly.
                                   +--------------------------+                                             +----------------------------+
                                   |            0.            |                                             |             0.             |
                                   |    printf(0x804a00c)     |                                             |     printf(0x804a00c)      |
                                   | scanf(0x804a025, &(y#1)) |                                             | scanf(0x804a025, &(var_0)) |
                                   |  printf(0x804a028, y#1)  |                                             |  printf(0x804a028, var_0)  |
                                   +--------------------------+                                             |     copy_var_0 = var_0     |
                                     |                                                                      +----------------------------+
                                     |                                                                        |
                                     v                                                                        |
    +------------------------+     +------------------------------------+                                     v
    |           2.           |     |                 1.                 |  +--------------------------+     +--------------------------------------+
    | printf(0x804a049, u#3) |     |        u#3 = ϕ(y#1,y#4,y#4)        |  |            2.            |     |                  1.                  |
    |       return 0x0       |     |        y#4 = ϕ(y#1,y#7,v#4)        |  | printf(0x804a049, var_2) |     |            var_2 = var_0             |
    |                        | <-- |           if(y#4 <= 0x0)           |  |        return 0x0        |     |          var_0 = copy_var_0          |
    +------------------------+     +------------------------------------+  |                          | <-- |           if(var_0 <= 0x0)           |
                                     |                           ^    ^    +--------------------------+     +--------------------------------------+
                                     |                           |    |                                       |                             ^    ^
                                     v                           |    |                                       |                             |    |
                                   +--------------------------+  |    |                                       v                             |    |
                                   |            3.            |  |    |    +--------------------------+     +----------------------------+  |    |
                                   |  printf(0x804a045, y#4)  |  |    |    |                          |     |             3.             |  |    |
                                   |     y#7 = y#4 - 0x2      |  |    |    |            5.            |     |  printf(0x804a045, var_0)  |  |    |
                                   |    v#2 = is_odd(y#7)     |  |    |    |    copy_var_0 = var_1    |     |    var_1 = var_0 - 0x2     |  |    |
                                   | if((v#2 & 0xff) == 0x0)  | -+    |    |                          |     |   var_2 = is_odd(var_1)    |  |    |
                                   +--------------------------+       |    |                          | <-- | if((var_2 & 0xff) == 0x0)  |  |    |
                                     |                                |    +--------------------------+     +----------------------------+  |    |
                                     |                                |      |                                |                             |    |
                                     v                                |      |                                |                             |    |
                                   +--------------------------+       |      |                                v                             |    |
                                   |            4.            |       |      |                              +----------------------------+  |    |
                                   |     v#4 = y#7 - 0x1      | ------+      |                              |             4.             |  |    |
                                   +--------------------------+              |                              |    var_2 = var_1 - 0x1     |  |    |
                                                                             |                              |     copy_var_0 = var_2     | -+    |
                                                                             |                              +----------------------------+       |
                                                                             |                                                                   |
                                                                             +-------------------------------------------------------------------+
    """
    nodes, _, cfg = graph_dependency_but_not_circular
    new_phi = Phi(variable_u[3], [aliased_variable_y[1], aliased_variable_y[4], aliased_variable_y[4]])
    new_phi._origin_block = {nodes[0]: aliased_variable_y[1], nodes[3]: aliased_variable_y[4], nodes[4]: aliased_variable_y[4]}
    nodes[1].instructions[0] = new_phi

    run_out_of_ssa(cfg, SSAOptions.minimization)

    new_node = [node for node in cfg.nodes if node not in set(nodes)][0]
    # variable y is aliased, so variable[0], variable[1], and copy_variable[0] must be aliased
    variable[0].is_aliased = True
    variable[1].is_aliased = True
    copy_variable[0].is_aliased = True

    new_node = [node for node in cfg.nodes if node not in set(nodes)][0]

    assert (
        nodes[0].instructions
        == [
            Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804A00C)])),
            Assignment(
                ListOperation([]),
                Call(imp_function_symbol("scanf"), [Constant(0x804A025), UnaryOperation(OperationType.address, [variable[0]])]),
            ),
            Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804A028), variable[0]])),
            Assignment(copy_variable[0], variable[0]),
        ]
        and nodes[1].instructions
        == [
            Assignment(variable[2], variable[0]),
            Assignment(variable[0], copy_variable[0]),
            Branch(Condition(OperationType.less_or_equal, [variable[0], Constant(0x0)])),
        ]
        and nodes[2].instructions
        == [Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804A049), variable[2]])), Return([Constant(0x0)])]
        and nodes[3].instructions
        == [
            Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804A045), variable[0]])),
            Assignment(variable[1], BinaryOperation(OperationType.minus, [variable[0], Constant(0x2)])),
            Assignment(variable[2], Call(function_symbol("is_odd"), [variable[1]])),
            Branch(
                Condition(OperationType.equal, [BinaryOperation(OperationType.bitwise_and, [variable[2], Constant(0xFF)]), Constant(0x0)])
            ),
        ]
        and nodes[4].instructions
        == [
            Assignment(variable[2], BinaryOperation(OperationType.minus, [variable[1], Constant(0x1)])),
            Assignment(copy_variable[0], variable[2]),
        ]
        and new_node.instructions == [Assignment(copy_variable[0], variable[1])]
    )

    assert (
        len(cfg.edges) == 7
        and isinstance(cfg.get_edge(nodes[0], nodes[1]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[1], nodes[2]), FalseCase)
        and isinstance(cfg.get_edge(nodes[1], nodes[3]), TrueCase)
        and isinstance(cfg.get_edge(nodes[3], new_node), TrueCase)
        and isinstance(cfg.get_edge(new_node, nodes[1]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[3], nodes[4]), FalseCase)
        and isinstance(cfg.get_edge(nodes[4], nodes[1]), UnconditionalEdge)
    )


def test_circular_dependency_minimization(graph_circular_dependency, variable, copy_variable):
    """Here we test whether Phi-functions, with circular dependency and where all ingoing edges are unconditional, are lifted correctly.
                                   +-----------------------+                                      +-------------------------+
                                   |          0.           |                                      |           0.            |
                                   |   printf(0x804b00c)   |                                      |    printf(0x804b00c)    |
                                   |     x#1 = &(y#1)      |                                      |    var_2 = &(var_0)     |
                                   | scanf(0x804b01f, x#1) |                                      | scanf(0x804b01f, var_2) |
                                   |       y#2 = y#1       |                                      |    printf(0x804bb0c)    |
                                   |   printf(0x804bb0c)   |                                      |    var_3 = &(var_1)     |
                                   |     v#1 = &(z#3)      |                                      | scanf(0x804bb1f, var_3) |
                                   | scanf(0x804bb1f, v#1) |                                      |   copy_var_3 = var_3    |
                                   +-----------------------+                                      |      var_4 = var_2      |
                                     |                                                            |       var_2 = 0x1       |
                                     |                                                            +-------------------------+
                                     v                                                              |
    +------------------------+     +-----------------------+                                        |
    |                        |     |          1.           |                                        v
    |           3.           |     |   x#2 = ϕ(x#1,v#2)    |     +--------------------------+     +-------------------------+
    | printf(0x804bb0c, x#2) |     |   v#2 = ϕ(v#1,x#2)    |     |            3.            |     |           1.            |
    |                        |     |   u#2 = ϕ(0x1,u#1)    |     | printf(0x804bb0c, var_4) |     |   var_3 = copy_var_3    |
    |                        | <-- |    if(u#2 <= 0x14)    | <+  |                          | <-- |    if(var_2 <= 0x14)    | <+
    +------------------------+     +-----------------------+  |  +--------------------------+     +-------------------------+  |
                                     |                        |                                     |                          |
                                     |                        |                                     |                          |
                                     v                        |                                     v                          |
                                   +-----------------------+  |                                   +-------------------------+  |
                                   |          2.           |  |                                   |           2.            |  |
                                   |    u#1 = u#2 + 0x1    | -+                                   |   var_2 = var_2 + 0x1   |  |
                                   +-----------------------+                                      |   copy_var_3 = var_4    |  |
                                                                                                  |      var_4 = var_3      | -+
                                                                                                  +-------------------------+
    """
    nodes, _, cfg = graph_circular_dependency

    run_out_of_ssa(cfg, SSAOptions.minimization)

    # variables y and z are aliased, so variable[0] and variable[1] must be aliased
    variable[0].is_aliased = True
    variable[1].is_aliased = True

    assert (
        nodes[0].instructions
        == [
            Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804B00C)])),
            Assignment(variable[2], UnaryOperation(OperationType.address, [variable[0]], Integer.int32_t())),
            Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [Constant(0x804B01F), variable[2]])),
            Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804BB0C)])),
            Assignment(variable[3], UnaryOperation(OperationType.address, [variable[1]], Integer.int32_t())),
            Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [Constant(0x804BB1F), variable[3]])),
            Assignment(copy_variable[3], variable[3]),
            Assignment(variable[4], variable[2]),
            Assignment(variable[2], Constant(0x1)),
        ]
        and nodes[1].instructions
        == [
            Assignment(variable[3], copy_variable[3]),
            Branch(Condition(OperationType.less_or_equal, [variable[2], Constant(20)])),
        ]
        and nodes[2].instructions
        == [
            Assignment(variable[2], BinaryOperation(OperationType.plus, [variable[2], Constant(1)])),
            Assignment(copy_variable[3], variable[4]),
            Assignment(variable[4], variable[3]),
        ]
        and nodes[3].instructions
        == [
            Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804BB0C), variable[4]])),
        ]
    )

    assert (
        len(cfg.edges) == 4
        and isinstance(cfg.get_edge(nodes[0], nodes[1]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[1], nodes[2]), TrueCase)
        and isinstance(cfg.get_edge(nodes[1], nodes[3]), FalseCase)
        and isinstance(cfg.get_edge(nodes[2], nodes[1]), UnconditionalEdge)
    )


def test_graph_with_input_arguments_more_variable_types_minimization(graph_with_input_arguments_different_variable_types_2, variable):
    """Graph where we have input arguments and where there is more than one variable type.
                       +----------------------------------+     +--------------+     +-----------------------------------------+
                       |                0.                |     |      8.      |     |                   0.                    |
                       | if(arg2#0 < arg1#0)              | -+  | arg2 = arg1  | <-- | if(arg2 < arg1)                         |
                       +----------------------------------+  |  +--------------+     +-----------------------------------------+
                         |                                   |    |                    |
                         |                                   |    |                    |
                         v                                   |    |                    v
                       +----------------------------------+  |    |                  +-----------------------------------------+
                       |                1.                |  |    |                  |                   1.                    |
                       +----------------------------------+  |    |                  +-----------------------------------------+
                         |                                   |    |                    |
                         |                                   |    |                    |
                         v                                   |    |                    v
                       +----------------------------------+  |    |                  +-----------------------------------------+
                       |                2.                |  |    |                  |                   2.                    |
                       | arg2#2 = ϕ(arg2#0,arg1#0)        |  |    +----------------> | if(arg1 > (arg2 + arg2))                | -+
                    +- | if(arg1#0 > (arg2#2 + arg2#2))   | <+                       +-----------------------------------------+  |
                    |  +----------------------------------+                            |                                          |
                    |    |                                                             |                                          |
                    |    |                                                             v                                          |
                    |    v                                                           +-----------------------------------------+  |
                    |  +----------------------------------+                          |                   3.                    |  |
                    |  |                3.                |                          | arg2 = arg1 - arg2                      |  |
                    |  | arg2#3 = arg1#0 - arg2#2         |                          +-----------------------------------------+  |
                    |  +----------------------------------+                            |                                          |
                    |    |                                                             |                                          |
                    |    |                                                             v                                          |
                    |    v                                                           +-----------------------------------------+  |
                    |  +----------------------------------+                          |                   4.                    |  |
                    |  |                4.                |                          | arg1 = (arg1 - arg2) + 0x1              |  |
                    |  | arg2#4 = ϕ(arg2#2,arg2#3)        |                          | var_0 = arg1                            |  |
                    +> | v#1 = (arg1#0 - arg2#4) + 0x1    |                          | var_1 = 0x1                             |  |
                       +----------------------------------+                          | arg1 = 0x1                              | <+
                         |                                                           +-----------------------------------------+
                         |                                                             |
                         v                                                             |
    +------------+     +----------------------------------+                            v
    |            |     |                5.                |     +--------------+     +-----------------------------------------+
    |     7.     |     | u#2 = ϕ(0x1,u#5)                 |     |      7.      |     |                   5.                    |
    | return x#2 |     | v#2 = ϕ(v#1,v#2)                 |     | return var_1 | <-- | if(arg1 <= arg2)                        | <+
    |            |     | x#2 = ϕ(0x1,y#1)                 |     +--------------+     +-----------------------------------------+  |
    |            | <-- | if(u#2 <= arg2#4)                | <+                         |                                          |
    +------------+     +----------------------------------+  |                         |                                          |
                         |                                   |                         v                                          |
                         |                                   |                       +-----------------------------------------+  |
                         v                                   |                       |                   6.                    |  |
                       +----------------------------------+  |                       | var_2 = arg1 + 0x1                      |  |
                       |                6.                |  |                       | var_3 = (((long) var_0) * var_1) / arg1 |  |
                       | u#5 = u#2 + 0x1                  |  |                       | var_1 = var_3                           |  |
                       | y#1 = (((long) v#2) * x#2) / u#2 | -+                       | arg1 = var_2                            | -+
                       +----------------------------------+                          +-----------------------------------------+
    """
    nodes, cfg = graph_with_input_arguments_different_variable_types_2
    run_out_of_ssa(
        cfg,
        SSAOptions.minimization,
        arguments=[argument1 := Variable("arg1", Integer.int32_t()), argument2 := Variable("arg2", Integer.int32_t())],
    )

    new_node = [node for node in cfg.nodes if node not in set(nodes)][0]
    variable[3] = Variable("var_3", Integer.int64_t())

    assert (
        nodes[0].instructions == [Branch(Condition(OperationType.less, [argument2, argument1]))]
        and nodes[1].instructions == []
        and nodes[2].instructions
        == [Branch(Condition(OperationType.greater, [argument1, BinaryOperation(OperationType.plus, [argument2, argument2])]))]
        and nodes[3].instructions == [Assignment(argument2, BinaryOperation(OperationType.minus, [argument1, argument2]))]
        and nodes[4].instructions
        == [
            Assignment(
                argument1,
                BinaryOperation(OperationType.plus, [BinaryOperation(OperationType.minus, [argument1, argument2]), Constant(0x1)]),
            ),
            Assignment(variable[0], argument1),
            Assignment(variable[1], Constant(0x1)),
            Assignment(argument1, Constant(0x1)),
        ]
        and nodes[5].instructions == [Branch(Condition(OperationType.less_or_equal, [argument1, argument2]))]
        and nodes[6].instructions
        == [
            Assignment(variable[2], BinaryOperation(OperationType.plus, [argument1, Constant(0x1)])),
            Assignment(
                variable[3],
                BinaryOperation(
                    OperationType.divide,
                    [
                        BinaryOperation(
                            OperationType.multiply,
                            [UnaryOperation(OperationType.cast, [variable[0]], vartype=Integer.int64_t()), variable[1]],
                        ),
                        argument1,
                    ],
                ),
            ),
            Assignment(variable[1], variable[3]),
            Assignment(argument1, variable[2]),
        ]
        and nodes[7].instructions == [Return([variable[1]])]
        and new_node.instructions == [Assignment(argument2, argument1)]
        and len(cfg) == 9
    )

    assert (
        len(cfg.edges) == 11
        and isinstance(cfg.get_edge(nodes[0], nodes[1]), TrueCase)
        and isinstance(cfg.get_edge(nodes[0], new_node), FalseCase)
        and isinstance(cfg.get_edge(new_node, nodes[2]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[1], nodes[2]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[2], nodes[3]), FalseCase)
        and isinstance(cfg.get_edge(nodes[2], nodes[4]), TrueCase)
        and isinstance(cfg.get_edge(nodes[3], nodes[4]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[4], nodes[5]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[5], nodes[6]), TrueCase)
        and isinstance(cfg.get_edge(nodes[5], nodes[7]), FalseCase)
        and isinstance(cfg.get_edge(nodes[6], nodes[5]), UnconditionalEdge)
    )


def test_graph_with_edge_condition_minimization(graph_with_edge_condition, variable):
    """Graph, where we have conditions on some edges."""
    nodes, cfg = graph_with_edge_condition
    run_out_of_ssa(cfg, SSAOptions.minimization)

    # variables x, y and z are aliased, so variable[0], variable[1], and variable[2] must be aliased
    variable[0].is_aliased = True
    variable[1].is_aliased = True
    variable[2].is_aliased = True

    assert (
        nodes[0].instructions
        == [
            Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("Enter your choice = ")])),
            Assignment(
                ListOperation([]),
                Call(imp_function_symbol("scanf"), [Constant(0x804A025), UnaryOperation(OperationType.address, [variable[0]])]),
            ),
            Assignment(ListOperation([]), Call(imp_function_symbol("puts"), [Constant("Enter a number ")])),
            Assignment(
                ListOperation([]),
                Call(imp_function_symbol("scanf"), [Constant(0x804A025), UnaryOperation(OperationType.address, [variable[1]])]),
            ),
            Assignment(ListOperation([]), Call(imp_function_symbol("puts"), [Constant("Enter a second number ")])),
            Assignment(
                ListOperation([]),
                Call(imp_function_symbol("scanf"), [Constant(0x804A025), UnaryOperation(OperationType.address, [variable[2]])]),
            ),
            Branch(Condition(OperationType.greater, [variable[0], Constant(0x5)])),
        ]
        and nodes[1].instructions == [IndirectBranch(variable[0])]
        and nodes[2].instructions
        == [
            Assignment(ListOperation([]), Call(imp_function_symbol("puts"), [Constant("default !")])),
            Assignment(variable[3], Constant(0x0)),
        ]
        and nodes[3].instructions
        == [
            Assignment(
                variable[3],
                BinaryOperation(
                    OperationType.multiply,
                    [BinaryOperation(OperationType.plus, [variable[1], Constant(0x1)]), variable[2]],
                ),
            ),
        ]
        and nodes[4].instructions
        == [
            Assignment(
                variable[3],
                BinaryOperation(
                    OperationType.plus,
                    [BinaryOperation(OperationType.plus, [variable[1], Constant(0x2)]), variable[2]],
                ),
            ),
        ]
        and nodes[5].instructions
        == [
            Assignment(
                variable[3],
                BinaryOperation(
                    OperationType.minus,
                    [variable[2], BinaryOperation(OperationType.plus, [variable[1], Constant(0x3)])],
                ),
            ),
        ]
        and nodes[6].instructions
        == [
            Assignment(
                variable[3],
                BinaryOperation(
                    OperationType.minus,
                    [BinaryOperation(OperationType.plus, [variable[1], Constant(0x4)]), variable[2]],
                ),
            ),
        ]
        and nodes[7].instructions
        == [
            Assignment(
                variable[3],
                BinaryOperation(
                    OperationType.multiply,
                    [
                        Constant(2),
                        BinaryOperation(
                            OperationType.plus,
                            [BinaryOperation(OperationType.plus, [variable[1], Constant(0x4)]), variable[2]],
                        ),
                    ],
                ),
            ),
        ]
        and nodes[8].instructions
        == [Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("a = %d "), variable[3]])), Return(Constant(0x0))]
        and len(cfg) == 9
    )

    assert (
        len(cfg.edges) == 14
        and isinstance(cfg.get_edge(nodes[0], nodes[3]), TrueCase)
        and isinstance(cfg.get_edge(nodes[0], nodes[1]), FalseCase)
        and isinstance(cfg.get_edge(nodes[3], nodes[8]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[1], nodes[2]), SwitchCase)
        and isinstance(cfg.get_edge(nodes[1], nodes[3]), SwitchCase)
        and isinstance(cfg.get_edge(nodes[1], nodes[4]), SwitchCase)
        and isinstance(cfg.get_edge(nodes[1], nodes[5]), SwitchCase)
        and isinstance(cfg.get_edge(nodes[1], nodes[6]), SwitchCase)
        and isinstance(cfg.get_edge(nodes[1], nodes[7]), SwitchCase)
        and isinstance(cfg.get_edge(nodes[2], nodes[8]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[4], nodes[8]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[5], nodes[8]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[6], nodes[8]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[7], nodes[8]), UnconditionalEdge)
        and cfg.get_edge(nodes[1], nodes[2]).cases == [Constant(0)]
        and cfg.get_edge(nodes[1], nodes[3]).cases == [Constant(1)]
        and cfg.get_edge(nodes[1], nodes[4]).cases == [Constant(2)]
        and cfg.get_edge(nodes[1], nodes[5]).cases == [Constant(3)]
        and cfg.get_edge(nodes[1], nodes[6]).cases == [Constant(4)]
        and cfg.get_edge(nodes[1], nodes[7]).cases == [Constant(5)]
    )


def test_graph_with_phi_fct_in_head_minimization1(graph_phi_fct_in_head1, variable, copy_variable):
    """Graph where the head has a Phi-function and therefore a Phi-value has no predecessor."""
    nodes, cfg = graph_phi_fct_in_head1
    run_out_of_ssa(cfg, SSAOptions.minimization)
    new_nodes = [nd for nd in cfg.nodes if nd != nodes[0]]

    assert (
        len(cfg) == 2
        and nodes[0].instructions
        == [
            Assignment(variable[0], copy_variable[0]),
            Assignment(variable[1], BinaryOperation(OperationType.plus, [variable[1], Constant(10)])),
            Assignment(copy_variable[0], variable[1]),
            Assignment(variable[1], variable[0]),
        ]
        and new_nodes[0].instructions
        == [
            Assignment(copy_variable[0], variable[1]),
        ]
    )

    assert (
        len(cfg.edges) == 2
        and isinstance(cfg.get_edge(new_nodes[0], nodes[0]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[0], nodes[0]), UnconditionalEdge)
    )


def test_graph_with_phi_fct_in_head_minimization2(graph_phi_fct_in_head2, variable, copy_variable):
    """Graph where the head has a Phi-function and therefore a Phi-value has no predecessor."""
    nodes, cfg = graph_phi_fct_in_head2
    run_out_of_ssa(cfg, SSAOptions.minimization)
    new_nodes = [nd for nd in cfg.nodes if nd != nodes[0]]

    assert (
        len(cfg) == 2
        and nodes[0].instructions
        == [
            Assignment(variable[1], copy_variable[1]),
            Assignment(variable[1], BinaryOperation(OperationType.plus, [variable[0], variable[1]])),
            Assignment(copy_variable[1], variable[0]),
            Assignment(variable[0], variable[1]),
        ]
        and new_nodes[0].instructions
        == [
            Assignment(copy_variable[1], variable[1]),
        ]
    )

    assert (
        len(cfg.edges) == 2
        and isinstance(cfg.get_edge(new_nodes[0], nodes[0]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[0], nodes[0]), UnconditionalEdge)
    )


def test_graph_with_relation_minimization(graph_with_relation, variable):
    """
        test minimization SSA with relation test loop test 2.
        Output:
                                            +----------------------------------+
                                            |                0.                |
                                            |         var_3 = &(var_0)         |
                                            | __isoc99_scanf(0x804b01f, var_3) |
                                            |    var_2 = var_0 * 0x66666667    |
                                            |       var_2 = var_2 << 0x2       |
                                            |          var_1 = var_0           |
                                            +----------------------------------+
                                              |
                                              |
                                              v
    +---------------------------------+     +----------------------------------+
    |               3.                |     |                1.                |
    | printf((var_0 - var_2) + var_1) |     |         if(var_1 > 0x9)          |
    |           return 0x0            | <-- |                                  | <+
    +---------------------------------+     +----------------------------------+  |
                                              |                                   |
                                              |                                   |
                                              v                                   |
                                            +----------------------------------+  |
                                            |                2.                |  |
                                            |    var_1 = var_1 * 0x66666667    | -+
                                            +----------------------------------+
    """
    nodes, cfg = graph_with_relation
    run_out_of_ssa(cfg, SSAOptions.minimization)
    variable[0].is_aliased = True
    variable[1].is_aliased = True
    variable[3]._type = Pointer(Integer(32, True), 32)

    assert (
        len(cfg) == 4
        and nodes[0].instructions
        == [
            Assignment(variable[3], UnaryOperation(OperationType.address, [variable[0]], Pointer(Integer(32, True), 32), None, False)),
            Assignment(
                ListOperation([]),
                Call(
                    Constant("__isoc99_scanf", UnknownType()),
                    [Constant(134524959, Integer(32, True)), variable[3]],
                    Pointer(CustomType("void", 0), 32),
                    2,
                ),
            ),
            Assignment(
                variable[2],
                BinaryOperation(OperationType.multiply, [variable[0], Constant(1717986919, Integer(32, True))], Integer(64, True)),
            ),
            Assignment(
                variable[2],
                BinaryOperation(OperationType.left_shift, [variable[2], Constant(2, Integer(32, True))], Integer(32, True)),
            ),
            Assignment(variable[1], variable[0]),
        ]
        and nodes[1].instructions
        == [Branch(Condition(OperationType.greater, [variable[1], Constant(9, Integer(32, True))], CustomType("bool", 1)))]
        and nodes[2].instructions
        == [
            Assignment(
                variable[1],
                BinaryOperation(OperationType.multiply, [variable[1], Constant(1717986919, Integer(32, True))], Integer(64, True)),
            )
        ]
        and nodes[3].instructions
        == [
            Assignment(
                ListOperation([]),
                Call(
                    Constant("printf", UnknownType()),
                    [
                        BinaryOperation(
                            OperationType.plus,
                            [BinaryOperation(OperationType.minus, [variable[0], variable[2]], Integer(32, True)), variable[1]],
                            Integer(32, True),
                        ),
                    ],
                    Pointer(CustomType("void", 0), 32),
                    5,
                ),
            ),
            Return(ListOperation([Constant(0, Integer(32, True))])),
        ]
    )


# tests for "lift_minimal" Out-of-SSA:
def test_no_dependency_unconditional_edge_lift_minimal(graph_no_dependency, variable_x, variable):
    """Here we test whether Phi-functions, without dependency and where one ingoing edge is not unconditional, are lifted correctly.
    +------------------------+  +--------------------------+
    |           0.           |  |            0.            |
    |   printf(0x804b00c)    |  |    printf(0x804b00c)     |
    +------------------------+  +--------------------------+
      |                           |
      |                           |
      v                           v
    +------------------------+  +--------------------------+
    |           1.           |  |            1.            |
    |    x#3 = ϕ(x#2,x#4)    |  |      var_2 = var_4       |
    |    v#2 = ϕ(v#1,v#3)    |  |    if(var_1 <= var_2)    | <+
    |    u#2 = ϕ(u#1,u#3)    |  +--------------------------+  |
    |    y#4 = ϕ(y#3,y#5)    |  +--------------------------+  |
    |       u#3 = y#4        |  |            2.            |  |
    |     if(v#2 <= u#3)     |  |      var_0 = var_1       |  |
    +------------------------+  | printf(0x804b045, var_0) |  |
      ^                         |     if(var_0 == 0x5)     |  |
      |                         +--------------------------+  |
      |                           |                           |
    +------------------------+    |                           |
    |           2.           |    v                           |
    |       x#4 = v#2        |  +--------------------------+  |
    | printf(0x804b045, x#4) |  |            3.            |  |
    |     if(x#4 == 0x5)     |  |      var_1 = var_3       | -+
    +------------------------+  +--------------------------+
    """
    nodes, _, cfg = graph_no_dependency
    cfg.substitute_edge(cfg.get_edge(nodes[2], nodes[1]), TrueCase(nodes[2], nodes[1]))
    nodes[2].instructions.append(Branch(Condition(OperationType.equal, [variable_x[4], Constant(5)])))

    run_out_of_ssa(cfg, SSAOptions.lift_minimal)

    # variable y is aliased, so variable[4] must be aliased
    variable[4].is_aliased = True

    new_node = [node for node in cfg.nodes if node not in set(nodes)][0]

    assert (
        nodes[0].instructions == [Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804B00C)]))]
        and nodes[1].instructions
        == [
            Assignment(variable[2], variable[4]),
            Branch(Condition(OperationType.less_or_equal, [variable[1], variable[2]], "bool")),
        ]
        and nodes[2].instructions
        == [
            Assignment(variable[0], variable[1]),
            Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804B045), variable[0]])),
            Branch(Condition(OperationType.equal, [variable[0], Constant(5)])),
        ]
        and new_node.instructions == [Assignment(variable[1], variable[3])]
    )

    assert (
        len(cfg.edges) == 3
        and isinstance(cfg.get_edge(nodes[0], nodes[1]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[2], new_node), TrueCase)
        and isinstance(cfg.get_edge(new_node, nodes[1]), UnconditionalEdge)
    )


def test_dependency_but_no_circle_lift_minimal(graph_dependency_but_not_circular, aliased_variable_y, variable_u, variable):
    """Here we test whether Phi-functions, with dependency, but no circular dependency and where one ingoing edge is not unconditional,
        are lifted correctly.
                                   +--------------------------+                                             +----------------------------+
                                   |            0.            |                                             |             0.             |
                                   |    printf(0x804a00c)     |                                             |     printf(0x804a00c)      |
                                   | scanf(0x804a025, &(y#1)) |                                             | scanf(0x804a025, &(var_0)) |
                                   |  printf(0x804a028, y#1)  |                                             |  printf(0x804a028, var_0)  |
                                   +--------------------------+                                             |       var_2 = var_0        |
                                     |                                                                      +----------------------------+
                                     |                                                                        |
                                     v                                                                        |
    +------------------------+     +------------------------------------+                                     v
    |           2.           |     |                 1.                 |  +--------------------------+     +--------------------------------------+
    | printf(0x804a049, u#3) |     |        u#3 = ϕ(y#1,y#4,y#4)        |  |            2.            |     |                  1.                  |
    |       return 0x0       |     |        y#4 = ϕ(y#1,y#7,v#4)        |  | printf(0x804a049, var_2) |     |           if(var_0 <= 0x0)           |
    |                        | <-- |           if(y#4 <= 0x0)           |  |        return 0x0        | <-- |                                      |
    +------------------------+     +------------------------------------+  +--------------------------+     +--------------------------------------+
                                     |                           ^    ^                                       |                             ^    ^
                                     |                           |    |                                       |                             |    |
                                     v                           |    |                                       v                             |    |
                                   +--------------------------+  |    |    +--------------------------+     +----------------------------+  |    |
                                   |            3.            |  |    |    |                          |     |             3.             |  |    |
                                   |  printf(0x804a045, y#4)  |  |    |    |            5.            |     |  printf(0x804a045, var_0)  |  |    |
                                   |     y#7 = y#4 - 0x2      |  |    |    |      var_2 = var_0       |     |    var_1 = var_0 - 0x2     |  |    |
                                   |    v#2 = is_odd(y#7)     |  |    |    |      var_0 = var_1       |     |   var_3 = is_odd(var_1)    |  |    |
                                   | if((v#2 & 0xff) == 0x0)  | -+    |    |                          | <-- | if((var_3 & 0xff) == 0x0)  |  |    |
                                   +--------------------------+       |    +--------------------------+     +----------------------------+  |    |
                                     |                                |      |                                |                             |    |
                                     |                                |      |                                |                             |    |
                                     v                                |      |                                v                             |    |
                                   +--------------------------+       |      |                              +----------------------------+  |    |
                                   |            4.            |       |      |                              |             4.             |  |    |
                                   |     v#4 = y#7 - 0x1      | ------+      |                              |    var_3 = var_1 - 0x1     |  |    |
                                   +--------------------------+              |                              |       var_2 = var_0        |  |    |
                                                                             |                              |       var_0 = var_3        | -+    |
                                                                             |                              +----------------------------+       |
                                                                             |                                                                   |
                                                                             +-------------------------------------------------------------------+
    """
    nodes, _, cfg = graph_dependency_but_not_circular
    new_phi = Phi(variable_u[3], [aliased_variable_y[1], aliased_variable_y[4], aliased_variable_y[4]])
    new_phi._origin_block = {nodes[0]: aliased_variable_y[1], nodes[3]: aliased_variable_y[4], nodes[4]: aliased_variable_y[4]}
    nodes[1].instructions[0] = new_phi

    run_out_of_ssa(cfg, SSAOptions.lift_minimal)

    # variable y is aliased, so variable[0] and variable[1] must be aliased
    variable[0].is_aliased = True
    variable[1].is_aliased = True

    new_node = [node for node in cfg.nodes if node not in set(nodes)][0]

    assert (
        nodes[0].instructions
        == [
            Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804A00C)])),
            Assignment(
                ListOperation([]),
                Call(imp_function_symbol("scanf"), [Constant(0x804A025), UnaryOperation(OperationType.address, [variable[0]])]),
            ),
            Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804A028), variable[0]])),
            Assignment(variable[2], variable[0]),
        ]
        and nodes[1].instructions
        == [
            Branch(Condition(OperationType.less_or_equal, [variable[0], Constant(0x0)])),
        ]
        and nodes[2].instructions
        == [Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804A049), variable[2]])), Return([Constant(0x0)])]
        and nodes[3].instructions
        == [
            Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804A045), variable[0]])),
            Assignment(variable[1], BinaryOperation(OperationType.minus, [variable[0], Constant(0x2)])),
            Assignment(variable[3], Call(function_symbol("is_odd"), [variable[1]])),
            Branch(
                Condition(OperationType.equal, [BinaryOperation(OperationType.bitwise_and, [variable[3], Constant(0xFF)]), Constant(0x0)])
            ),
        ]
        and nodes[4].instructions
        == [
            Assignment(variable[3], BinaryOperation(OperationType.minus, [variable[1], Constant(0x1)])),
            Assignment(variable[2], variable[0]),
            Assignment(variable[0], variable[3]),
        ]
        and new_node.instructions == [Assignment(variable[2], variable[0]), Assignment(variable[0], variable[1])]
    )

    assert (
        len(cfg.edges) == 7
        and isinstance(cfg.get_edge(nodes[0], nodes[1]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[1], nodes[2]), FalseCase)
        and isinstance(cfg.get_edge(nodes[1], nodes[3]), TrueCase)
        and isinstance(cfg.get_edge(nodes[3], new_node), TrueCase)
        and isinstance(cfg.get_edge(new_node, nodes[1]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[3], nodes[4]), FalseCase)
        and isinstance(cfg.get_edge(nodes[4], nodes[1]), UnconditionalEdge)
    )


def test_circular_dependency_lift_minimal(graph_circular_dependency, variable):
    """Here we test whether Phi-functions, with circular dependency and where all ingoing edges are unconditional, are lifted correctly.
                                   +-----------------------+                                      +-------------------------+
                                   |          0.           |                                      |           0.            |
                                   |   printf(0x804b00c)   |                                      |    printf(0x804b00c)    |
                                   |     x#1 = &(y#1)      |                                      |    var_3 = &(var_0)     |
                                   | scanf(0x804b01f, x#1) |                                      | scanf(0x804b01f, var_3) |
                                   |       y#2 = y#1       |                                      |    printf(0x804bb0c)    |
                                   |   printf(0x804bb0c)   |                                      |    var_2 = &(var_1)     |
                                   |     v#1 = &(z#3)      |                                      | scanf(0x804bb1f, var_2) |
                                   | scanf(0x804bb1f, v#1) |                                      |      var_4 = var_3      |
                                   +-----------------------+                                      |       var_3 = 0x1       |
                                     |                                                            +-------------------------+
                                     |                                                              |
                                     v                                                              |
    +------------------------+     +-----------------------+                                        v
    |                        |     |          1.           |     +--------------------------+     +-------------------------+
    |           3.           |     |   x#2 = ϕ(x#1,v#2)    |     |            3.            |     |           1.            |
    | printf(0x804bb0c, x#2) |     |   v#2 = ϕ(v#1,x#2)    |     | printf(0x804bb0c, var_4) |     |      var_5 = var_2      |
    |                        |     |   u#2 = ϕ(0x1,u#1)    |     |                          | <-- |    if(var_3 <= 0x14)    | <+
    |                        | <-- |    if(u#2 <= 0x14)    | <+  +--------------------------+     +-------------------------+  |
    +------------------------+     +-----------------------+  |                                     |                          |
                                     |                        |                                     |                          |
                                     |                        |                                     v                          |
                                     v                        |                                   +-------------------------+  |
                                   +-----------------------+  |                                   |           2.            |  |
                                   |          2.           |  |                                   |   var_3 = var_3 + 0x1   |  |
                                   |    u#1 = u#2 + 0x1    | -+                                   |      var_2 = var_4      |  |
                                   +-----------------------+                                      |      var_4 = var_5      | -+
                                                                                                  +-------------------------+
    """
    nodes, _, cfg = graph_circular_dependency
    run_out_of_ssa(cfg, SSAOptions.lift_minimal)

    # variables y and z are aliased, so variable[0] and variable[1] must be aliased
    variable[0].is_aliased = True
    variable[1].is_aliased = True

    assert (
        nodes[0].instructions
        == [
            Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804B00C)])),
            Assignment(variable[3], UnaryOperation(OperationType.address, [variable[0]], Integer.int32_t())),
            Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [Constant(0x804B01F), variable[3]])),
            Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804BB0C)])),
            Assignment(variable[2], UnaryOperation(OperationType.address, [variable[1]], Integer.int32_t())),
            Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [Constant(0x804BB1F), variable[2]])),
            Assignment(variable[4], variable[3]),
            Assignment(variable[3], Constant(0x1)),
        ]
        and nodes[1].instructions
        == [
            Assignment(variable[5], variable[2]),
            Branch(Condition(OperationType.less_or_equal, [variable[3], Constant(20)])),
        ]
        and nodes[2].instructions
        == [
            Assignment(variable[3], BinaryOperation(OperationType.plus, [variable[3], Constant(1)])),
            Assignment(variable[2], variable[4]),
            Assignment(variable[4], variable[5]),
        ]
        and nodes[3].instructions
        == [
            Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant(0x804BB0C), variable[4]])),
        ]
    )

    assert (
        {(edge.source, edge.sink) for edge in cfg.edges}
        == {(nodes[0], nodes[1]), (nodes[1], nodes[2]), (nodes[1], nodes[3]), (nodes[2], nodes[1])}
        and isinstance(cfg.get_edge(nodes[0], nodes[1]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[1], nodes[2]), TrueCase)
        and isinstance(cfg.get_edge(nodes[1], nodes[3]), FalseCase)
        and isinstance(cfg.get_edge(nodes[2], nodes[1]), UnconditionalEdge)
    )


def test_graph_with_input_arguments_more_variable_types_lift_minimal(graph_with_input_arguments_different_variable_types_2, variable):
    """Graph where we have input arguments and where there is more than one variable type.
                       +----------------------------------+     +--------------+     +-----------------------------------------+
                       |                0.                |     |      8.      |     |                   0.                    |
                       | if(arg2#0 < arg1#0)              | -+  | arg2 = arg1  | <-- | if(arg2 < arg1)                         |
                       +----------------------------------+  |  +--------------+     +-----------------------------------------+
                         |                                   |    |                    |
                         |                                   |    |                    |
                         v                                   |    |                    v
                       +----------------------------------+  |    |                  +-----------------------------------------+
                       |                1.                |  |    |                  |                   1.                    |
                       +----------------------------------+  |    |                  +-----------------------------------------+
                         |                                   |    |                    |
                         |                                   |    |                    |
                         v                                   |    |                    v
                       +----------------------------------+  |    |                  +-----------------------------------------+     +----+
                       |                2.                |  |    |                  |                   2.                    |     | 9. |
                       | arg2#2 = ϕ(arg2#0,arg1#0)        |  |    +----------------> | if(arg1 > (arg2 + arg2))                | --> |    |
                    +- | if(arg1#0 > (arg2#2 + arg2#2))   | <+                       +-----------------------------------------+     +----+
                    |  +----------------------------------+                            |                                               |
                    |    |                                                             |                                               |
                    |    |                                                             v                                               |
                    |    v                                                           +-----------------------------------------+       |
                    |  +----------------------------------+                          |                   3.                    |       |
                    |  |                3.                |                          | arg2 = arg1 - arg2                      |       |
                    |  | arg2#3 = arg1#0 - arg2#2         |                          +-----------------------------------------+       |
                    |  +----------------------------------+                            |                                               |
                    |    |                                                             |                                               |
                    |    |                                                             v                                               |
                    |    v                                                           +-----------------------------------------+       |
                    |  +----------------------------------+                          |                   4.                    |       |
                    |  |                4.                |                          | arg1 = (arg1 - arg2) + 0x1              |       |
                    |  | arg2#4 = ϕ(arg2#2,arg2#3)        |                          | var_0 = arg1                            |       |
                    +> | v#1 = (arg1#0 - arg2#4) + 0x1    |                          | arg1 = 0x1                              |       |
                       +----------------------------------+                          | var_1 = 0x1                             | <-----+
                         |                                                           +-----------------------------------------+
                         |                                                             |
                         v                                                             |
    +------------+     +----------------------------------+                            v
    |            |     |                5.                |     +--------------+     +-----------------------------------------+
    |     7.     |     | u#2 = ϕ(0x1,u#5)                 |     |      7.      |     |                   5.                    |
    | return x#2 |     | v#2 = ϕ(v#1,v#2)                 |     | return var_1 | <-- | if(arg1 <= arg2)                        | <+
    |            |     | x#2 = ϕ(0x1,y#1)                 |     +--------------+     +-----------------------------------------+  |
    |            | <-- | if(u#2 <= arg2#4)                | <+                         |                                          |
    +------------+     +----------------------------------+  |                         |                                          |
                         |                                   |                         v                                          |
                         |                                   |                       +-----------------------------------------+  |
                         v                                   |                       |                   6.                    |  |
                       +----------------------------------+  |                       | var_2 = arg1 + 0x1                      |  |
                       |                6.                |  |                       | var_3 = (((long) var_0) * var_1) / arg1 |  |
                       | u#5 = u#2 + 0x1                  |  |                       | arg1 = var_2                            |  |
                       | y#1 = (((long) v#2) * x#2) / u#2 | -+                       | var_1 = var_3                           | -+
                       +----------------------------------+                          +-----------------------------------------+
    """
    nodes, cfg = graph_with_input_arguments_different_variable_types_2
    run_out_of_ssa(
        cfg,
        SSAOptions.lift_minimal,
        arguments=[argument1 := Variable("arg1", Integer.int32_t()), argument2 := Variable("arg2", Integer.int32_t())],
    )

    new_node = [node for node in cfg.nodes if node not in set(nodes)]
    variable[3] = Variable("var_3", Integer.int64_t())

    assert (
        nodes[0].instructions == [Branch(Condition(OperationType.less, [argument2, argument1]))]
        and nodes[1].instructions == []
        and nodes[2].instructions
        == [Branch(Condition(OperationType.greater, [argument1, BinaryOperation(OperationType.plus, [argument2, argument2])]))]
        and nodes[3].instructions == [Assignment(argument2, BinaryOperation(OperationType.minus, [argument1, argument2]))]
        and nodes[4].instructions
        == [
            Assignment(
                argument1,
                BinaryOperation(OperationType.plus, [BinaryOperation(OperationType.minus, [argument1, argument2]), Constant(0x1)]),
            ),
            Assignment(variable[0], argument1),
            Assignment(argument1, Constant(0x1)),
            Assignment(variable[1], Constant(0x1)),
        ]
        and nodes[5].instructions == [Branch(Condition(OperationType.less_or_equal, [argument1, argument2]))]
        and nodes[6].instructions
        == [
            Assignment(variable[2], BinaryOperation(OperationType.plus, [argument1, Constant(0x1)])),
            Assignment(
                variable[3],
                BinaryOperation(
                    OperationType.divide,
                    [
                        BinaryOperation(
                            OperationType.multiply,
                            [UnaryOperation(OperationType.cast, [variable[0]], vartype=Integer.int64_t()), variable[1]],
                        ),
                        argument1,
                    ],
                ),
            ),
            Assignment(argument1, variable[2]),
            Assignment(variable[1], variable[3]),
        ]
        and nodes[7].instructions == [Return([variable[1]])]
        and new_node[0].instructions == [Assignment(argument2, argument1)]
        and new_node[1].instructions == []
        and len(cfg) == 10
    )

    assert (
        len(cfg.edges) == 12
        and isinstance(cfg.get_edge(nodes[0], nodes[1]), TrueCase)
        and isinstance(cfg.get_edge(nodes[0], new_node[0]), FalseCase)
        and isinstance(cfg.get_edge(new_node[0], nodes[2]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[1], nodes[2]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[2], nodes[3]), FalseCase)
        and isinstance(cfg.get_edge(nodes[2], new_node[1]), TrueCase)
        and isinstance(cfg.get_edge(new_node[1], nodes[4]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[3], nodes[4]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[4], nodes[5]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[5], nodes[6]), TrueCase)
        and isinstance(cfg.get_edge(nodes[5], nodes[7]), FalseCase)
        and isinstance(cfg.get_edge(nodes[6], nodes[5]), UnconditionalEdge)
    )


def test_graph_with_edge_conditions_lift_minimal(graph_with_edge_condition, variable):
    """Graph, where we have conditions on some edges."""
    nodes, cfg = graph_with_edge_condition
    run_out_of_ssa(cfg, SSAOptions.lift_minimal)

    # variables x, yy and z are aliased, so variable[0], variable[1] and variable[2] must be aliased
    variable[0].is_aliased = True
    variable[1].is_aliased = True
    variable[2].is_aliased = True

    assert (
        nodes[0].instructions
        == [
            Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("Enter your choice = ")])),
            Assignment(
                ListOperation([]),
                Call(imp_function_symbol("scanf"), [Constant(0x804A025), UnaryOperation(OperationType.address, [variable[0]])]),
            ),
            Assignment(ListOperation([]), Call(imp_function_symbol("puts"), [Constant("Enter a number ")])),
            Assignment(
                ListOperation([]),
                Call(imp_function_symbol("scanf"), [Constant(0x804A025), UnaryOperation(OperationType.address, [variable[1]])]),
            ),
            Assignment(ListOperation([]), Call(imp_function_symbol("puts"), [Constant("Enter a second number ")])),
            Assignment(
                ListOperation([]),
                Call(imp_function_symbol("scanf"), [Constant(0x804A025), UnaryOperation(OperationType.address, [variable[2]])]),
            ),
            Branch(Condition(OperationType.greater, [variable[0], Constant(0x5)])),
        ]
        and nodes[1].instructions == [IndirectBranch(variable[0])]
        and nodes[2].instructions
        == [
            Assignment(ListOperation([]), Call(imp_function_symbol("puts"), [Constant("default !")])),
            Assignment(variable[3], Constant(0x0)),
        ]
        and nodes[3].instructions
        == [
            Assignment(
                variable[3],
                BinaryOperation(
                    OperationType.multiply,
                    [BinaryOperation(OperationType.plus, [variable[1], Constant(0x1)]), variable[2]],
                ),
            ),
        ]
        and nodes[4].instructions
        == [
            Assignment(
                variable[3],
                BinaryOperation(
                    OperationType.plus,
                    [BinaryOperation(OperationType.plus, [variable[1], Constant(0x2)]), variable[2]],
                ),
            ),
        ]
        and nodes[5].instructions
        == [
            Assignment(
                variable[3],
                BinaryOperation(
                    OperationType.minus,
                    [variable[2], BinaryOperation(OperationType.plus, [variable[1], Constant(0x3)])],
                ),
            ),
        ]
        and nodes[6].instructions
        == [
            Assignment(
                variable[3],
                BinaryOperation(
                    OperationType.minus,
                    [BinaryOperation(OperationType.plus, [variable[1], Constant(0x4)]), variable[2]],
                ),
            ),
        ]
        and nodes[7].instructions
        == [
            Assignment(
                variable[3],
                BinaryOperation(
                    OperationType.multiply,
                    [
                        Constant(2),
                        BinaryOperation(
                            OperationType.plus,
                            [BinaryOperation(OperationType.plus, [variable[1], Constant(0x4)]), variable[2]],
                        ),
                    ],
                ),
            ),
        ]
        and nodes[8].instructions
        == [Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("a = %d "), variable[3]])), Return(Constant(0x0))]
        and len(cfg) == 9
    )

    assert (
        len(cfg.edges) == 14
        and isinstance(cfg.get_edge(nodes[0], nodes[3]), TrueCase)
        and isinstance(cfg.get_edge(nodes[0], nodes[1]), FalseCase)
        and isinstance(cfg.get_edge(nodes[3], nodes[8]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[1], nodes[2]), SwitchCase)
        and isinstance(cfg.get_edge(nodes[1], nodes[3]), SwitchCase)
        and isinstance(cfg.get_edge(nodes[1], nodes[4]), SwitchCase)
        and isinstance(cfg.get_edge(nodes[1], nodes[5]), SwitchCase)
        and isinstance(cfg.get_edge(nodes[1], nodes[6]), SwitchCase)
        and isinstance(cfg.get_edge(nodes[1], nodes[7]), SwitchCase)
        and isinstance(cfg.get_edge(nodes[2], nodes[8]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[4], nodes[8]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[5], nodes[8]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[6], nodes[8]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[7], nodes[8]), UnconditionalEdge)
        and cfg.get_edge(nodes[1], nodes[2]).cases == [Constant(0)]
        and cfg.get_edge(nodes[1], nodes[3]).cases == [Constant(1)]
        and cfg.get_edge(nodes[1], nodes[4]).cases == [Constant(2)]
        and cfg.get_edge(nodes[1], nodes[5]).cases == [Constant(3)]
        and cfg.get_edge(nodes[1], nodes[6]).cases == [Constant(4)]
        and cfg.get_edge(nodes[1], nodes[7]).cases == [Constant(5)]
    )


def test_aliased_name_problem(aliased_variable_z, aliased_variable_y, variable_u, variable_v, variable_x, variable):
    """
                       +------------------------------+                        +------------------------------+
                       |              0.              |                        |              0.              |
                       | printf("Enter two numbers ") |                        | printf("Enter two numbers ") |
                       |          z#2 = z#0           |                        |          z#2 = z#0           |
                       |         v#1 = &(z#2)         |                        |         v#1 = &(z#2)         |
                       |    scanf(0x804a025, v#1)     |                        |    scanf(0x804a025, v#1)     |
                       |          y#3 = y#0           |                        |          y#3 = y#0           |
                       |         u#2 = &(y#3)         |                        |         u#2 = &(y#3)         |
                       |    scanf(0x804a025, u#2)     |                        |    scanf(0x804a025, u#2)     |
                       +------------------------------+                        +------------------------------+
                         |                                                       |
                         |                                                       |
                         v                                                       v
    +------------+     +------------------------------+     +------------+     +------------------------------+
    |            |     |              1.              |     |            |     |              1.              |
    |     3.     |     |       x#2 = ϕ(0x1,x#3)       |     |     3.     |     |       x#2 = ϕ(0x1,x#3)       |
    | return 0x0 |     |       y#5 = ϕ(y#3,y#6)       |     | return 0x0 |     |       y#5 = ϕ(y#3,y#6)       |
    |            |     |       z#5 = ϕ(z#2,z#5)       |     |            |     |       z#5 = ϕ(z#2,z#5)       |
    |            | <-- |        if(x#2 <= z#5)        | <+  |            | <-- |        if(x#2 <= z#5)        | <+
    +------------+     +------------------------------+  |  +------------+     +------------------------------+  |
                         |                               |                       |                               |
                         |                               |                       |                               |
                         v                               |                       v                               |
                       +------------------------------+  |                     +------------------------------+  |
                       |              2.              |  |                     |              2.              |  |
                       |       y#6 = y#5 * x#2        |  |                     |       y#6 = y#5 * x#2        |  |
                       |       x#3 = x#2 + 0x1        | -+                     |       x#3 = x#2 + 0x1        | -+
                       +------------------------------+                        +------------------------------+
    """
    instructions = [
        # node 0
        Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("Enter two numbers ")])),
        Assignment(aliased_variable_z[2], aliased_variable_z[0]),
        Assignment(variable_v[1], UnaryOperation(OperationType.address, [aliased_variable_z[2]])),
        Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [Constant(0x804A025), variable_v[1]])),
        Assignment(aliased_variable_y[3], aliased_variable_y[0]),
        Assignment(variable_u[2], UnaryOperation(OperationType.address, [aliased_variable_y[3]])),
        Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [Constant(0x804A025), variable_u[2]])),
        # node 1
        Phi(variable_x[2], [Constant(0x1), variable_x[3]]),
        Phi(aliased_variable_y[5], [aliased_variable_y[3], aliased_variable_y[6]]),
        Phi(aliased_variable_z[5], [aliased_variable_z[2], aliased_variable_z[5]]),
        Branch(Condition(OperationType.less_or_equal, [variable_x[2], aliased_variable_z[5]])),
        # node 2
        Assignment(
            aliased_variable_y[6],
            BinaryOperation(
                OperationType.multiply,
                [aliased_variable_y[5], variable_x[2]],
            ),
        ),
        Assignment(
            variable_x[3],
            BinaryOperation(
                OperationType.plus,
                [variable_x[2], Constant(0x1)],
            ),
        ),
        # node 3
        Return([Constant(0x0)]),
    ]

    # Set of nodes:
    nodes = [BasicBlock(i) for i in range(4)]
    # Add instructions:
    nodes[0].instructions = instructions[0:7]
    nodes[1].instructions = instructions[7:11]
    nodes[2].instructions = instructions[11:13]
    nodes[3].instructions = [instructions[13]]

    instructions[7]._origin_block = {nodes[0]: Constant(0x1), nodes[2]: variable_x[3]}
    instructions[8]._origin_block = {nodes[0]: aliased_variable_y[3], nodes[2]: aliased_variable_y[6]}
    instructions[9]._origin_block = {nodes[0]: aliased_variable_z[2], nodes[2]: aliased_variable_z[5]}

    cfg = ControlFlowGraph()
    cfg.add_edges_from(
        [
            UnconditionalEdge(nodes[0], nodes[1]),
            TrueCase(nodes[1], nodes[2]),
            FalseCase(nodes[1], nodes[3]),
            UnconditionalEdge(nodes[2], nodes[1]),
        ]
    )

    run_out_of_ssa(cfg, SSAOptions.lift_minimal)

    variable[0].is_aliased = True
    variable[1].is_aliased = True

    assert (
        len(cfg) == 4
        and nodes[0].instructions
        == [
            Assignment(ListOperation([]), Call(imp_function_symbol("printf"), [Constant("Enter two numbers ")])),
            Assignment(variable[2], UnaryOperation(OperationType.address, [variable[0]])),
            Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [Constant(0x804A025), variable[2]])),
            Assignment(variable[2], UnaryOperation(OperationType.address, [variable[1]])),
            Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [Constant(0x804A025), variable[2]])),
            Assignment(variable[2], Constant(0x1)),
        ]
        and nodes[1].instructions == [Branch(Condition(OperationType.less_or_equal, [variable[2], variable[0]]))]
        and nodes[2].instructions
        == [
            Assignment(
                variable[1],
                BinaryOperation(
                    OperationType.multiply,
                    [variable[1], variable[2]],
                ),
            ),
            Assignment(
                variable[2],
                BinaryOperation(
                    OperationType.plus,
                    [variable[2], Constant(0x1)],
                ),
            ),
        ]
        and nodes[3].instructions == [Return([Constant(0x0)])]
    )

    assert (
        len(cfg.edges) == 4
        and isinstance(cfg.get_edge(nodes[0], nodes[1]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[1], nodes[2]), TrueCase)
        and isinstance(cfg.get_edge(nodes[1], nodes[3]), FalseCase)
        and isinstance(cfg.get_edge(nodes[2], nodes[1]), UnconditionalEdge)
    )


def test_graph_with_phi_fct_in_head_lift_minimal1(graph_phi_fct_in_head1, variable):
    """Graph where the head has a Phi-function and therefore a Phi-value has no predecessor."""
    nodes, cfg = graph_phi_fct_in_head1
    run_out_of_ssa(cfg, SSAOptions.lift_minimal)
    new_nodes = [nd for nd in cfg.nodes if nd != nodes[0]]

    assert (
        len(cfg) == 2
        and nodes[0].instructions
        == [
            Assignment(variable[2], BinaryOperation(OperationType.plus, [variable[1], Constant(10)])),
            Assignment(variable[1], variable[0]),
            Assignment(variable[0], variable[2]),
        ]
        and new_nodes[0].instructions
        == [
            Assignment(variable[1], variable[0]),
        ]
    )

    assert (
        len(cfg.edges) == 2
        and isinstance(cfg.get_edge(new_nodes[0], nodes[0]), UnconditionalEdge)
        and isinstance(cfg.get_edge(nodes[0], nodes[0]), UnconditionalEdge)
    )


def test_graph_with_phi_fct_in_head_lift_minimal2(graph_phi_fct_in_head2, variable):
    """Graph where the head has a Phi-function and therefore a Phi-value has no predecessor."""
    nodes, cfg = graph_phi_fct_in_head2
    run_out_of_ssa(cfg, SSAOptions.lift_minimal)
    new_nodes = [nd for nd in cfg.nodes if nd != nodes[0]]

    assert (
        len(cfg) == 2
        and nodes[0].instructions
        == [
            Assignment(variable[2], BinaryOperation(OperationType.plus, [variable[1], variable[0]])),
            Assignment(variable[0], variable[1]),
            Assignment(variable[1], variable[2]),
        ]
        and new_nodes[0].instructions == []
    )

    assert (
        len(cfg.edges) == 2
        and cfg.get_edge(new_nodes[0], nodes[0]).condition_type == BasicBlockEdgeCondition.unconditional
        and cfg.get_edge(nodes[0], nodes[0]).condition_type == BasicBlockEdgeCondition.unconditional
    )


def test_graph_with_relation_lift_minimal(graph_with_relation, variable):
    """
        test lift minimal SSA with relation test loop test 2.
        Output:
                                            +----------------------------------+
                                            |                0.                |
                                            |         var_3 = &(var_0)         |
                                            | __isoc99_scanf(0x804b01f, var_3) |
                                            |    var_2 = var_0 * 0x66666667    |
                                            |       var_2 = var_2 << 0x2       |
                                            |          var_1 = var_0           |
                                            +----------------------------------+
                                              |
                                              |
                                              v
    +---------------------------------+     +----------------------------------+
    |               3.                |     |                1.                |
    | printf((var_0 - var_2) + var_1) |     |         if(var_1 > 0x9)          |
    |           return 0x0            | <-- |                                  | <+
    +---------------------------------+     +----------------------------------+  |
                                              |                                   |
                                              |                                   |
                                              v                                   |
                                            +----------------------------------+  |
                                            |                2.                |  |
                                            |    var_1 = var_1 * 0x66666667    | -+
                                            +----------------------------------+
    """
    nodes, cfg = graph_with_relation
    run_out_of_ssa(cfg, SSAOptions.lift_minimal)
    variable[0].is_aliased = True
    variable[1].is_aliased = True
    variable[3]._type = Pointer(Integer(32, True), 32)

    assert (
        len(cfg) == 4
        and nodes[0].instructions
        == [
            Assignment(variable[3], UnaryOperation(OperationType.address, [variable[0]], Pointer(Integer(32, True), 32), None, False)),
            Assignment(
                ListOperation([]),
                Call(
                    Constant("__isoc99_scanf", UnknownType()),
                    [Constant(134524959, Integer(32, True)), variable[3]],
                    Pointer(CustomType("void", 0), 32),
                    2,
                ),
            ),
            Assignment(
                variable[2],
                BinaryOperation(OperationType.multiply, [variable[0], Constant(1717986919, Integer(32, True))], Integer(64, True)),
            ),
            Assignment(
                variable[2],
                BinaryOperation(OperationType.left_shift, [variable[2], Constant(2, Integer(32, True))], Integer(32, True)),
            ),
            Assignment(variable[1], variable[0]),
        ]
        and nodes[1].instructions
        == [Branch(Condition(OperationType.greater, [variable[1], Constant(9, Integer(32, True))], CustomType("bool", 1)))]
        and nodes[2].instructions
        == [
            Assignment(
                variable[1],
                BinaryOperation(OperationType.multiply, [variable[1], Constant(1717986919, Integer(32, True))], Integer(64, True)),
            )
        ]
        and nodes[3].instructions
        == [
            Assignment(
                ListOperation([]),
                Call(
                    Constant("printf", UnknownType()),
                    [
                        BinaryOperation(
                            OperationType.plus,
                            [BinaryOperation(OperationType.minus, [variable[0], variable[2]], Integer(32, True)), variable[1]],
                            Integer(32, True),
                        ),
                    ],
                    Pointer(CustomType("void", 0), 32),
                    5,
                ),
            ),
            Return(ListOperation([Constant(0, Integer(32, True))])),
        ]
    )


def test_make_sure_fct_parameters_interfere():
    """
        error.out safe_div_func_float_f_f -> Issue 432
               +----+     +---------------------------------------------------+                                                           +----+     +-------------------------------------------------+
               |    |     |                        0.                         |                                                           |    |     |                       0.                        |
               |    |     |                c0#0 = "_mm_and_ps"                |                                                           |    |     |              var_3 = "_mm_and_ps"               |
               | 1. |     |     c0#0(0x7fffffff, (unsigned int *) arg2#0)     |                                                           | 1. |     |    var_3(0x7fffffff, (unsigned int *) arg2)     |
               |    |     |       rax_1#2 = ((!(z#0)) & (!(c#0))) ^ 0x1       |                                                           |    |     |     var_2 = ((!(var_1)) & (!(var_0))) ^ 0x1     |
               |    | <-- |       if(((unsigned char) rax_1#2) != 0x0)        |                                                           |    | <-- |       if(((unsigned char) var_2) != 0x0)        |
               +----+     +---------------------------------------------------+                                                           +----+     +-------------------------------------------------+
                 |          |                                                                                                               |          |
                 |          |                                                                                                               |          |
                 |          v                                                                                                               |          v
                 |        +---------------------------------------------------+     +------------------------------+                        |        +-------------------------------------------------+     +----------------------------+
                 |        |                        2.                         |     |                              |                        |        |                       2.                        |     |                            |
                 |        |            p_1#1 = pxor    xmm0, xmm0             |     |              5.              |                        |        |           var_1 = pxor    xmm0, xmm0            |     |             5.             |
                 |        |     z_1#1 = (0x3f800000 ^ 0x3f800000) == 0x0      |     |  z_1#2 = (0x0 ^ 0x0) == 0x0  |                        |        |    var_0 = (0x3f800000 ^ 0x3f800000) == 0x0     |     | var_0 = (0x0 ^ 0x0) == 0x0 |
                 |        |                if(p_1#1 != false)                 | --> |                              |                        |        |               if(var_1 != false)                | --> |                            |
                 |        +---------------------------------------------------+     +------------------------------+                        |        +-------------------------------------------------+     +----------------------------+
                 |          |                                                         |                                                     |          |                                                       |
                 |          |                                                         |                                                     |          |                                                       |
                 |          v                                                         v                                                     |          v                                                       v
                 |        +---------------------------------------------------+     +------------------------------+                        |        +-------------------------------------------------+     +----------------------------+
                 |        |                        4.                         |     |              8.              |                        |        |                       4.                        |     |             8.             |
                 |        +---------------------------------------------------+     +------------------------------+                        |        +-------------------------------------------------+     +----------------------------+
                 |          |                                                         |                                                     |          |                                                       |
                 |          |                                                         |                                                     |          |                                                       |
                 |          v                                                         v                                                     |          v                                                       v
    +----+       |        +---------------------------------------------------+     +------------------------------+           +----+       |        +-------------------------------------------------+     +----------------------------+
    |    |       |        |                        7.                         |     |                              |           |    |       |        |                       7.                        |     |                            |
    |    |       |        |              z_1#3 = ϕ(z_1#1,z_1#2)               |     |                              |           |    |       |        |         (4: ) arg1 = divss   xmm0, xmm1         |     |                            |
    | 9. |       |        |         (4: ) arg1#8 = divss   xmm0, xmm1         |     |             11.              |           | 9. |       |        |             var_3(arg1, 0x7fffffff)             |     |            11.             |
    |    |       |        |             c0#0(arg1#8, 0x7fffffff)              |     | rax_1#5 = ϕ(rax_1#2,rax_1#4) |           |    |       |        | var_2 = ((unsigned int) (!(var_0)) & 0x1) ^ 0x1 |     |                            |
    |    |       |        | rax_1#4 = ((unsigned int) (!(z_1#3)) & 0x1) ^ 0x1 |     |                              |           |    | <-----+------- |       if(((unsigned char) var_2) == 0x0)        |     |                            | <+
    |    | <-----+------- |       if(((unsigned char) rax_1#4) == 0x0)        |     |                              | <+        +----+       |        +-------------------------------------------------+     +----------------------------+  |
    +----+       |        +---------------------------------------------------+     +------------------------------+  |          |          |          |                                                       |                             |
      |          |          |                                                         |                               |          |          |          |                                                       |                             |
      |          |          |                                                         |                               |          |          |          v                                                       |                             |
      |          |          v                                                         |                               |          |          |        +-------------------------------------------------+       |                             |
      |          |        +---------------------------------------------------+       |                               |          |          |        |                       10.                       |       |                             |
      |          |        |                        10.                        |       |                               |          |          |        +-------------------------------------------------+       |                             |
      |          |        +---------------------------------------------------+       |                               |          |          |          |                                                       |                             |
      |          |          |                                                         |                               |          |          |          |                                                       |                             |
      |          |          |                                                         |                               |          |          |          v                                                       |                             |
      |          |          v                                                         |                               |          |          |        +-------------------------------------------------+       |                             |
      |          |        +---------------------------------------------------+       |                               |          |          +------> |                       3.                        |       |                             |
      |          |        |                        3.                         |       |                               |          |                   +-------------------------------------------------+       |                             |
      |          +------> |           rax_1#6 = ϕ(rax_1#2,rax_1#4)            |       |                               |          |                     |                                                       |                             |
      |                   +---------------------------------------------------+       |                               |          |                     |                                                       |                             |
      |                     |                                                         |                               |          |                     v                                                       |                             |
      |                     |                                                         |                               |          |                   +-------------------------------------------------+       |                             |
      |                     v                                                         |                               |          |                   |                       6.                        |       |                             |
      |                   +---------------------------------------------------+       |                               |          |                   |                  return var_2                   | <-----+                             |
      |                   |                        6.                         |       |                               |          |                   +-------------------------------------------------+                                     |
      |                   |           rax_1#7 = ϕ(rax_1#5,rax_1#6)            |       |                               |          |                                                                                                           |
      |                   |                  return rax_1#7                   | <-----+                               |          +-----------------------------------------------------------------------------------------------------------+
      |                   +---------------------------------------------------+                                       |
      |                                                                                                               |
      +---------------------------------------------------------------------------------------------------------------+
    """
    instructions = [
        [
            Assignment(Variable("c0", UnknownType(), 0), Constant("_mm_and_ps", UnknownType())),
            Assignment(
                ListOperation([]),
                Call(
                    Variable("c0", UnknownType(), 0),
                    [
                        Constant(2147483647, Pointer(Integer(32, False), 128)),
                        UnaryOperation(
                            OperationType.cast, [Variable("arg2", Pointer(Integer(32, False), 128), 0)], Pointer(Integer(32, False), 32)
                        ),
                    ],
                    Pointer(Integer(32, False), 128),
                ),
            ),
            Assignment(
                Variable("rax_1", Integer(64, False), 2),
                BinaryOperation(
                    OperationType.bitwise_xor,
                    [
                        BinaryOperation(
                            OperationType.bitwise_and,
                            [
                                UnaryOperation(OperationType.logical_not, [Variable("z", CustomType("bool", 1), 0)], CustomType("void", 0)),
                                UnaryOperation(OperationType.logical_not, [Variable("c", CustomType("bool", 1), 0)], CustomType("void", 0)),
                            ],
                            CustomType("void", 0),
                        ),
                        Constant(1, Integer(32, True)),
                    ],
                    Integer(32, True),
                ),
            ),
            Branch(
                Condition(
                    OperationType.not_equal,
                    [
                        UnaryOperation(OperationType.cast, [Variable("rax_1", Integer(64, False), 2)], Integer(8, False)),
                        Constant(0, Integer(8, True)),
                    ],
                    CustomType("bool", 1),
                )
            ),
        ],
        [],
        [
            Assignment(Variable("p_1", CustomType("bool", 1), 1), UnknownExpression("pxor    xmm0, xmm0")),
            Assignment(
                Variable("z_1", CustomType("bool", 1), 1),
                Condition(
                    OperationType.equal,
                    [
                        BinaryOperation(
                            OperationType.bitwise_xor,
                            [
                                Constant(1065353216, Pointer(Integer(32, False), 128)),
                                Constant(1065353216, Pointer(Integer(32, False), 128)),
                            ],
                            Integer(128, True),
                        ),
                        Constant(0, Integer(128, True)),
                    ],
                    CustomType("bool", 1),
                ),
            ),
            Branch(
                Condition(
                    OperationType.not_equal,
                    [Variable("p_1", CustomType("bool", 1), 1), Constant(0, CustomType("bool", 1))],
                    CustomType("bool", 1),
                )
            ),
        ],
        [
            Phi(
                Variable("rax_1", Integer(64, False), 6),
                [Variable("rax_1", Integer(64, False), 2), Variable("rax_1", Integer(64, False), 4)],
            )
        ],
        [],
        [
            Assignment(
                Variable("z_1", CustomType("bool", 1), 2),
                Condition(
                    OperationType.equal,
                    [
                        BinaryOperation(
                            OperationType.bitwise_xor,
                            [Constant(0, Pointer(Integer(32, False), 128)), Constant(0, Pointer(Integer(32, False), 128))],
                            Integer(128, True),
                        ),
                        Constant(0, Integer(128, True)),
                    ],
                    CustomType("bool", 1),
                ),
            )
        ],
        [
            Phi(
                Variable("rax_1", Integer(64, False), 7),
                [Variable("rax_1", Integer(64, False), 5), Variable("rax_1", Integer(64, False), 6)],
            ),
            Return(ListOperation([Variable("rax_1", Integer(64, False), 7)])),
        ],
        [
            Phi(
                Variable("z_1", CustomType("bool", 1), 3),
                [Variable("z_1", CustomType("bool", 1), 1), Variable("z_1", CustomType("bool", 1), 2)],
            ),
            Assignment(
                UnaryOperation(
                    OperationType.cast,
                    [Variable("arg1", Pointer(Integer(32, False), 128), 8)],
                    Pointer(Integer(32, False), 32),
                    contraction=True,
                ),
                UnknownExpression("divss   xmm0, xmm1"),
            ),
            Assignment(
                ListOperation([]),
                Call(
                    Variable("c0", UnknownType(), 0),
                    [
                        Variable("arg1", Pointer(Integer(32, False), 128), 8),
                        Constant(2147483647, Pointer(Integer(32, False), 128)),
                    ],
                    Pointer(Integer(32, False), 128),
                ),
            ),
            Assignment(
                Variable("rax_1", Integer(64, False), 4),
                BinaryOperation(
                    OperationType.bitwise_xor,
                    [
                        UnaryOperation(
                            OperationType.cast,
                            [
                                BinaryOperation(
                                    OperationType.bitwise_and,
                                    [
                                        UnaryOperation(
                                            OperationType.logical_not,
                                            [Variable("z_1", CustomType("bool", 1), 3)],
                                            CustomType("void", 0),
                                        ),
                                        Constant(1, Integer(64, True)),
                                    ],
                                    CustomType("void", 0),
                                )
                            ],
                            Integer(32, False),
                        ),
                        Constant(1, Integer(32, True)),
                    ],
                    Integer(32, True),
                ),
            ),
            Branch(
                Condition(
                    OperationType.equal,
                    [
                        UnaryOperation(OperationType.cast, [Variable("rax_1", Integer(64, False), 4)], Integer(8, False)),
                        Constant(0, Integer(8, True)),
                    ],
                    CustomType("bool", 1),
                )
            ),
        ],
        [],
        [],
        [],
        [
            Phi(
                Variable("rax_1", Integer(64, False), 5),
                [Variable("rax_1", Integer(64, False), 2), Variable("rax_1", Integer(64, False), 4)],
            )
        ],
    ]
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(vertices := [BasicBlock(i, instr.copy()) for i, instr in enumerate(instructions)])

    vertices[3].instructions[0]._origin_block = {
        vertices[1]: Variable("rax_1", Integer(64, False), 2),
        vertices[10]: Variable("rax_1", Integer(64, False), 4),
    }
    vertices[6].instructions[0]._origin_block = {
        vertices[3]: Variable("rax_1", Integer(64, False), 6),
        vertices[11]: Variable("rax_1", Integer(64, False), 5),
    }
    vertices[7].instructions[0]._origin_block = {vertices[4]: Variable("z_1", CustomType("bool", 1), 1)}
    vertices[11].instructions[0]._origin_block = {
        vertices[8]: Variable("rax_1", Integer(64, False), 2),
        vertices[9]: Variable("rax_1", Integer(64, False), 4),
    }

    cfg.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            UnconditionalEdge(vertices[1], vertices[3]),
            TrueCase(vertices[2], vertices[4]),
            FalseCase(vertices[2], vertices[5]),
            UnconditionalEdge(vertices[3], vertices[6]),
            UnconditionalEdge(vertices[4], vertices[7]),
            UnconditionalEdge(vertices[5], vertices[8]),
            TrueCase(vertices[7], vertices[9]),
            FalseCase(vertices[7], vertices[10]),
            UnconditionalEdge(vertices[8], vertices[11]),
            UnconditionalEdge(vertices[9], vertices[11]),
            UnconditionalEdge(vertices[10], vertices[3]),
            UnconditionalEdge(vertices[11], vertices[6]),
        ]
    )

    run_out_of_ssa(
        cfg,
        SSAOptions.lift_minimal,
        arguments=[Variable("arg1", Pointer(Integer(32, False), 128)), Variable("arg2", Pointer(Integer(32, False), 128))],
    )

    assert len(cfg) == 12
    assert vertices[0].instructions == [
        Assignment(Variable("var_3", UnknownType(), ssa_name=Variable("c0", UnknownType(), 0)), Constant("_mm_and_ps", UnknownType())),
        Assignment(
            ListOperation([]),
            Call(
                Variable("var_3", UnknownType(), ssa_name=Variable("c0", UnknownType(), 0)),
                [
                    Constant(2147483647, Pointer(Integer(32, False), 128)),
                    UnaryOperation(
                        OperationType.cast,
                        [
                            Variable(
                                "arg2", Pointer(Integer(32, False), 128), ssa_name=Variable("arg2", Pointer(Integer(32, False), 128), 0)
                            )
                        ],
                        Pointer(Integer(32, False), 32),
                    ),
                ],
                Pointer(Integer(32, False), 128),
            ),
        ),
        Assignment(
            Variable("var_2", Integer(64, False), ssa_name=Variable("rax_1", Integer(64, False), 2)),
            BinaryOperation(
                OperationType.bitwise_xor,
                [
                    BinaryOperation(
                        OperationType.bitwise_and,
                        [
                            UnaryOperation(
                                OperationType.logical_not,
                                [Variable("var_0", CustomType("bool", 1), ssa_name=Variable("z", CustomType("bool", 1), 0))],
                                CustomType("void", 0),
                            ),
                            UnaryOperation(
                                OperationType.logical_not,
                                [Variable("var_1", CustomType("bool", 1), ssa_name=Variable("c", CustomType("bool", 1), 0))],
                                CustomType("void", 0),
                            ),
                        ],
                        CustomType("void", 0),
                    ),
                    Constant(1, Integer(32, True)),
                ],
                Integer(32, True),
            ),
        ),
        Branch(
            Condition(
                OperationType.not_equal,
                [
                    UnaryOperation(
                        OperationType.cast,
                        [Variable("var_2", Integer(64, False), ssa_name=Variable("rax_1", Integer(64, False), 2))],
                        Integer(8, False),
                    ),
                    Constant(0, Integer(8, True)),
                ],
                CustomType("bool", 1),
            )
        ),
    ]
    assert vertices[1].instructions == []
    assert vertices[2].instructions == [
        Assignment(
            Variable("var_1", CustomType("bool", 1), ssa_name=Variable("p_1", CustomType("bool", 1), 1)),
            UnknownExpression("pxor    xmm0, xmm0"),
        ),
        Assignment(
            Variable("var_0", CustomType("bool", 1), ssa_name=Variable("z_1", CustomType("bool", 1), 1)),
            Condition(
                OperationType.equal,
                [
                    BinaryOperation(
                        OperationType.bitwise_xor,
                        [Constant(1065353216, Pointer(Integer(32, False), 128)), Constant(1065353216, Pointer(Integer(32, False), 128))],
                        Integer(128, True),
                    ),
                    Constant(0, Integer(128, True)),
                ],
                CustomType("bool", 1),
            ),
        ),
        Branch(
            Condition(
                OperationType.not_equal,
                [
                    Variable("var_1", CustomType("bool", 1), ssa_name=Variable("p_1", CustomType("bool", 1), 1)),
                    Constant(0, CustomType("bool", 1)),
                ],
                CustomType("bool", 1),
            )
        ),
    ]
    assert vertices[3].instructions == []
    assert vertices[4].instructions == []
    assert vertices[5].instructions == [
        Assignment(
            Variable("var_0", CustomType("bool", 1), ssa_name=Variable("z_1", CustomType("bool", 1), 2)),
            Condition(
                OperationType.equal,
                [
                    BinaryOperation(
                        OperationType.bitwise_xor,
                        [Constant(0, Pointer(Integer(32, False), 128)), Constant(0, Pointer(Integer(32, False), 128))],
                        Integer(128, True),
                    ),
                    Constant(0, Integer(128, True)),
                ],
                CustomType("bool", 1),
            ),
        )
    ]
    assert vertices[6].instructions == [
        Return(ListOperation([Variable("var_2", Integer(64, False), ssa_name=Variable("rax_1", Integer(64, False), 7))]))
    ]
    assert vertices[7].instructions == [
        Assignment(
            UnaryOperation(
                OperationType.cast,
                [Variable("arg1", Pointer(Integer(32, False), 128), ssa_name=Variable("arg1", Pointer(Integer(32, False), 128), 8))],
                Pointer(Integer(32, False), 32),
                None,
                True,
            ),
            UnknownExpression("divss   xmm0, xmm1"),
        ),
        Assignment(
            ListOperation([]),
            Call(
                Variable("var_3", UnknownType(), ssa_name=Variable("c0", UnknownType(), 0, False, None)),
                [
                    Variable(
                        "arg1",
                        Pointer(Integer(32, False), 128),
                        ssa_name=Variable("arg1", Pointer(Integer(32, False), 128), 8, False, None),
                    ),
                    Constant(2147483647, Pointer(Integer(32, False), 128)),
                ],
                Pointer(Integer(32, False), 128),
            ),
        ),
        Assignment(
            Variable("var_2", Integer(64, False), ssa_name=Variable("rax_1", Integer(64, False), 4)),
            BinaryOperation(
                OperationType.bitwise_xor,
                [
                    UnaryOperation(
                        OperationType.cast,
                        [
                            BinaryOperation(
                                OperationType.bitwise_and,
                                [
                                    UnaryOperation(
                                        OperationType.logical_not,
                                        [Variable("var_0", CustomType("bool", 1), ssa_name=Variable("z_1", CustomType("bool", 1), 3))],
                                        CustomType("void", 0),
                                    ),
                                    Constant(1, Integer(64, True)),
                                ],
                                CustomType("void", 0),
                            )
                        ],
                        Integer(32, False),
                    ),
                    Constant(1, Integer(32, True)),
                ],
                Integer(32, True),
            ),
        ),
        Branch(
            Condition(
                OperationType.equal,
                [
                    UnaryOperation(
                        OperationType.cast,
                        [Variable("var_2", Integer(64, False), ssa_name=Variable("rax_1", Integer(64, False), 4))],
                        Integer(8, False),
                    ),
                    Constant(0, Integer(8, True)),
                ],
                CustomType("bool", 1),
            )
        ),
    ]
    assert vertices[8].instructions == []
    assert vertices[9].instructions == []
    assert vertices[10].instructions == []
    assert vertices[11].instructions == []
