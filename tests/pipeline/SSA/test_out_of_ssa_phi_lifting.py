# pytest for lifting Phi-functions

from decompiler.pipeline.ssa.phi_lifting import PhiFunctionLifter
from decompiler.structures.interferencegraph import InterferenceGraph

from tests.pipeline.SSA.utils_out_of_ssa_tests import *


@pytest.fixture()
def construct_stage_for_lifting(variable_v, variable_u) -> Tuple[PhiFunctionLifter, List[Instruction], List[BasicBlock]]:
    """The base control flow graph for the lifter tests."""
    instructions = [
        IndirectBranch(variable_v[1]),
        Phi(variable_v[2], [variable_v[1], variable_v[3]]),
        Phi(variable_u[2], [variable_u[1], variable_u[3]]),
        Phi(variable_v[3], [variable_v[1], variable_v[6]]),
        Branch(Condition(OperationType.less, [variable_v[2], variable_u[2]])),
        Assignment(variable_v[4], BinaryOperation(OperationType.plus, [variable_u[2], variable_v[3]])),
        Assignment(variable_v[5], BinaryOperation(OperationType.plus, [variable_v[2], variable_v[3]])),
        Phi(variable_v[6], [variable_v[4], variable_v[5]]),
        Phi(variable_u[3], [variable_v[2], variable_v[3]]),
        Branch(Condition(OperationType.less, [variable_v[1], variable_u[3]])),
    ]

    # Set of nodes:
    nodes = [BasicBlock(i) for i in range(6)]
    # Add instructions:
    nodes[0].instructions = [instructions[0]].copy()
    nodes[1].instructions = instructions[1:5].copy()
    nodes[2].instructions = [instructions[5]].copy()
    nodes[3].instructions = [instructions[6]].copy()
    nodes[4].instructions = instructions[7:].copy()
    nodes[5].instructions = []

    instructions[1]._origin_block = {nodes[0]: variable_v[1], nodes[4]: variable_v[3]}
    instructions[2]._origin_block = {nodes[0]: variable_u[1], nodes[4]: variable_u[3]}
    instructions[3]._origin_block = {nodes[0]: variable_v[1], nodes[4]: variable_v[6]}
    instructions[7]._origin_block = {nodes[2]: variable_v[4], nodes[3]: variable_v[5]}
    instructions[8]._origin_block = {nodes[2]: variable_v[2], nodes[3]: variable_v[3]}

    cfg = ControlFlowGraph()
    cfg.add_edges_from(
        [
            SwitchCase(nodes[0], nodes[1], [Constant(3), Constant(2)]),
            TrueCase(nodes[1], nodes[2]),
            FalseCase(nodes[1], nodes[3]),
            UnconditionalEdge(nodes[2], nodes[4]),
            UnconditionalEdge(nodes[3], nodes[4]),
            TrueCase(nodes[4], nodes[1]),
            FalseCase(nodes[4], nodes[5]),
        ]
    )

    phi_fct_lifter = PhiFunctionLifter(cfg, InterferenceGraph(cfg), init_phi_functions_of_block(cfg))

    return phi_fct_lifter, instructions, nodes


def test_lifting_no_unnecessary_assignment(variable_v, variable_u, construct_stage_for_lifting):
    """We need all assignments that result from the Phi-functions."""
    phi_fct_lifter, instructions, nodes = construct_stage_for_lifting

    old_edges = set(phi_fct_lifter.interference_graph.edges())

    phi_fct_lifter.lift()

    new_edges = set(phi_fct_lifter.interference_graph.edges())
    new_node = [node for node in phi_fct_lifter._cfg.nodes if node not in set(nodes)]

    assert (
        nodes[0].instructions == [instructions[0]]
        and nodes[1].instructions == [instructions[4]]
        and nodes[2].instructions
        == [instructions[5]] + [Assignment(phi.definitions[0], phi.origin_block[nodes[2]]) for phi in instructions[7:9]]
        and nodes[3].instructions
        == [instructions[6]] + [Assignment(phi.definitions[0], phi.origin_block[nodes[3]]) for phi in instructions[7:9]]
        and nodes[4].instructions == [instructions[9]]
        and nodes[5].instructions == []
        and new_node[0].instructions == [Assignment(phi.definitions[0], phi.origin_block[nodes[0]]) for phi in instructions[1:4]]
        and new_node[1].instructions == [Assignment(phi.definitions[0], phi.origin_block[nodes[4]]) for phi in instructions[1:4]]
        and len(new_node) == 2
        and isinstance(edge := phi_fct_lifter._cfg.get_edge(nodes[0], new_node[0]), SwitchCase)
        and edge.cases == [Constant(3), Constant(2)]
        and isinstance(phi_fct_lifter._cfg.get_edge(new_node[0], nodes[1]), UnconditionalEdge)
        and isinstance(phi_fct_lifter._cfg.get_edge(nodes[1], nodes[2]), TrueCase)
        and isinstance(phi_fct_lifter._cfg.get_edge(nodes[1], nodes[3]), FalseCase)
        and isinstance(phi_fct_lifter._cfg.get_edge(nodes[2], nodes[4]), UnconditionalEdge)
        and isinstance(phi_fct_lifter._cfg.get_edge(nodes[3], nodes[4]), UnconditionalEdge)
        and isinstance(phi_fct_lifter._cfg.get_edge(nodes[4], nodes[5]), FalseCase)
        and isinstance(phi_fct_lifter._cfg.get_edge(nodes[4], new_node[1]), TrueCase)
        and isinstance(phi_fct_lifter._cfg.get_edge(new_node[1], nodes[1]), UnconditionalEdge)
        and old_edges - new_edges == set()
        and new_edges - old_edges
        == {(variable_v[2], variable_u[3]), (variable_u[1], variable_v[2]), (variable_u[2], variable_v[6]), (variable_v[2], variable_v[6])}
    )


def test_lifting_some_unnecessary_assignment(variable_v, variable_u, construct_stage_for_lifting):
    """There are some assignments that we do not need to lift."""
    phi_fct_lifter, instructions, nodes = construct_stage_for_lifting

    instructions[3].substitute(variable_v[1], variable_v[3])
    instructions[3].substitute(variable_v[6], variable_v[4])
    instructions[6].rename_destination(variable_v[5], variable_v[4])
    instructions[7].substitute(variable_v[5], variable_v[4])
    instructions[7].rename_destination(variable_v[6], variable_v[4])

    # update interference graph
    for neighbor in set(phi_fct_lifter.interference_graph.neighbors(variable_v[5])).union(
        set(phi_fct_lifter.interference_graph.neighbors(variable_v[6]))
    ):
        if neighbor != variable_v[4]:
            phi_fct_lifter.interference_graph.add_edge(variable_v[4], neighbor)
    phi_fct_lifter.interference_graph.remove_nodes_from([variable_v[5], variable_v[6]])
    phi_fct_lifter.interference_graph.add_edge(variable_v[3], variable_u[1])

    old_edges = set(phi_fct_lifter.interference_graph.edges())

    phi_fct_lifter.lift()

    new_edges = set(phi_fct_lifter.interference_graph.edges())
    new_node = [node for node in phi_fct_lifter._cfg.nodes if node not in set(nodes)]

    assert (
        nodes[0].instructions == [instructions[0]]
        and nodes[1].instructions == [instructions[4]]
        and nodes[2].instructions == [instructions[5]] + [Assignment(variable_u[3], variable_v[2])]
        and nodes[3].instructions == [instructions[6]] + [Assignment(variable_u[3], variable_v[3])]
        and nodes[4].instructions == [instructions[9]]
        and nodes[5].instructions == []
        and new_node[0].instructions == [Assignment(phi.definitions[0], phi.origin_block[nodes[0]]) for phi in instructions[1:3]]
        and new_node[1].instructions == [Assignment(phi.definitions[0], phi.origin_block[nodes[4]]) for phi in instructions[1:4]]
        and len(new_node) == 2
        and isinstance(edge := phi_fct_lifter._cfg.get_edge(nodes[0], new_node[0]), SwitchCase)
        and edge.cases == [Constant(3), Constant(2)]
        and isinstance(phi_fct_lifter._cfg.get_edge(new_node[0], nodes[1]), UnconditionalEdge)
        and isinstance(phi_fct_lifter._cfg.get_edge(nodes[1], nodes[2]), TrueCase)
        and isinstance(phi_fct_lifter._cfg.get_edge(nodes[1], nodes[3]), FalseCase)
        and isinstance(phi_fct_lifter._cfg.get_edge(nodes[2], nodes[4]), UnconditionalEdge)
        and isinstance(phi_fct_lifter._cfg.get_edge(nodes[3], nodes[4]), UnconditionalEdge)
        and isinstance(phi_fct_lifter._cfg.get_edge(nodes[4], nodes[5]), FalseCase)
        and isinstance(phi_fct_lifter._cfg.get_edge(nodes[4], new_node[1]), TrueCase)
        and isinstance(phi_fct_lifter._cfg.get_edge(new_node[1], nodes[1]), UnconditionalEdge)
        and old_edges - new_edges == set()
        and new_edges - old_edges == {(variable_v[2], variable_u[3]), (variable_u[1], variable_v[2]), (variable_u[2], variable_v[4])}
    )


def test_lifting_new_instructions_empty_a(variable_v, variable_u, construct_stage_for_lifting):
    """We do not lift instructions to one basic block."""
    phi_fct_lifter, instructions, nodes = construct_stage_for_lifting

    instructions[2].substitute(variable_u[3], variable_v[3])
    instructions[3].substitute(variable_v[1], variable_v[3])
    instructions[3].substitute(variable_v[6], variable_v[4])
    instructions[6].rename_destination(variable_v[5], variable_v[4])
    instructions[7].substitute(variable_v[5], variable_v[4])
    instructions[7].rename_destination(variable_v[6], variable_v[4])
    instructions[8].rename_destination(variable_u[3], variable_v[3])
    instructions[9].substitute(variable_u[3], variable_v[3])

    # update interference graph
    for neighbor in set(phi_fct_lifter.interference_graph.neighbors(variable_v[5])).union(
        set(phi_fct_lifter.interference_graph.neighbors(variable_v[6]))
    ):
        if neighbor != variable_v[4]:
            phi_fct_lifter.interference_graph.add_edge(variable_v[4], neighbor)
    phi_fct_lifter.interference_graph.remove_nodes_from([variable_u[3], variable_v[5], variable_v[6]])
    phi_fct_lifter.interference_graph.add_edge(variable_v[3], variable_u[1])

    old_edges = set(phi_fct_lifter.interference_graph.edges())

    phi_fct_lifter.lift()

    new_edges = set(phi_fct_lifter.interference_graph.edges())
    new_node = [node for node in phi_fct_lifter._cfg.nodes if node not in set(nodes)]
    assert (
        nodes[0].instructions == [instructions[0]]
        and nodes[1].instructions == [instructions[4]]
        and nodes[2].instructions == [instructions[5]] + [Assignment(variable_v[3], variable_v[2])]
        and nodes[3].instructions == [instructions[6]]
        and nodes[4].instructions == [instructions[9]]
        and nodes[5].instructions == []
        and new_node[0].instructions == [Assignment(phi.definitions[0], phi.origin_block[nodes[0]]) for phi in instructions[1:3]]
        and new_node[1].instructions == [Assignment(phi.definitions[0], phi.origin_block[nodes[4]]) for phi in instructions[1:4]]
        and len(new_node) == 2
        and isinstance(edge := phi_fct_lifter._cfg.get_edge(nodes[0], new_node[0]), SwitchCase)
        and edge.cases == [Constant(3), Constant(2)]
        and isinstance(phi_fct_lifter._cfg.get_edge(new_node[0], nodes[1]), UnconditionalEdge)
        and isinstance(phi_fct_lifter._cfg.get_edge(nodes[1], nodes[2]), TrueCase)
        and isinstance(phi_fct_lifter._cfg.get_edge(nodes[1], nodes[3]), FalseCase)
        and isinstance(phi_fct_lifter._cfg.get_edge(nodes[2], nodes[4]), UnconditionalEdge)
        and isinstance(phi_fct_lifter._cfg.get_edge(nodes[3], nodes[4]), UnconditionalEdge)
        and isinstance(phi_fct_lifter._cfg.get_edge(nodes[4], nodes[5]), FalseCase)
        and isinstance(phi_fct_lifter._cfg.get_edge(nodes[4], new_node[1]), TrueCase)
        and isinstance(phi_fct_lifter._cfg.get_edge(new_node[1], nodes[1]), UnconditionalEdge)
        and old_edges - new_edges == set()
        and new_edges - old_edges == {(variable_u[1], variable_v[2]), (variable_u[2], variable_v[4])}
    )


def test_lifting_new_instructions_empty_b(variable_v, variable_u):
    """We do not lift instructions to one basic block, this would be a new added basic block."""
    instructions = [
        Branch(Condition(OperationType.less, [variable_v[1], variable_u[1]])),
        Assignment(variable_v[2], BinaryOperation(OperationType.multiply, [Constant(2), variable_v[1]])),
        Phi(variable_v[1], [variable_v[1], variable_v[2]]),
        Phi(variable_u[1], [variable_u[1], variable_u[1]]),
    ]

    # Set of nodes:
    nodes = [BasicBlock(i) for i in range(3)]
    # Add instructions:
    nodes[0].instructions = [instructions[0]]
    nodes[1].instructions = [instructions[1]]
    nodes[2].instructions = instructions[2:]

    instructions[2]._origin_block = {nodes[0]: variable_v[1], nodes[1]: variable_v[2]}
    instructions[3]._origin_block = {nodes[0]: variable_u[1], nodes[1]: variable_u[1]}

    cfg = ControlFlowGraph()
    cfg.add_edges_from(
        [
            TrueCase(nodes[0], nodes[2]),
            FalseCase(nodes[0], nodes[1]),
            UnconditionalEdge(nodes[1], nodes[2]),
        ]
    )
    phi_fct_lifter = PhiFunctionLifter(cfg, InterferenceGraph(cfg), init_phi_functions_of_block(cfg))
    phi_fct_lifter.lift()

    assert (
        nodes[0].instructions == [instructions[0]]
        and nodes[1].instructions == [instructions[1], Assignment(variable_v[1], variable_v[2])]
        and nodes[2].instructions == []
        and set(phi_fct_lifter._cfg.nodes) == set(nodes)
        and isinstance(phi_fct_lifter._cfg.get_edge(nodes[0], nodes[2]), TrueCase)
        and isinstance(phi_fct_lifter._cfg.get_edge(nodes[0], nodes[1]), FalseCase)
        and isinstance(phi_fct_lifter._cfg.get_edge(nodes[1], nodes[2]), UnconditionalEdge)
        and set(phi_fct_lifter.interference_graph.edges()) == {(variable_v[1], variable_u[1]), (variable_u[1], variable_v[2])}
    )


def test_lifting_wrong_order(construct_stage_for_lifting):
    """The Phi-functions we want to lift have the wrong order."""
    phi_fct_lifter, instructions, nodes = construct_stage_for_lifting

    nodes[1].instructions[:3] = instructions[2:4] + [instructions[1]]
    phi_fct_lifter._phi_functions_of[nodes[1]] = nodes[1].instructions[:3]

    with pytest.raises(ValueError):
        phi_fct_lifter.lift()


def test_lifting_phi_on_top_1(variable_v, variable_u):
    """
    +--------------------+
    |        0.          | ---+
    | v#1 = ϕ(v#0, u#1)  |    |
    | u#1 = ϕ(v#0, u#2)  |    |
    | u#2 = v#1 + 10     | <--+
    +--------------------+
    """
    instructions = [
        Phi(variable_v[1], [variable_v[0], variable_u[1]]),
        Phi(variable_u[1], [variable_v[0], variable_u[2]]),
        Assignment(variable_u[2], BinaryOperation(OperationType.plus, [variable_v[1], Constant(10)])),
    ]
    node = BasicBlock(0, instructions[:])
    node.instructions[0]._origin_block = {None: variable_v[0], node: variable_u[1]}
    node.instructions[1]._origin_block = {None: variable_v[0], node: variable_u[2]}

    cfg = ControlFlowGraph()
    cfg.add_node(node)
    cfg.add_edges_from([UnconditionalEdge(node, node)])
    phi_fct_lifter = PhiFunctionLifter(cfg, InterferenceGraph(cfg), init_phi_functions_of_block(cfg))

    phi_fct_lifter.lift()

    new_nodes = [nd for nd in phi_fct_lifter._cfg.nodes if nd != node]

    assert (
        node.instructions == [instructions[-1]] + [Assignment(phi.definitions[0], phi.origin_block[node]) for phi in instructions[0:2]]
        and new_nodes[0].instructions == [Assignment(phi.definitions[0], phi.origin_block[None]) for phi in instructions[0:2]]
        and len(phi_fct_lifter._cfg) == 2
        and isinstance(phi_fct_lifter._cfg.get_edge(new_nodes[0], node), UnconditionalEdge)
        and isinstance(phi_fct_lifter._cfg.get_edge(node, node), UnconditionalEdge)
        and len(phi_fct_lifter._cfg.edges) == 2
    )
    # The root of the CFG must be updated by PhiFunctionLifter for the other stages to work
    assert cfg.root == new_nodes[0]


def test_lifting_phi_on_top_2(variable_v, variable_u):
    """
    +--------------------+
    |        0.          | ---+
    | u#2 = ϕ(v#1, u#1)  |    |
    | u#1 = ϕ(v#0, u#3)  |    |
    | u#3 = u#1 + u#2    | <--+
    +--------------------+
    """
    instructions = [
        Phi(variable_u[2], [variable_v[1], variable_u[1]]),
        Phi(variable_u[1], [variable_v[0], variable_u[3]]),
        Assignment(variable_u[3], BinaryOperation(OperationType.plus, [variable_u[1], variable_u[2]])),
    ]
    node = BasicBlock(0, instructions[:])
    node.instructions[0]._origin_block = {None: variable_v[0], node: variable_u[1]}
    node.instructions[1]._origin_block = {None: variable_v[1], node: variable_u[3]}

    cfg = ControlFlowGraph()
    cfg.add_node(node)
    cfg.add_edges_from([UnconditionalEdge(node, node)])
    phi_fct_lifter = PhiFunctionLifter(cfg, InterferenceGraph(cfg), init_phi_functions_of_block(cfg))

    phi_fct_lifter.lift()

    new_nodes = [nd for nd in phi_fct_lifter._cfg.nodes if nd != node]

    assert (
        node.instructions == [instructions[-1]] + [Assignment(phi.definitions[0], phi.origin_block[node]) for phi in instructions[0:2]]
        and new_nodes[0].instructions == [Assignment(phi.definitions[0], phi.origin_block[None]) for phi in instructions[0:2]]
        and len(phi_fct_lifter._cfg.nodes) == 2
        and isinstance(phi_fct_lifter._cfg.get_edge(new_nodes[0], node), UnconditionalEdge)
        and isinstance(phi_fct_lifter._cfg.get_edge(node, node), UnconditionalEdge)
        and len(phi_fct_lifter._cfg.edges) == 2
    )
    # The root of the CFG must be updated by PhiFunctionLifter for the other stages to work
    assert cfg.root == new_nodes[0]


def test_lifted_copies_of_the_same_value_do_not_interfere_with_it():
    """x#5 = x#6; r#4 = x#6: x#5 is a copy of x#6 while both are live, so they do not interfere (Chaitin)."""
    int32 = Integer.int32_t()
    x5, x6, r4, w, u = (Variable(n, int32, ssa_label=l) for n, l in [("x", 5), ("x", 6), ("r", 4), ("w", 0), ("u", 0)])
    lifter = PhiFunctionLifter(ControlFlowGraph(), InterferenceGraph(), {})
    lifter._update_interference_graph_after_lifting([Assignment(x5, x6), Assignment(r4, x6), Assignment(u, w)])
    assert not lifter.interference_graph.has_edge(x5, x6)
    assert lifter.interference_graph.has_edge(x5, w) and lifter.interference_graph.has_edge(r4, w)


def _relation_in_loop_task() -> DecompilerTask:
    """coreutils basenc base32_decode_ctx: phi copies on the back edge define x#5 before r#4 = x#6 reads x#6.

    0: x#4 = 1; r#3 = 2
    1: x#5 = ϕ(x#4, x#6); r#4 = ϕ(r#3, x#6); x#6 -> x#5; r#5 = x#6 + r#4; if (r#5 < 10)
    2: (back edge to 1)    3: return r#5
    """
    int32 = Integer.int32_t()
    x4, x5, x6 = (Variable("x", int32, ssa_label=l, is_aliased=True) for l in (4, 5, 6))
    r3, r4, r5 = (Variable("r", int32, ssa_label=l) for l in (3, 4, 5))
    nodes = [BasicBlock(i, []) for i in range(4)]
    phi_x, phi_r = Phi(x5, [x4, x6]), Phi(r4, [r3, x6])
    phi_x._origin_block, phi_r._origin_block = {nodes[0]: x4, nodes[2]: x6}, {nodes[0]: r3, nodes[2]: x6}
    nodes[0].instructions = [Assignment(x4, Constant(1, int32)), Assignment(r3, Constant(2, int32))]
    nodes[1].instructions = [
        phi_x,
        phi_r,
        Relation(x6, x5),
        Assignment(r5, BinaryOperation(OperationType.plus, [x6, r4])),
        Branch(Condition(OperationType.less, [r5, Constant(10, int32)])),
    ]
    nodes[3].instructions = [Return([r5])]
    cfg = ControlFlowGraph()
    cfg.add_edges_from(
        [
            UnconditionalEdge(nodes[0], nodes[1]),
            TrueCase(nodes[1], nodes[2]),
            FalseCase(nodes[1], nodes[3]),
            UnconditionalEdge(nodes[2], nodes[1]),
        ]
    )
    return DecompilerTask(name="relation-in-loop", function_identifier="", cfg=cfg, options=Options())


@pytest.mark.parametrize("mode", ["simple", "min", "lift_minimal", "conditional"])
def test_relation_whose_value_is_read_by_another_phi_survives_out_of_ssa(mode):
    from decompiler.pipeline.ssa.outofssatranslation import OutOfSsaTranslation

    task = _relation_in_loop_task()
    task.options.set("out-of-ssa-translation.mode", mode)
    OutOfSsaTranslation().run(task)
    assert not task.failed
