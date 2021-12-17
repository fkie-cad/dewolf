from dewolf.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, SwitchCase, TrueCase, UnconditionalEdge
from dewolf.structures.pseudo.expressions import Constant, FunctionSymbol, ImportedFunctionSymbol, Symbol, Variable
from dewolf.structures.pseudo.instructions import Assignment, Branch, Call, IndirectBranch, ListOperation, Phi, Return
from dewolf.structures.pseudo.operations import BinaryOperation, Condition, OperationType, UnaryOperation
from dewolf.structures.pseudo.typing import Integer, Pointer
from pytest import fixture


@fixture
def cfg() -> ControlFlowGraph:
    """A ControlFlowGraph fixture used in the unittests below.
                                      +------------------------------+
                                      |            65536.            |
                                      |          i#0 = 0x1           |
                                      +------------------------------+
                                        |
                                        |
                                        v
    +---------------------------+     +------------------------------+
    |          262144.          |     |           131072.            |
    | x#0 = printf(FORMAT, i#2) |     |       i#2 = ϕ(i#0,i#1)       |
    |        return x#0         | <-- |        if(i#2 < arg1)        | <+
    +---------------------------+     +------------------------------+  |
                                        |                               |
                                        |                               |
                                        v                               |
    +---------------------------+     +------------------------------+  |
    |          196352.          |     |           192512.            |  |
    |         odd(i#2)          |     | a#0 = (unsigned char) i#2 x2 |  |
    |                           | <-- |           jmp a#0            |  |
    +---------------------------+     +------------------------------+  |
      |                                 |                               |
      |                                 |                               |
      |                                 v                               |
      |                               +------------------------------+  |
      |                               |           195072.            |  |
      |                               |          even(i#2)           |  |
      |                               +------------------------------+  |
      |                                 |                               |
      |                                 |                               |
      |                                 v                               |
      |                               +------------------------------+  |
      |                               |           196608.            |  |
      +-----------------------------> |       i#1 = i#2 + 0x1        | -+
                                      +------------------------------+
    """
    graph = ControlFlowGraph()
    blocks = [
        BasicBlock(0x10000, [Assignment(Variable("i", Integer.uint32_t(), ssa_label=0), Constant(1, Integer.uint32_t()))]),
        BasicBlock(
            0x20000,
            [
                Phi(
                    Variable("i", Integer.uint32_t(), ssa_label=2),
                    [Variable("i", Integer.uint32_t(), ssa_label=0), Variable("i", Integer.uint32_t(), ssa_label=1)],
                ),
                Branch(
                    Condition(OperationType.less, [Variable("i", Integer.uint32_t(), ssa_label=2), Variable("arg1", Integer.uint32_t())])
                ),
            ],
        ),
        BasicBlock(
            0x2F000,
            [
                Assignment(
                    Variable("a", Integer.uint8_t(), ssa_label=0),
                    UnaryOperation(
                        OperationType.cast,
                        [
                            BinaryOperation(
                                OperationType.modulo, [Variable("i", Integer.uint32_t(), ssa_label=2), Constant(2, Integer.uint32_t())]
                            ),
                        ],
                        Integer.uint8_t(),
                    ),
                ),
                IndirectBranch(Variable("a", Integer.uint8_t(), ssa_label=0)),
            ],
        ),
        BasicBlock(
            0x2FA00,
            [
                Assignment(ListOperation([]), Call(FunctionSymbol("even", 0x100), [Variable("i", Integer.uint32_t(), ssa_label=2)])),
            ],
        ),
        BasicBlock(
            0x2FF00,
            [
                Assignment(ListOperation([]), Call(FunctionSymbol("odd", 0x200), [Variable("i", Integer.uint32_t(), ssa_label=2)])),
            ],
        ),
        BasicBlock(
            0x30000,
            [
                Assignment(
                    Variable("i", Integer.uint32_t(), ssa_label=1),
                    BinaryOperation(OperationType.plus, [Variable("i", Integer.uint32_t(), ssa_label=2), Constant(1, Integer.uint32_t())]),
                )
            ],
        ),
        BasicBlock(
            0x40000,
            [
                Assignment(
                    Variable("x", Integer.uint32_t(), ssa_label=0),
                    Call(
                        ImportedFunctionSymbol("printf", 0x300),
                        [Symbol("FORMAT", 0x3A0, Pointer(Integer.char(), 32)), Variable("i", Integer.uint32_t(), ssa_label=2)],
                    ),
                ),
                Return(ListOperation([Variable("x", Integer.uint32_t(), ssa_label=0)])),
            ],
        ),
    ]
    graph.add_nodes_from(blocks)
    graph.add_edges_from(
        [
            UnconditionalEdge(blocks[0], blocks[1]),
            TrueCase(blocks[1], blocks[2]),
            FalseCase(blocks[1], blocks[6]),
            SwitchCase(blocks[2], blocks[3], [Constant(0, Integer.uint8_t())]),
            SwitchCase(blocks[2], blocks[4], [Constant(1, Integer.uint8_t())]),
            UnconditionalEdge(blocks[3], blocks[5]),
            UnconditionalEdge(blocks[4], blocks[5]),
            UnconditionalEdge(blocks[5], blocks[1]),
        ]
    )
    return graph


def test_properties(cfg: ControlFlowGraph):
    """Test the basic properties of a ControlFlowGraph."""
    assert len(cfg) == len(cfg.nodes) == len(list(cfg)) == 7
    assert all([node in cfg for node in cfg])
    assert cfg.root.address == 0x10000
    assert cfg.root == cfg[0x10000]
    assert {node.address for node in cfg} == {0x10000, 0x20000, 0x2F000, 0x2FA00, 0x2FF00, 0x30000, 0x40000}
    assert not cfg.is_acyclic()


def test_edges(cfg: ControlFlowGraph):
    """Check the edge properties of the cfg."""
    assert len(cfg.edges) == 8
    assert all(edge.source in cfg and edge.sink in cfg for edge in cfg.edges)
    assert isinstance(cfg.get_edge(cfg[0x10000], cfg[0x20000]), UnconditionalEdge)
    assert isinstance(cfg.get_edge(cfg[0x20000], cfg[0x2F000]), TrueCase)
    assert isinstance(cfg.get_edge(cfg[0x20000], cfg[0x40000]), FalseCase)
    assert isinstance(cfg.get_edge(cfg[0x2F000], cfg[0x2FA00]), SwitchCase)
    assert isinstance(cfg.get_edge(cfg[0x2F000], cfg[0x2FF00]), SwitchCase)
    assert isinstance(cfg.get_edge(cfg[0x2FA00], cfg[0x30000]), UnconditionalEdge)
    assert isinstance(e2 := cfg.get_edge(cfg[0x2FF00], cfg[0x30000]), UnconditionalEdge)
    assert isinstance(e1 := cfg.get_edge(cfg[0x30000], cfg[0x20000]), UnconditionalEdge)
    assert e1 in cfg.edges
    assert e1 == e1.copy()
    cfg.remove_edge(e1)
    assert e1 not in cfg.edges and cfg.get_edge(cfg[0x30000], cfg[0x20000]) is None
    assert cfg.is_acyclic()
    e3 = e2.copy(sink=cfg[0x20000])
    assert e3 not in cfg.edges and e3 != e2
    cfg.substitute_edge(e2, e3)
    assert e2 not in cfg.edges and cfg.get_edge(cfg[0x2FF00], cfg[0x30000]) is None
    assert e3 in cfg.edges and cfg.get_edge(cfg[0x2FF00], cfg[0x20000])


def test_create_block(cfg: ControlFlowGraph):
    """Unittest for the ControlFlowGraph.add_block method."""
    blocks = cfg.nodes
    first_new_block = cfg.create_block()
    assert first_new_block.address == -1 and first_new_block not in blocks and first_new_block in cfg
    instruction = Assignment(Variable("i"), BinaryOperation(OperationType.plus, [Variable("i"), Constant(1, Integer.int32_t())]))
    second_new_block = cfg.create_block([instruction])
    assert second_new_block.address == -2 and second_new_block not in blocks and second_new_block in cfg
    assert second_new_block.instructions == [instruction]
    assert first_new_block not in cfg.dominator_tree and second_new_block not in cfg.dominator_tree


def test_variables(cfg: ControlFlowGraph):
    """Test the variable management of ControlFlowGraph methods."""
    assert cfg.get_variables() == {
        Variable("i", Integer.uint32_t(), ssa_label=0),
        Variable("i", Integer.uint32_t(), ssa_label=1),
        Variable("i", Integer.uint32_t(), ssa_label=2),
        Variable("a", Integer.uint8_t(), ssa_label=0),
        Variable("x", Integer.uint32_t(), ssa_label=0),
        Variable("arg1", Integer.uint32_t()),
    }
    assert cfg.get_defined_variables() == {
        Variable("i", Integer.uint32_t(), ssa_label=0),
        Variable("i", Integer.uint32_t(), ssa_label=1),
        Variable("i", Integer.uint32_t(), ssa_label=2),
        Variable("a", Integer.uint8_t(), ssa_label=0),
        Variable("x", Integer.uint32_t(), ssa_label=0),
    }
    assert cfg.get_undefined_variables() == {Variable("arg1", Integer.uint32_t())}
    cfg.root.add_instruction(Assignment(Variable("arg1", Integer.uint32_t()), Constant(0, Integer.uint32_t())))
    assert cfg.get_undefined_variables() == set()
    cfg.remove_node(cfg[0x40000])
    assert Variable("x", Integer.uint32_t(), ssa_label=0) not in cfg.get_variables()


def test_definitions(cfg: ControlFlowGraph):
    """Test the cfg.get_definitions method."""
    assert list(cfg.get_definitions(Variable("i", Integer.uint32_t(), ssa_label=0))) == [
        Assignment(Variable("i", Integer.uint32_t(), ssa_label=0), Constant(1, Integer.uint32_t()))
    ]
    assert list(cfg.get_definitions(Variable("a", Integer.uint8_t(), ssa_label=0))) == [
        Assignment(
            Variable("a", Integer.uint8_t(), ssa_label=0),
            UnaryOperation(
                OperationType.cast,
                [
                    BinaryOperation(
                        OperationType.modulo, [Variable("i", Integer.uint32_t(), ssa_label=2), Constant(2, Integer.uint32_t())]
                    ),
                ],
                Integer.uint8_t(),
            ),
        )
    ]


def test_get_usages(cfg: ControlFlowGraph):
    """Test the cfg.get_usages method."""
    assert list(cfg.get_usages(Variable("i", Integer.uint32_t(), ssa_label=0))) == [
        Phi(
            Variable("i", Integer.uint32_t(), ssa_label=2),
            [Variable("i", Integer.uint32_t(), ssa_label=0), Variable("i", Integer.uint32_t(), ssa_label=1)],
        )
    ]
    assert set(cfg.get_usages(Variable("i", Integer.uint32_t(), ssa_label=2))) == {
        Assignment(
            Variable("i", Integer.uint32_t(), ssa_label=1),
            BinaryOperation(OperationType.plus, [Variable("i", Integer.uint32_t(), ssa_label=2), Constant(1, Integer.uint32_t())]),
        ),
        Assignment(
            Variable("x", Integer.uint32_t(), ssa_label=0),
            Call(
                ImportedFunctionSymbol("printf", 0x300),
                [Symbol("FORMAT", 0x3A0, Pointer(Integer.char(), 32)), Variable("i", Integer.uint32_t(), ssa_label=2)],
            ),
        ),
        Assignment(ListOperation([]), Call(FunctionSymbol("even", 0x100), [Variable("i", Integer.uint32_t(), ssa_label=2)])),
        Assignment(ListOperation([]), Call(FunctionSymbol("odd", 0x200), [Variable("i", Integer.uint32_t(), ssa_label=2)])),
        Assignment(
            Variable("a", Integer.uint8_t(), ssa_label=0),
            UnaryOperation(
                OperationType.cast,
                [
                    BinaryOperation(
                        OperationType.modulo, [Variable("i", Integer.uint32_t(), ssa_label=2), Constant(2, Integer.uint32_t())]
                    ),
                ],
                Integer.uint8_t(),
            ),
        ),
    }
