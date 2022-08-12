from typing import Tuple

from decompiler.pipeline.preprocessing import MemPhiConverter
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, UnconditionalEdge
from decompiler.structures.pseudo.expressions import Constant, FunctionSymbol, GlobalVariable, ImportedFunctionSymbol, Variable
from decompiler.structures.pseudo.instructions import Assignment, Branch, MemPhi, Phi
from decompiler.structures.pseudo.operations import BinaryOperation, Call, Condition, ListOperation, OperationType, UnaryOperation
from decompiler.structures.pseudo.typing import Integer, UnknownType
from decompiler.task import DecompilerTask
from pytest import fixture


def function_symbol(name: str, value: int = 0x42) -> FunctionSymbol:
    return FunctionSymbol(name, value)


def ext_function_symbol(name: str, value: int = 0x42) -> ImportedFunctionSymbol:
    return ImportedFunctionSymbol(name, value)


def test_mem_phi_result_in_no_phi_when_no_aliased_variables(cfg_with_no_aliased_variable_1):
    input_cfg, expected_cfg = cfg_with_no_aliased_variable_1
    _test_mem_phi_converter(input_cfg, expected_cfg)


def test_single_aliased_variable_result_in_single_phi_chain_1(cfg_with_single_aliased_variable_1):
    input_cfg, expected_cfg = cfg_with_single_aliased_variable_1
    _test_mem_phi_converter(input_cfg, expected_cfg)


def test_single_aliased_variable_result_in_single_phi_chain_2(cfg_with_single_aliased_variable_2):
    input_cfg, expected_cfg = cfg_with_single_aliased_variable_2
    _test_mem_phi_converter(input_cfg, expected_cfg)


def test_single_aliased_variable_result_in_single_phi_chain_3(cfg_with_single_aliased_variable_3):
    input_cfg, expected_cfg = cfg_with_single_aliased_variable_3
    _test_mem_phi_converter(input_cfg, expected_cfg)


def test_single_aliased_variable_result_in_single_phi_chain_4(cfg_with_single_aliased_variable_4):
    input_cfg, expected_cfg = cfg_with_single_aliased_variable_4
    _test_mem_phi_converter(input_cfg, expected_cfg)


def test_single_aliased_variable_result_in_single_phi_chain_5(cfg_with_single_aliased_variable_5):
    input_cfg, expected_cfg = cfg_with_single_aliased_variable_5
    _test_mem_phi_converter(input_cfg, expected_cfg)


def test_multiple_aliased_variables_result_in_corresponding_number_of_phi_chains_1(cfg_with_multiple_aliased_variables_1):
    input_cfg, expected_cfg = cfg_with_multiple_aliased_variables_1
    _test_mem_phi_converter(input_cfg, expected_cfg)


def test_multiple_aliased_variables_result_in_corresponding_number_of_phi_chains_2(cfg_with_multiple_aliased_variables_2):
    input_cfg, expected_cfg = cfg_with_multiple_aliased_variables_2
    _test_mem_phi_converter(input_cfg, expected_cfg)


def test_multiple_aliased_variables_result_in_corresponding_number_of_phi_chains_3(cfg_with_multiple_aliased_variables_3):
    input_cfg, expected_cfg = cfg_with_multiple_aliased_variables_3
    _test_mem_phi_converter(input_cfg, expected_cfg)


def test_multiple_aliased_variables_result_in_corresponding_number_of_phi_chains_4(cfg_with_multiple_aliased_variables_4):
    input_cfg, expected_cfg = cfg_with_multiple_aliased_variables_4
    _test_mem_phi_converter(input_cfg, expected_cfg)


def test_multiple_aliased_variables_result_in_corresponding_number_of_phi_chains_5(cfg_with_multiple_aliased_variables_5):
    input_cfg, expected_cfg = cfg_with_multiple_aliased_variables_5
    _test_mem_phi_converter(input_cfg, expected_cfg)


def test_no_mem_phi_target_used_only_mem_phi_arguments_used(no_mem_phi_target_in_use_only_arguments):
    input_cfg, expected_cfg = no_mem_phi_target_in_use_only_arguments
    _test_mem_phi_converter(input_cfg, expected_cfg)


def test_no_mem_phi_connected_explicitly_to_aliased_variable(no_connection_between_aliased_variables_and_mem_phi_for_calls):
    input_cfg, expected_cfg = no_connection_between_aliased_variables_and_mem_phi_for_calls
    _test_mem_phi_converter(input_cfg, expected_cfg)


def test_phi_created_for_global_variables(cfg_with_single_global_variable):
    input_cfg, expected_cfg = cfg_with_single_global_variable
    _test_mem_phi_converter(input_cfg, expected_cfg)


@fixture
def cfg_with_single_aliased_variable_1(x, z_aliased) -> Tuple[ControlFlowGraph, ControlFlowGraph]:
    """
          +-------------+                        +-------------+
          |  x#0 = x#1  |                        | v1#0 = v3#0 |
          +------+------+                        +------+------+
                 |                                      |
    +------------+------------+              +----------+----------+
    | mem#1 = φ(mem#0, mem#3) |<--+          |  z#1 = φ(z#0, z#3)  |<----+
    | x#2  = z#1              |   |          |  x#2 = z#1          |     |
    +-------------------------+   |          +----------+----------+     |
                 |                |                     |                |
         +-------+-------+        |             +-------+-------+        |
         |               |        |             |               |        |
    +----+----+     +----+----+   |        +----+----+     +----+----+   |
    |         |     |         |   |   ->   |         »     |         |   |
    +----+----+     +----+----+   |        +----+----+     +----+----+   |
         |               |        |             |               |        |
         +-------+-------+        |             +-------+-------+        |
                 |                |                     |                |
    +------------+------------+   |        +------------+------------+   |
    | mem#3 = φ(mem#1, mem#2) |---+        |   z#3 = φ(z#1, z#2)     |---+
    +-------------------------+            +-------------------------+
    """
    cfg = ControlFlowGraph()
    mem0, mem1, mem2, mem3 = generate_mem_phi_variables(4)
    n1 = BasicBlock(1, [Assignment(x[0], x[1])])
    n2 = BasicBlock(2, [MemPhi(mem1, [mem0, mem3]), Assignment(x[2], z_aliased[1])])
    n3 = BasicBlock(3, [])
    n4 = BasicBlock(4, [])
    n5 = BasicBlock(5, [MemPhi(mem3, [mem1, mem2])])
    cfg.add_edges_from(
        [
            UnconditionalEdge(n1, n2),
            UnconditionalEdge(n2, n3),
            UnconditionalEdge(n2, n4),
            UnconditionalEdge(n3, n5),
            UnconditionalEdge(n4, n5),
            UnconditionalEdge(n5, n2),
        ]
    )

    expected_cfg = ControlFlowGraph()
    n2 = BasicBlock(2, [Phi(z_aliased[1], [z_aliased[0], z_aliased[3]]), Assignment(x[2], z_aliased[1])])
    n5 = BasicBlock(5, [Phi(z_aliased[3], [z_aliased[1], z_aliased[2]])])
    expected_cfg.add_edges_from(
        [
            UnconditionalEdge(n1, n2),
            UnconditionalEdge(n2, n3),
            UnconditionalEdge(n2, n4),
            UnconditionalEdge(n3, n5),
            UnconditionalEdge(n4, n5),
            UnconditionalEdge(n5, n2),
        ]
    )
    return cfg, expected_cfg


@fixture
def cfg_with_multiple_aliased_variables_1(x, z_aliased, y_aliased) -> Tuple[ControlFlowGraph, ControlFlowGraph]:
    """
           +-------------+                        +-------------+
           |  x#0 = x#1  |                        |  x#0 = x#1  |
           +------+------+                        +------+------+
                  |                                      |
     +------------+------------+              +----------+----------+
     | mem#2 = φ(mem#1, mem#5) |<--+          |  z#2 = φ(z#1, z#5)  |<----+
     +-------------------------+   |          |  y#2 = φ(y#1, y#5)  |     |
                  |                |          +----------+----------+     |
                  |                |                     |                |
          +-------+-------+        |             +-------+-------+        |
          |               |        |             |               |        |
    +-----+-----+    +----+----+   |       +-----+-----+    +----+----+   |
    | x#2 = z#2 |    |         |   |       | x#2 = z#2 |    |         |   |
    +-----+-----+    +----+----+   |       +-----+-----+    +----+----+   |
          |               |        |             |               |        |
          +-------+-------+        |             +-------+-------+        |
                  |                |                     |                |
     +------------+------------+   |        +------------+------------+   |
     | mem#4 = φ(mem#2, mem#3) |   |   ->   |   z#4 = φ(z#2, z#3)     |   |
     +-------------------------+   |        |   y#4 = φ(y#2, z#3)     |   |
                  |                |        +-------------------------+   |
                  |                |                     |                |
          +-------+-------+        |             +-------+-------+        |
     +----+----+    +-----+-----+  |        +----+----+    +-----+-----+  |
     |         |    | x#3 = y#4 |  |        |         |    | x#3 = y#4 |  |
     +----+----+    +-----+-----+  |        +----+----+    +-----+-----+  |
          +-------+-------+        |             +-------+-------+        |
                  |                |                     |                |
     +------------+------------+   |         +-----------+-----------+    |
     | mem#5 = φ(mem#4, mem#6) |---+         |  z#5 = φ(z#4, z#6)    |----+
     +-------------------------+             |  y#5 = φ(y#4, y#6)    |
                                             +-----------------------+
    """
    cfg = ControlFlowGraph()
    mem0, mem1, mem2, mem3, mem4, mem5, mem6 = generate_mem_phi_variables(7)
    n1 = BasicBlock(1, [Assignment(x[1], x[0])])
    n2 = BasicBlock(2, [MemPhi(mem2, [mem1, mem5])])
    n3 = BasicBlock(3, [Assignment(x[2], z_aliased[2])])
    n4 = BasicBlock(4, [])
    n5 = BasicBlock(5, [MemPhi(mem4, [mem2, mem3])])
    n6 = BasicBlock(6, [])
    n7 = BasicBlock(7, [Assignment(x[3], y_aliased[4])])
    n8 = BasicBlock(8, [MemPhi(mem5, [mem4, mem6])])
    cfg.add_edges_from(
        [
            UnconditionalEdge(n1, n2),
            UnconditionalEdge(n2, n3),
            UnconditionalEdge(n2, n4),
            UnconditionalEdge(n3, n5),
            UnconditionalEdge(n4, n5),
            UnconditionalEdge(n5, n6),
            UnconditionalEdge(n5, n7),
            UnconditionalEdge(n6, n8),
            UnconditionalEdge(n7, n8),
            UnconditionalEdge(n8, n2),
        ]
    )

    expected_cfg = ControlFlowGraph()
    n1 = BasicBlock(1, [Assignment(x[1], x[0])])
    n2 = BasicBlock(2, [Phi(z_aliased[2], [z_aliased[1], z_aliased[5]]), Phi(y_aliased[2], [y_aliased[1], y_aliased[5]])])
    n5 = BasicBlock(5, [Phi(z_aliased[4], [z_aliased[2], z_aliased[3]]), Phi(y_aliased[4], [y_aliased[2], y_aliased[3]])])
    n8 = BasicBlock(8, [Phi(z_aliased[5], [z_aliased[4], z_aliased[6]]), Phi(y_aliased[5], [y_aliased[4], y_aliased[6]])])
    expected_cfg.add_edges_from(
        [
            UnconditionalEdge(n1, n2),
            UnconditionalEdge(n2, n3),
            UnconditionalEdge(n2, n4),
            UnconditionalEdge(n3, n5),
            UnconditionalEdge(n4, n5),
            UnconditionalEdge(n5, n6),
            UnconditionalEdge(n5, n7),
            UnconditionalEdge(n6, n8),
            UnconditionalEdge(n7, n8),
            UnconditionalEdge(n8, n2),
        ]
    )
    return cfg, expected_cfg


@fixture
def cfg_with_no_aliased_variable_1(x) -> Tuple[ControlFlowGraph, ControlFlowGraph]:
    """
          +-------------+                        +-------------+
          |  x#1 = x#0  |                        |  x#1 = x#0  |
          +------+------+                        +------+------+
                 |                                      |
    +------------+------------+                 +------+--------+
    | mem#2 = φ(mem#1, mem#4) |<--+             |   x#2 = x#1   |<-------+
    | x#2  = x#1              |   |             +-------+-------+        |
    +-------------------------+   |                     |                |
                 |                |                     |                |
         +-------+-------+        |             +-------+-------+        |
         |               |        |             |               |        |
    +----+----+     +----+----+   |        +----+----+     +----+----+   |
    |         |     |         |   |   ->   |         »     |         |   |
    +----+----+     +----+----+   |        +----+----+     +----+----+   |
         |               |        |             |               |        |
         +-------+-------+        |             +-------+-------+        |
                 |                |                     |                |
    +------------+------------+   |                +----+----+           |
    | mem#4 = φ(mem#2, mem#3) |---+                |         |-----------+
    +-------------------------+                    +---------+
    """
    cfg = ControlFlowGraph()
    mem0, mem1, mem2, mem3, mem4 = generate_mem_phi_variables(5)
    n1 = BasicBlock(1, [Assignment(x[1], x[0])])
    n2 = BasicBlock(2, [MemPhi(mem2, [mem1, mem4]), Assignment(x[2], x[1])])
    n3 = BasicBlock(3, [])
    n4 = BasicBlock(4, [])
    n5 = BasicBlock(5, [MemPhi(mem4, [mem2, mem3])])
    cfg.add_edges_from(
        [
            UnconditionalEdge(n1, n2),
            UnconditionalEdge(n2, n3),
            UnconditionalEdge(n2, n4),
            UnconditionalEdge(n3, n5),
            UnconditionalEdge(n4, n5),
            UnconditionalEdge(n5, n2),
        ]
    )

    res_cfg = ControlFlowGraph()
    n2 = BasicBlock(2, [Assignment(x[2], x[1])])
    n5 = BasicBlock(5, [])
    res_cfg.add_edges_from(
        [
            UnconditionalEdge(n1, n2),
            UnconditionalEdge(n2, n3),
            UnconditionalEdge(n2, n4),
            UnconditionalEdge(n3, n5),
            UnconditionalEdge(n4, n5),
            UnconditionalEdge(n5, n2),
        ]
    )
    return cfg, res_cfg


@fixture
def cfg_with_single_aliased_variable_2(x, z_aliased) -> Tuple[ControlFlowGraph, ControlFlowGraph]:
    """
    +---+     +--------------------------------+        +---+     +---------------------+
    | 4 | <-- |           x#1 = x#0            |        | 4 | <-- |      x#1 = x#0      |
    +---+     +--------------------------------+        +---+     +---------------------+
      |         |                                         |         |
      |         |                                         |         |
      |         v                                         |         v
      |       +--------------------------------+          |       +---------------------+
      |       |   mem#2 = ϕ(mem#1,mem#3)       | <+       |       |  z#2 = ϕ(z#1,z#3)   | <+
      |       +--------------------------------+  |       |       +---------------------+  |
      |         |                                 |       |         |                      |
      |         |                                 | -->   |         |                      |
      |         v                                 |       |         v                      |
      |       +--------------------------------+  |       |       +---------------------+  |
      |       |               3                | -+       |       |          3          | -+
      |       +--------------------------------+          |       +---------------------+
      |         |                                         |         |
      |         |                                         |         |
      |         v                                         |         v
      |       +--------------------------------+          |       +---------------------+
      +-----> |     mem#4 = ϕ(mem#3,mem#5)     |          +-----> |  z#4 = ϕ(z#3,z#5)   |
              |     x#2 = z#4                  |                  |  x#2 = z#4
              +--------------------------------+                  +---------------------+


    """
    cfg = ControlFlowGraph()
    _, mem1, mem2, mem3, mem4, mem5 = generate_mem_phi_variables(6)
    n1 = BasicBlock(1, [Assignment(x[1], x[0])])
    n2 = BasicBlock(2, [MemPhi(mem2, [mem1, mem3])])
    n3 = BasicBlock(3, [])
    n4 = BasicBlock(4, [])
    n5 = BasicBlock(5, [MemPhi(mem4, [mem3, mem5]), Assignment(x[2], z_aliased[4])])
    cfg.add_edges_from(
        [
            UnconditionalEdge(n1, n2),
            UnconditionalEdge(n1, n4),
            UnconditionalEdge(n2, n3),
            UnconditionalEdge(n3, n2),
            UnconditionalEdge(n3, n5),
            UnconditionalEdge(n4, n5),
        ]
    )

    res = ControlFlowGraph()
    n1 = BasicBlock(1, [Assignment(x[1], x[0])])
    n2 = BasicBlock(2, [Phi(z_aliased[2], [z_aliased[1], z_aliased[3]])])
    n5 = BasicBlock(5, [Phi(z_aliased[4], [z_aliased[3], z_aliased[5]]), Assignment(x[2], z_aliased[4])])

    res.add_edges_from(
        [
            UnconditionalEdge(n1, n2),
            UnconditionalEdge(n1, n4),
            UnconditionalEdge(n2, n3),
            UnconditionalEdge(n3, n2),
            UnconditionalEdge(n3, n5),
            UnconditionalEdge(n4, n5),
        ]
    )
    return cfg, res


@fixture
def cfg_with_single_aliased_variable_3(x, z_aliased) -> Tuple[ControlFlowGraph, ControlFlowGraph]:
    """
    +-------------------------+             +-------------------+
    | mem#3 = φ(mem#1, mem#2) |             | z#3 = φ(z#1, z#2) |
    | x#2 = z#3               |             | x#2 = x#1         |
    +-------------------------+             +-------------------+

    +-------------------------+             +-------------------+
    | mem#5 = φ(mem#3, mem#4) |             | z#5 = φ(z#3, z#4) |
    +-------------------------+             +-------------------+

    +-------------------------+             +-------------------+
    | mem#7 = φ(mem#5, mem#6) |             | z#7 = φ(z#5, z#6) |
    +-------------------------+             +-------------------+
    """
    cfg = ControlFlowGraph()
    _, mem1, mem2, mem3, mem4, mem5, mem6, mem7, mem8 = generate_mem_phi_variables(9)
    n1 = BasicBlock(1, [MemPhi(mem3, [mem1, mem2]), Assignment(x[2], z_aliased[3])])
    n2 = BasicBlock(2, [MemPhi(mem5, [mem3, mem4])])
    n3 = BasicBlock(3, [MemPhi(mem7, [mem5, mem6])])
    cfg.add_nodes_from([n1, n2, n3])

    expected_cfg = ControlFlowGraph()
    n1 = BasicBlock(1, [Phi(z_aliased[3], [z_aliased[1], z_aliased[2]]), Assignment(x[2], z_aliased[3])])
    n2 = BasicBlock(2, [Phi(z_aliased[5], [z_aliased[3], z_aliased[4]])])
    n3 = BasicBlock(3, [Phi(z_aliased[7], [z_aliased[5], z_aliased[6]])])
    expected_cfg.add_nodes_from([n1, n2, n3])

    return cfg, expected_cfg


@fixture
def cfg_with_multiple_aliased_variables_5(x, z_aliased, y_aliased) -> Tuple[ControlFlowGraph, ControlFlowGraph]:
    """ " MemPhi followed by Phi and once by an assignment
           +-------------+                        +-------------+
           |  z#1 = x#1  |                        |  z#1 = x#1  |
           +------+------+                        +------+------+
                  |                                      |
     +------------+------------+              +----------+----------+
     | mem#2 = φ(mem#1, mem#5) |<--+          |  z#2 = φ(z#1, z#5)  |<----+
     | x#3 = φ(x#1, x#2)       |   |          |  y#2 = φ(y#1, y#5)  |     |
     | x#1 = z#2               |   |          |  x#3 = φ(x#1, x#2)  |     |
     +-------------------------+   |          |  x#1 = z#2          |     |
                  |                |          +----------+----------+     |
                  |                |                     |                |
          +-------+-------+        |             +-------+-------+        |
          |               |        |             |               |        |
    +-----+-----+    +----+----+   |       +-----+-----+    +----+----+   |
    |           |    |         |   |       |           |    |         |   |
    +-----+-----+    +----+----+   |       +-----+-----+    +----+----+   |
          |               |        |             |               |        |
          +-------+-------+        |             +-------+-------+        |
                  |                |                     |                |
     +------------+------------+   |        +------------+------------+   |
     | mem#4 = φ(mem#2, mem#3) |   |   ->   |   z#4 = φ(z#2, z#3)     |   |
     +-------------------------+   |        |   y#4 = φ(y#2, z#3)     |   |
                  |                |        +-------------------------+   |
                  |                |                     |                |
          +-------+-------+        |             +-------+-------+        |
     +----+----+    +-----+-----+  |        +----+----+    +-----+-----+  |
     |         |    |           |  |        |         |    |           |  |
     +----+----+    +-----+-----+  |        +----+----+    +-----+-----+  |
          +-------+-------+        |             +-------+-------+        |
                  |                |                     |                |
     +------------+------------+   |         +-----------+-----------+    |
     | mem#5 = φ(mem#4, mem#6) |---+         |  z#5 = φ(z#4, z#6)    |----+
     | x#5 = z#5               |             |  y#5 = φ(y#4, y#6)    |
     | x#0 = y#5               |             |  x#5 = z#5            |
     +-------------------------+             |  x#0 = y#5            |
                                             +-----------------------+
    """
    cfg = ControlFlowGraph()
    _, mem1, mem2, mem3, mem4, mem5, mem6 = generate_mem_phi_variables(7)
    n1 = BasicBlock(1, [Assignment(z_aliased[1], x[1])])
    n2 = BasicBlock(2, [MemPhi(mem2, [mem1, mem5]), Phi(x[3], [x[1], x[2]]), Assignment(x[1], z_aliased[2])])
    n3 = BasicBlock(3, [])
    n4 = BasicBlock(4, [])
    n5 = BasicBlock(5, [MemPhi(mem4, [mem2, mem3])])
    n6 = BasicBlock(6, [])
    n7 = BasicBlock(7, [])
    n8 = BasicBlock(8, [MemPhi(mem5, [mem4, mem6]), Assignment(x[5], z_aliased[5]), Assignment(x[0], y_aliased[5])])
    cfg.add_edges_from(
        [
            UnconditionalEdge(n1, n2),
            UnconditionalEdge(n2, n3),
            UnconditionalEdge(n2, n4),
            UnconditionalEdge(n3, n5),
            UnconditionalEdge(n4, n5),
            UnconditionalEdge(n5, n6),
            UnconditionalEdge(n5, n7),
            UnconditionalEdge(n6, n8),
            UnconditionalEdge(n7, n8),
            UnconditionalEdge(n8, n2),
        ]
    )

    res = ControlFlowGraph()
    n2 = BasicBlock(
        2,
        [
            Phi(z_aliased[2], [z_aliased[1], z_aliased[5]]),
            Phi(y_aliased[2], [y_aliased[1], y_aliased[5]]),
            Phi(x[3], [x[1], x[2]]),
            Assignment(x[1], z_aliased[2]),
        ],
    )
    n5 = BasicBlock(5, [Phi(z_aliased[4], [z_aliased[2], z_aliased[3]]), Phi(y_aliased[4], [y_aliased[2], y_aliased[3]])])
    n8 = BasicBlock(
        8,
        [
            Phi(z_aliased[5], [z_aliased[4], z_aliased[6]]),
            Phi(y_aliased[5], [y_aliased[4], y_aliased[6]]),
            Assignment(x[5], z_aliased[5]),
            Assignment(x[0], y_aliased[5]),
        ],
    )
    res.add_edges_from(
        [
            UnconditionalEdge(n1, n2),
            UnconditionalEdge(n2, n3),
            UnconditionalEdge(n2, n4),
            UnconditionalEdge(n3, n5),
            UnconditionalEdge(n4, n5),
            UnconditionalEdge(n5, n6),
            UnconditionalEdge(n5, n7),
            UnconditionalEdge(n6, n8),
            UnconditionalEdge(n7, n8),
            UnconditionalEdge(n8, n2),
        ]
    )
    return cfg, res


@fixture
def cfg_with_multiple_aliased_variables_2(x, z_aliased, y_aliased) -> Tuple[ControlFlowGraph, ControlFlowGraph]:
    """ "
           +-------------+                        +-------------+
           |  z#1 = x#1  |                        |  z#1 = x#1  |
           +------+------+                        +------+------+
                  |                                      |
     +------------+------------+              +----------+----------+
     | mem#1 = φ(mem#0, mem#9) |<--+          |  z#1 = φ(z#0, z#9)  |
     |                         |   |          |  y#1 = φ(y#0, y#9)  |<----+
     | x#3 = φ(x#1, x#2)       |   |          |  x#3 = φ(x#1, x#2)  |     |
     | x#1 = z#1               |   |          |  x#1 = z#1          |     |
     +-------------------------+   |          +----------+----------+     |
                  |                |                     |                |
                  |                |                     |                |
          +-------+-------+        |             +-------+-------+        |
          |               |        |             |               |        |
    +-----+-----+    +----+----+   |       +-----+-----+    +----+----+   |
    |           |    |         |   |       |           |    |         |   |
    +-----+-----+    +----+----+   |       +-----+-----+    +----+----+   |
          |               |        |             |               |        |
          +-------+-------+        |             +-------+-------+        |
                  |                |                     |                |
     +------------+------------+   |        +------------+------------+   |
     | mem#4 = φ(mem#2, mem#3) |   |   ->   |   z#4 = φ(z#2, z#3)     |   |
     +-------------------------+   |        |   y#4 = φ(y#2, z#3)     |   |
                  |                |        +-------------------------+   |
                  |                |                     |                |
          +-------+-------+        |             +-------+-------+        |
     +----+----+    +-----+-----+  |        +----+----+    +-----+-----+  |
     |         |    |           |  |        |         |    |           |  |
     +----+----+    +-----+-----+  |        +----+----+    +-----+-----+  |
          +-------+-------+        |             +-------+-------+        |
                  |                |                     |                |
     +------------+------------+   |        +------------+------------+   |
     | mem#6 = φ(mem#4, mem#5) |   |        |   z#6 = φ(z#4, z#5)     |   |
     | x#5 = z#4               |   |        |   y#6 = φ(y#4, z#5)     |   |
     | x#0 = y#6               |   |        |   x#5 = z#4             |   |
     +-------------------------+   |        |   x#0 = y#6             |   |
                  |                |        +-------------------------+   |
                  |                |                     |                |
          +-------+-------+        |             +-------+-------+        |
     +----+----+    +-----+-----+  |        +----+----+    +-----+-----+  |
     |         |    |           |  |        |         |    |           |  |
     +----+----+    +-----+-----+  |        +----+----+    +-----+-----+  |
          +-------+-------+        |             +-------+-------+        |
                  |                |                     |                |
     +------------+------------+   |         +-----------+-----------+    |
     | mem#9 = φ(mem#7, mem#8) |---+         |  z#9 = φ(z#7, z#8)    |    |
     |                         |             |  y#9 = φ(y#7, y#8)    |----+
     +-------------------------+             +-----------------------+
    """
    cfg = ControlFlowGraph()
    mem = generate_mem_phi_variables(10)
    n1 = BasicBlock(1, [Assignment(z_aliased[1], x[1])])
    n2 = BasicBlock(2, [MemPhi(mem[1], [mem[0], mem[9]]), Phi(x[3], [x[1], x[2]]), Assignment(x[1], z_aliased[1])])
    n3 = BasicBlock(3, [])
    n4 = BasicBlock(4, [])
    n5 = BasicBlock(5, [MemPhi(mem[4], [mem[2], mem[3]])])
    n6 = BasicBlock(6, [])
    n7 = BasicBlock(7, [])
    n8 = BasicBlock(8, [MemPhi(mem[6], [mem[4], mem[5]]), Assignment(x[5], z_aliased[4]), Assignment(x[0], y_aliased[6])])
    n9 = BasicBlock(9, [])
    n10 = BasicBlock(10, [])
    n11 = BasicBlock(11, [MemPhi(mem[9], [mem[7], mem[8]])])
    cfg.add_edges_from(
        [
            UnconditionalEdge(n1, n2),
            UnconditionalEdge(n2, n3),
            UnconditionalEdge(n2, n4),
            UnconditionalEdge(n3, n5),
            UnconditionalEdge(n4, n5),
            UnconditionalEdge(n5, n6),
            UnconditionalEdge(n5, n7),
            UnconditionalEdge(n6, n8),
            UnconditionalEdge(n7, n8),
            UnconditionalEdge(n8, n9),
            UnconditionalEdge(n8, n10),
            UnconditionalEdge(n9, n11),
            UnconditionalEdge(n10, n11),
            UnconditionalEdge(n11, n2),
        ]
    )

    res = ControlFlowGraph()
    n2 = BasicBlock(
        2,
        [
            Phi(z_aliased[1], [z_aliased[0], z_aliased[9]]),
            Phi(y_aliased[1], [y_aliased[0], y_aliased[9]]),
            Phi(x[3], [x[1], x[2]]),
            Assignment(x[1], z_aliased[1]),
        ],
    )
    n5 = BasicBlock(5, [Phi(z_aliased[4], [z_aliased[2], z_aliased[3]]), Phi(y_aliased[4], [y_aliased[2], y_aliased[3]])])
    n8 = BasicBlock(
        8,
        [
            Phi(z_aliased[6], [z_aliased[4], z_aliased[5]]),
            Phi(y_aliased[6], [y_aliased[4], y_aliased[5]]),
            Assignment(x[5], z_aliased[4]),
            Assignment(x[0], y_aliased[6]),
        ],
    )
    n11 = BasicBlock(11, [Phi(z_aliased[9], [z_aliased[7], z_aliased[8]]), Phi(y_aliased[9], [y_aliased[7], y_aliased[8]])])
    res.add_edges_from(
        [
            UnconditionalEdge(n1, n2),
            UnconditionalEdge(n2, n3),
            UnconditionalEdge(n2, n4),
            UnconditionalEdge(n3, n5),
            UnconditionalEdge(n4, n5),
            UnconditionalEdge(n5, n6),
            UnconditionalEdge(n5, n7),
            UnconditionalEdge(n6, n8),
            UnconditionalEdge(n7, n8),
            UnconditionalEdge(n8, n9),
            UnconditionalEdge(n8, n10),
            UnconditionalEdge(n9, n11),
            UnconditionalEdge(n10, n11),
            UnconditionalEdge(n11, n2),
        ]
    )

    return cfg, res


@fixture
def cfg_with_single_aliased_variable_4(x, z_aliased):
    """
    +-------------------------+             +-------------------+
    |       func(*z#1)        |             |    func(*z#1)     |
    +-------------------------+             +-------------------+
                |                                     |
                |                                     |
    +-------------------------+             +-------------------+
    | mem#2 = φ(mem#1, mem#3) |<--+         | z#2 = φ(z#1, z#3) |<--+
    | x#1 = x#0 + 1           |   |         | x#1 = x#0 + 1     |   |
    | if( z#2 <= x#1)         |   |         | if( z#2 <= x#1)   |   |
    +-------------------------+   |         +-------------------+   |
                |         |       |                    |    |       |
                |         +-------+                    |    +-------+
    +-------------------------+             +-------------------+
    |                         |             |                   |
    +-------------------------+             +-------------------+
    """
    cfg = ControlFlowGraph()
    mem0, mem1, mem2, mem3 = generate_mem_phi_variables(4)
    n0 = BasicBlock(
        0,
        [
            Assignment(ListOperation([]), Call(function_symbol("func"), [UnaryOperation(OperationType.dereference, [z_aliased[1]])])),
        ],
    )
    n1 = BasicBlock(
        1,
        [
            MemPhi(mem2, [mem1, mem3]),
            Assignment(x[1], BinaryOperation(OperationType.plus, [x[0], Constant(1)])),
            Branch(Condition(OperationType.less_or_equal, [z_aliased[2], x[1]])),
        ],
    )
    n2 = BasicBlock(2, [])
    cfg.add_edges_from([UnconditionalEdge(n0, n1), UnconditionalEdge(n1, n1), UnconditionalEdge(n1, n2)])

    expected_cfg = ControlFlowGraph()
    n1 = BasicBlock(
        1,
        [
            Phi(z_aliased[2], [z_aliased[1], z_aliased[3]]),
            Assignment(x[1], BinaryOperation(OperationType.plus, [x[0], Constant(1)])),
            Branch(Condition(OperationType.less_or_equal, [z_aliased[2], x[1]])),
        ],
    )
    expected_cfg.add_edges_from([UnconditionalEdge(n0, n1), UnconditionalEdge(n1, n1), UnconditionalEdge(n1, n2)])
    return cfg, expected_cfg


@fixture
def cfg_with_multiple_aliased_variables_3(x, z_aliased, y_aliased):
    """
    +-------------------------+             +-------------------+
    |     scanf(&z#0)         |--+          |  scanf(&z#0)      |--+
    |     scanf(&y#0)         |  |          |  scanf(&y#0)      |  |
    |     if( z#0 <= y#0)     |  |          |  if( z#0 <= y#0)  |  |
    +-------------------------+  |          +-------------------+  |
                |                |                    |            |
                |                |                    |            |
    +-------------------------+  |          +-------------------+  |
    |      scanf(&z#0)        |  |          |    scanf(&z#0)    |  |
    +-------------------------+  |          +-------------------+  |
                |                |                     |           |
                |                |                     |           |
    +-------------------------+  |          +-------------------+  |
    | mem#2 = φ(mem#0, mem#1) |<-+          | z#2 = φ(z#0, z#1) |<-+
    | x#0 = z#2 * y#2         |             | y#2 = φ(y#0, y#1) |
    +-------------------------+             | x#0 = z#2 * y#2   |
                                            +-------------------+

    """
    mem0, mem1, mem2 = generate_mem_phi_variables(3)
    cfg = ControlFlowGraph()
    n0 = BasicBlock(
        0,
        [
            Assignment(ListOperation([]), Call(ext_function_symbol("scanf"), [UnaryOperation(OperationType.address, [z_aliased[0]])])),
            Assignment(ListOperation([]), Call(ext_function_symbol("scanf"), [UnaryOperation(OperationType.address, [y_aliased[0]])])),
            Branch(Condition(OperationType.less_or_equal, [z_aliased[0], y_aliased[0]])),
        ],
    )
    n1 = BasicBlock(
        1,
        [
            Assignment(ListOperation([]), Call(ext_function_symbol("scanf"), [UnaryOperation(OperationType.address, [z_aliased[0]])])),
        ],
    )
    n2 = BasicBlock(
        2, [MemPhi(mem2, [mem0, mem1]), Assignment(x[0], BinaryOperation(OperationType.multiply, [z_aliased[2], y_aliased[2]]))]
    )
    cfg.add_edges_from([UnconditionalEdge(n0, n2), UnconditionalEdge(n0, n1), UnconditionalEdge(n1, n2)])
    expected_cfg = ControlFlowGraph()
    n2 = BasicBlock(
        2,
        [
            Phi(z_aliased[2], [z_aliased[0], z_aliased[1]]),
            Phi(y_aliased[2], [y_aliased[0], y_aliased[1]]),
            Assignment(x[0], BinaryOperation(OperationType.multiply, [z_aliased[2], y_aliased[2]])),
        ],
    )
    expected_cfg.add_edges_from([UnconditionalEdge(n0, n2), UnconditionalEdge(n0, n1), UnconditionalEdge(n1, n2)])
    return cfg, expected_cfg


@fixture
def cfg_with_single_aliased_variable_5(x, z_aliased):
    """
       +-------------------------+             +-------------------+
    +--|       scanf(&z#0)       |          +--|    scanf(&z#0)    |
    |  +-------------------------+          |  +-------------------+
    |              |                        |            |
    |              |                        |            |
    |  +-------------------------+          |  +-------------------+
    |  | mem#1 = φ(mem#0, mem#2) |<--+      |  | z#1 = φ(z#0, z#2) |<--+
    |  | scanf(&z#1)             |   |      |  | scanf(&z#1)       |   |
    |  | if( z#2 != x#0)         |   |      |  | if( z#2 != x#0)   |   |
    |  +-------------------------+   |      |  +-------------------+   |
    |                        |       |      |             |    |       |
    |                        +-------+      |             |    +-------+
    |  +-------------------------+          |  +-------------------+
    +->|                         |          +->|                   |
       +-------------------------+             +-------------------+
    """
    mem0, mem1, mem2 = generate_mem_phi_variables(3)
    cfg = ControlFlowGraph()
    n0 = BasicBlock(
        0, [Assignment(ListOperation([]), Call(ext_function_symbol("scanf"), [UnaryOperation(OperationType.address, [z_aliased[0]])]))]
    )
    n1 = BasicBlock(
        1,
        [
            MemPhi(mem1, [mem0, mem2]),
            Assignment(ListOperation([]), Call(ext_function_symbol("scanf"), [UnaryOperation(OperationType.address, [z_aliased[1]])])),
            Branch(Condition(OperationType.not_equal, [z_aliased[2], x[0]])),
        ],
    )
    n2 = BasicBlock(2, [])

    cfg.add_edges_from([UnconditionalEdge(n0, n1), UnconditionalEdge(n1, n1), UnconditionalEdge(n0, n2)])
    expected_cfg = ControlFlowGraph()
    n1 = BasicBlock(
        1,
        [
            Phi(z_aliased[1], [z_aliased[0], z_aliased[2]]),
            Assignment(ListOperation([]), Call(ext_function_symbol("scanf"), [UnaryOperation(OperationType.address, [z_aliased[1]])])),
            Branch(Condition(OperationType.not_equal, [z_aliased[2], x[0]])),
        ],
    )
    expected_cfg.add_edges_from([UnconditionalEdge(n0, n1), UnconditionalEdge(n1, n1), UnconditionalEdge(n0, n2)])
    return cfg, expected_cfg


@fixture
def cfg_with_multiple_aliased_variables_4(x, z_aliased, y_aliased):
    """
    +-------------------------+             +-------------------+
    |                         |             |                   |
    +-------------------------+             +-------------------+
                |                                     |
                |                           +-------------------+
    +-------------------------+             | z#1 = φ(z#0, z#2) |
    | mem#1 = φ(mem#0, mem#2) |<--+         | y#1 = φ(y#0, y#2) |<--+
    | *z#1 = x#0              |   |         | *z#1 = x#0        |   |
    | x#1 = *y#1              |   |         | x#1 = *y#1        |   |
    +-------------------------+   |         +-------------------+   |
                |         |       |                    |    |       |
                |         +-------+                    |    +-------+
    +-------------------------+             +-------------------+
    |                         |             |                   |
    +-------------------------+             +-------------------+
    """
    cfg = ControlFlowGraph()
    mem0, mem1, mem2 = generate_mem_phi_variables(3)
    n0 = BasicBlock(0, [])
    n1 = BasicBlock(
        1,
        [
            MemPhi(mem1, [mem0, mem2]),
            Assignment(UnaryOperation(OperationType.dereference, [z_aliased[1]]), x[0]),
            Assignment(x[1], UnaryOperation(OperationType.dereference, [y_aliased[1]])),
        ],
    )
    n2 = BasicBlock(2, [])
    cfg.add_edges_from(
        [
            UnconditionalEdge(n0, n1),
            UnconditionalEdge(n1, n2),
            UnconditionalEdge(n1, n1),
        ]
    )

    expected_cfg = ControlFlowGraph()
    n1 = BasicBlock(
        1,
        [
            Phi(z_aliased[1], [z_aliased[0], z_aliased[2]]),
            Phi(y_aliased[1], [y_aliased[0], y_aliased[2]]),
            Assignment(UnaryOperation(OperationType.dereference, [z_aliased[1]]), x[0]),
            Assignment(x[1], UnaryOperation(OperationType.dereference, [y_aliased[1]])),
        ],
    )

    expected_cfg.add_edges_from(
        [
            UnconditionalEdge(n0, n1),
            UnconditionalEdge(n1, n2),
            UnconditionalEdge(n1, n1),
        ]
    )
    return cfg, expected_cfg


@fixture
def no_mem_phi_target_in_use_only_arguments(x, z_aliased):
    """
    The arguments of mem phi are being used, targets are not. E.g. mem#4 is never used as it will be updated to mem#5 via call to print
    Still we want to have all mem phis in order to keep labels and definitions of aliased variables (e.g. z#5) correct.
          +-------------------------------------------+
      |                                           |
      |       +---------------------------+       |
      |       |            0.             |       |
      |       |          print()          |       |
      |       |   x#0 = &(z_aliased#1)    |       |
      |       |        scanf(x#0)         |       |
      |       | x#1 = (long) z_aliased#2  |       |
      |       +---------------------------+       |
      |         |                                 |
      |         |                                 |
      |         v                                 |
      |       +---------------------------+       |
      |       |            1.             |       |
      |       |     x#2 = ϕ(x#1,x#5)      |       |
      |       | mem#3 = ϕ(mem#2,mem#6) -> |       |
      |    +> |      if(x#2 <= 0x0)       | -+    |
      |    |  +---------------------------+  |    |
      |    |    |                            |    |
      |    |    |                            |    |
      |    |    v                            |    |
      |    |  +---------------------------+  |    |
      |    |  |            2.             |  |    |
      |    |  |     x#3 = ϕ(x#2,x#6)      |  |    |
      |    |  | mem#4 = ϕ(mem#3,mem#7) -> |  |    |
      |    |  |        print(x#3)         |  |    |
      |    |  | x#4 = (long) z_aliased#5  |  |    |
      |    |  |      x#5 = x#4 - 0x2      |  |    |
      |    |  |  z_aliased#6 = (int) x#5  |  |    |
      |    +- |  if((x#5 & 0x1) != 0x0)   | <+----+
      |       +---------------------------+  |
      |         |                            |
      |         |                            |
      |         v                            |
      |       +---------------------------+  |
      |       |            3.             |  |
      |       |      x#6 = x#5 - 0x1      |  |
      |       |  z_aliased#7 = (int) x#6  |  |
      +------ |       if(x#6 > 0x0)       |  |
              +---------------------------+  |
                |                            |
                |                            |
                v                            |
              +---------------------------+  |
              |            4.             |  |
              |     x#7 = ϕ(x#2,x#6)      |  |
              | mem#8 = ϕ(mem#3,mem#7) -> | <+
              +---------------------------+


        Out:
          +----------------------------------------------------------+
      |                                                          |
      |       +------------------------------------------+       |
      |       |                    0.                    |       |
      |       |                 print()                  |       |
      |       |           x#0 = &(z_aliased#1)           |       |
      |       |                scanf(x#0)                |       |
      |       |         x#1 = (long) z_aliased#2         |       |
      |       +------------------------------------------+       |
      |         |                                                |
      |         |                                                |
      |         v                                                |
      |       +------------------------------------------+       |
      |       |                    1.                    |       |
      |       |             x#2 = ϕ(x#1,x#5)             |       |
      |       | z_aliased#3 = ϕ(z_aliased#2,z_aliased#6) |       |
      |    +> |              if(x#2 <= 0x0)              | -+    |
      |    |  +------------------------------------------+  |    |
      |    |    |                                           |    |
      |    |    |                                           |    |
      |    |    v                                           |    |
      |    |  +------------------------------------------+  |    |
      |    |  |                    2.                    |  |    |
      |    |  |             x#3 = ϕ(x#2,x#6)             |  |    |
      |    |  | z_aliased#4 = ϕ(z_aliased#3,z_aliased#7) |  |    |
      |    |  |                print(x#3)                |  |    |
      |    |  |         x#4 = (long) z_aliased#5         |  |    |
      |    |  |             x#5 = x#4 - 0x2              |  |    |
      |    |  |         z_aliased#6 = (int) x#5          |  |    |
      |    +- |          if((x#5 & 0x1) != 0x0)          | <+----+
      |       +------------------------------------------+  |
      |         |                                           |
      |         |                                           |
      |         v                                           |
      |       +------------------------------------------+  |
      |       |                    3.                    |  |
      |       |             x#6 = x#5 - 0x1              |  |
      |       |         z_aliased#7 = (int) x#6          |  |
      +------ |              if(x#6 > 0x0)               |  |
              +------------------------------------------+  |
                |                                           |
                |                                           |
                v                                           |
              +------------------------------------------+  |
              |                    4.                    |  |
              |             x#7 = ϕ(x#2,x#6)             |  |
              | z_aliased#8 = ϕ(z_aliased#3,z_aliased#7) | <+
              +------------------------------------------+
    """
    cfg = ControlFlowGraph()
    mem = generate_mem_phi_variables(9)
    n0 = BasicBlock(
        0,
        [
            Assignment(ListOperation([]), Call(ext_function_symbol("print"), [], writes_memory=1)),
            Assignment(x[0], UnaryOperation(OperationType.address, [z_aliased[1]])),
            Assignment(ListOperation([]), Call(ext_function_symbol("scanf"), [x[0]], writes_memory=2)),
            Assignment(x[1], UnaryOperation(OperationType.cast, [z_aliased[2]], Integer.int64_t())),
        ],
    )
    n1 = BasicBlock(
        1, [Phi(x[2], [x[1], x[5]]), MemPhi(mem[3], [mem[2], mem[6]]), Branch(Condition(OperationType.less_or_equal, [x[2], Constant(0)]))]
    )
    n2 = BasicBlock(
        2,
        [
            Phi(x[3], [x[2], x[6]]),
            MemPhi(mem[4], [mem[3], mem[7]]),
            Assignment(ListOperation([]), Call(ext_function_symbol("print"), [x[3]], writes_memory=5)),
            Assignment(x[4], UnaryOperation(OperationType.cast, [z_aliased[5]], Integer.int64_t())),
            Assignment(x[5], BinaryOperation(OperationType.minus, [x[4], Constant(2)])),
            Assignment(z_aliased[6], UnaryOperation(OperationType.cast, [x[5]], Integer.int32_t())),
            Branch(Condition(OperationType.not_equal, [BinaryOperation(OperationType.bitwise_and, [x[5], Constant(1)]), Constant(0)])),
        ],
    )
    n3 = BasicBlock(
        3,
        [
            Assignment(x[6], BinaryOperation(OperationType.minus, [x[5], Constant(1)])),
            Assignment(z_aliased[7], UnaryOperation(OperationType.cast, [x[6]], Integer.int32_t())),
            Branch(Condition(OperationType.greater, [x[6], Constant(0)])),
        ],
    )
    n4 = BasicBlock(4, [Phi(x[7], [x[2], x[6]]), MemPhi(mem[8], [mem[3], mem[7]])])
    cfg.add_edges_from(
        [
            UnconditionalEdge(n0, n1),
            UnconditionalEdge(n1, n2),
            UnconditionalEdge(n2, n3),
            UnconditionalEdge(n3, n4),
            UnconditionalEdge(n1, n4),
            UnconditionalEdge(n2, n1),
            UnconditionalEdge(n3, n2),
        ]
    )

    expected_cfg = ControlFlowGraph()
    n1 = BasicBlock(
        1,
        [
            Phi(x[2], [x[1], x[5]]),
            Phi(z_aliased[3], [z_aliased[2], z_aliased[6]]),
            Branch(Condition(OperationType.less_or_equal, [x[2], Constant(0)])),
        ],
    )
    n2 = BasicBlock(
        2,
        [
            Phi(x[3], [x[2], x[6]]),
            Phi(z_aliased[4], [z_aliased[3], z_aliased[7]]),
            Assignment(ListOperation([]), Call(ext_function_symbol("print"), [x[3]], writes_memory=5)),
            Assignment(x[4], UnaryOperation(OperationType.cast, [z_aliased[5]], Integer.int64_t())),
            Assignment(x[5], BinaryOperation(OperationType.minus, [x[4], Constant(2)])),
            Assignment(z_aliased[6], UnaryOperation(OperationType.cast, [x[5]], Integer.int32_t())),
            Branch(Condition(OperationType.not_equal, [BinaryOperation(OperationType.bitwise_and, [x[5], Constant(1)]), Constant(0)])),
        ],
    )
    n4 = BasicBlock(4, [Phi(x[7], [x[2], x[6]]), Phi(z_aliased[8], [z_aliased[3], z_aliased[7]])])
    expected_cfg.add_edges_from(
        [
            UnconditionalEdge(n0, n1),
            UnconditionalEdge(n1, n2),
            UnconditionalEdge(n2, n3),
            UnconditionalEdge(n3, n4),
            UnconditionalEdge(n1, n4),
            UnconditionalEdge(n2, n1),
            UnconditionalEdge(n3, n2),
        ]
    )
    return cfg, expected_cfg


@fixture
def no_connection_between_aliased_variables_and_mem_phi_for_calls(x, z_aliased):
    """
    Here mem phi are not directly connected to aliased variables that depend on them
    because of the calls that change memory versions
            +----------------------------------------+
        |                   0.                   |
        |         printf("enter number")         |
        |          x#0 = &(z_aliased#1)          |
        |            scanf("%d", x#0)            |
        |        x#1 = z_aliased#2 + 0x1         |
        |               x#2 = x#1                |
        | printf("increase memory version to 3") |
        | printf("increase memory version to 4") |
        |             if(x#2 <= 0xa)             | -+
        +----------------------------------------+  |
          |                                         |
          |                                         |
          v                                         |
        +----------------------------------------+  |
        |                   1.                   |  |
        | printf("increase memory version to 5") |  |
        |        x#3 = z_aliased#5 + 0x1         |  |
        |           z_aliased#6 = x#3            |  |
        | printf("increase memory version to 7") |  |
        +----------------------------------------+  |
          |                                         |
          |                                         |
          v                                         |
        +----------------------------------------+  |
        |                   2.                   |  |
        |            x#4 = ϕ(x#3,x#2)            |  |
        |       mem#8 = ϕ(mem#7,mem#4) ->        |  |
        | printf("increase memory version to 9") |  |
        |           x#5 = z_aliased#9            |  |
        |   printf("your number is: %d", x#5)    | <+
        +----------------------------------------+

        Out:

        +------------------------------------------+
        |                    0.                    |
        |          printf("enter number")          |
        |           x#0 = &(z_aliased#1)           |
        |             scanf("%d", x#0)             |
        |         x#1 = z_aliased#2 + 0x1          |
        |                x#2 = x#1                 |
        |  printf("increase memory version to 3")  |
        |  printf("increase memory version to 4")  |
        |              if(x#2 <= 0xa)              | -+
        +------------------------------------------+  |
          |                                           |
          |                                           |
          v                                           |
        +------------------------------------------+  |
        |                    1.                    |  |
        |  printf("increase memory version to 5")  |  |
        |         x#3 = z_aliased#5 + 0x1          |  |
        |            z_aliased#6 = x#3             |  |
        |  printf("increase memory version to 7")  |  |
        +------------------------------------------+  |
          |                                           |
          |                                           |
          v                                           |
        +------------------------------------------+  |
        |                    2.                    |  |
        |             x#4 = ϕ(x#3,x#2)             |  |
        | z_aliased#8 = ϕ(z_aliased#7,z_aliased#4) |  |
        |  printf("increase memory version to 9")  |  |
        |            x#5 = z_aliased#9             |  |
        |    printf("your number is: %d", x#5)     | <+
        +------------------------------------------+
    """
    cfg = ControlFlowGraph()
    mem = generate_mem_phi_variables(9)
    n0 = BasicBlock(
        0,
        [
            Assignment(ListOperation([]), Call(ext_function_symbol("printf"), [Constant("enter number")], writes_memory=1)),
            Assignment(x[0], UnaryOperation(OperationType.address, [z_aliased[1]])),
            Assignment(ListOperation([]), Call(ext_function_symbol("scanf"), [Constant("%d"), x[0]], writes_memory=2)),
            Assignment(x[1], BinaryOperation(OperationType.plus, [z_aliased[2], Constant(1)])),
            Assignment(x[2], x[1]),
            Assignment(ListOperation([]), Call(ext_function_symbol("printf"), [Constant("increase memory version to 3")], writes_memory=3)),
            Assignment(ListOperation([]), Call(ext_function_symbol("printf"), [Constant("increase memory version to 4")], writes_memory=4)),
            Branch(Condition(OperationType.less_or_equal, [x[2], Constant(10)])),
        ],
    )
    n1 = BasicBlock(
        1,
        [
            Assignment(ListOperation([]), Call(ext_function_symbol("printf"), [Constant("increase memory version to 5")], writes_memory=5)),
            Assignment(x[3], BinaryOperation(OperationType.plus, [z_aliased[5], Constant(1)])),
            Assignment(z_aliased[6], x[3]),
            Assignment(ListOperation([]), Call(ext_function_symbol("printf"), [Constant("increase memory version to 7")], writes_memory=7)),
        ],
    )
    n2 = BasicBlock(
        2,
        [
            Phi(x[4], [x[3], x[2]]),
            MemPhi(mem[8], [mem[7], mem[4]]),
            Assignment(ListOperation([]), Call(ext_function_symbol("printf"), [Constant("increase memory version to 9")], writes_memory=9)),
            Assignment(x[5], z_aliased[9]),
            Assignment(ListOperation([]), Call(ext_function_symbol("printf"), [Constant("your number is: %d"), x[5]], writes_memory=10)),
        ],
    )
    cfg.add_edges_from([UnconditionalEdge(n0, n1), UnconditionalEdge(n0, n2), UnconditionalEdge(n1, n2)])
    expected_cfg = ControlFlowGraph()
    n2 = BasicBlock(
        2,
        [
            Phi(x[4], [x[3], x[2]]),
            Phi(z_aliased[8], [z_aliased[7], z_aliased[4]]),
            Assignment(ListOperation([]), Call(ext_function_symbol("printf"), [Constant("increase memory version to 9")], writes_memory=9)),
            Assignment(x[5], z_aliased[9]),
            Assignment(ListOperation([]), Call(ext_function_symbol("printf"), [Constant("your number is: %d"), x[5]], writes_memory=10)),
        ],
    )
    expected_cfg.add_edges_from([UnconditionalEdge(n0, n1), UnconditionalEdge(n0, n2), UnconditionalEdge(n1, n2)])
    return cfg, expected_cfg


@fixture
def cfg_with_single_global_variable(x) -> Tuple[ControlFlowGraph, ControlFlowGraph]:
    """
          +-------------+                        +-------------+
          |  x#0 = x#1  |                        | x#0 = x#1 |
          +------+------+                        +------+------+
                 |                                      |
    +------------+------------+              +----------+----------+
    | mem#1 = φ(mem#0, mem#3) |<--+          |  g#1 = φ(g#0, g#3)  |<----+
    | x#2  = g#1              |   |          |  x#2 = g#1          |     |
    +-------------------------+   |          +----------+----------+     |
                 |                |                     |                |
         +-------+-------+        |             +-------+-------+        |
         |               |        |             |               |        |
    +----+----+     +----+----+   |        +----+----+     +----+----+   |
    |         |     |         |   |   ->   |         »     |         |   |
    +----+----+     +----+----+   |        +----+----+     +----+----+   |
         |               |        |             |               |        |
         +-------+-------+        |             +-------+-------+        |
                 |                |                     |                |
    +------------+------------+   |        +------------+------------+   |
    | mem#3 = φ(mem#1, mem#2) |---+        |   g#3 = φ(g#1, g#2)     |---+
    +-------------------------+            +-------------------------+
    """
    cfg = ControlFlowGraph()
    mem0, mem1, mem2, mem3 = generate_mem_phi_variables(4)
    g = [GlobalVariable("g", Integer.char(), i, initial_value=42) for i in range(4)]
    n1 = BasicBlock(1, [Assignment(x[0], x[1])])
    n2 = BasicBlock(2, [MemPhi(mem1, [mem0, mem3]), Assignment(x[2], g[1])])
    n3 = BasicBlock(3, [])
    n4 = BasicBlock(4, [])
    n5 = BasicBlock(5, [MemPhi(mem3, [mem1, mem2])])
    cfg.add_edges_from(
        [
            UnconditionalEdge(n1, n2),
            UnconditionalEdge(n2, n3),
            UnconditionalEdge(n2, n4),
            UnconditionalEdge(n3, n5),
            UnconditionalEdge(n4, n5),
            UnconditionalEdge(n5, n2),
        ]
    )

    expected_cfg = ControlFlowGraph()
    n2 = BasicBlock(2, [Phi(g[1], [g[0], g[3]]), Assignment(x[2], g[1])])
    n5 = BasicBlock(5, [Phi(g[3], [g[1], g[2]])])
    expected_cfg.add_edges_from(
        [
            UnconditionalEdge(n1, n2),
            UnconditionalEdge(n2, n3),
            UnconditionalEdge(n2, n4),
            UnconditionalEdge(n3, n5),
            UnconditionalEdge(n4, n5),
            UnconditionalEdge(n5, n2),
        ]
    )
    return cfg, expected_cfg


def _test_mem_phi_converter(input_cfg: ControlFlowGraph, expected_output_cfg: ControlFlowGraph):
    task = DecompilerTask("test", input_cfg)
    MemPhiConverter().run(task)
    assert _equal(input_cfg, expected_output_cfg)


def _equal(cfg1: ControlFlowGraph, cfg2: ControlFlowGraph) -> bool:
    # we don't care and don't control ordering of phi functions
    # as they are assumed to be executed in parallel
    return all((set(x.instructions) == set(y.instructions) for x, y in zip(cfg1.nodes, cfg2.nodes)))


def generate_mem_phi_variables(number):
    return tuple(Variable(f"mem", UnknownType(), i) for i in range(number))


@fixture
def mem_phis():
    return tuple(Variable(f"mem", UnknownType(), i) for i in range(1, 7))


@fixture
def x():
    return tuple(Variable("x", Integer(32), i) for i in range(20))


@fixture
def y_aliased():
    return tuple(Variable("y_aliased", Integer(32), i, is_aliased=True) for i in range(12))


@fixture
def z_aliased():
    return tuple(Variable("z_aliased", Integer(32), i, is_aliased=True) for i in range(12))
