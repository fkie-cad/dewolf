from typing import List
from copy import deepcopy
from decompiler.pipeline.commons.livenessanalysis import LivenessAnalysis
from decompiler.pipeline.ssa.sreedhar_out_of_ssa import SreedharOutOfSsa
from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.graphs.branches import UnconditionalEdge, TrueCase, FalseCase
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo.expressions import Constant, Variable
from decompiler.structures.pseudo.instructions import Assignment, Instruction, Phi,Branch,Condition,OperationType,Return
from decompiler.structures.pseudo.typing import Integer
from decompiler.task import DecompilerTask
from decompiler.util.decoration import DecoratedCFG, DecoratedGraph
from decompiler.structures.pseudo.operations import BinaryOperation, OperationType
from tests.pipeline.SSA.test_out_of_ssa import run_out_of_ssa
from decompiler.pipeline.ssa.outofssatranslation import SSAOptions
from tests.pipeline.SSA.utils_out_of_ssa_tests import *

def test_sreedhar_Step1_Swap():
    ''' +---------------+
        |      0.       |
        |   x1 = 0x1    |
        |   y1 = 0x2    |
        +---------------+
        |
        |
        v
        +---------------+
        |      1.       |
        | x2 = ϕ(x1,y2) | ---+
        | y2 = ϕ(y1,x2) |    |
        |  if(x2 > y2)  | <--+
        +---------------+
        |
        |
        v
        +---------------+
        |      2.       |
        |    return     |
        +---------------+
        '''
    x_1 = Variable("x",vartype=Integer.int32_t(),ssa_label="1")
    y_1 = Variable("y",vartype=Integer.int32_t(),ssa_label="1")
    x_2 = Variable("x",vartype=Integer.int32_t(),ssa_label="2")
    y_2 = Variable("y", vartype=Integer.int32_t(),ssa_label="2")

    px = Phi(x_2,[x_1,y_2])
    py = Phi(y_2,[y_1,x_2])

    bb = [BasicBlock(1),BasicBlock(2),BasicBlock(3)]

    px.update_phi_function({bb[0]: x_1, bb[1]: y_2})
    py.update_phi_function({bb[0]: y_1, bb[1]: x_2})
    
    bb[0].instructions = [
            Assignment(x_1,Constant(1)),
            Assignment(y_1,Constant(2))
    ]
    bb[1].instructions = [
            px,
            py,
            Branch(Condition(OperationType.greater,[x_2,y_2]))
    ]
    bb[2].instructions = [
            Return(Constant(1))
    ]

    cfg = ControlFlowGraph()
    cfg.add_node(bb[0])
    cfg.add_node(bb[1])
    cfg.add_node(bb[2])
    cfg.add_edge(UnconditionalEdge(bb[0],bb[1]))
    cfg.add_edge(TrueCase(bb[1],bb[2]))
    cfg.add_edge(FalseCase(bb[1],bb[1]))
    
    decompTask = DecompilerTask("test_task",None)
    decompTask.cfg = cfg

    soossa = SreedharOutOfSsa(decompTask)
    soossa._eliminate_phi_resource_interference()

    bb1 = cfg.nodes[1].instructions
    assert(
            len(cfg.nodes[0].instructions) == 2 and
            len(cfg.nodes[1].instructions) == 6 and
            len(cfg.nodes[2].instructions) == 1 and
            type (bb1[0]) == type(bb1[1]) == Phi and
            type(bb1[5]) == Branch
    )
    assert(
            bb1[0].destination == bb1[3].value and
            bb1[0].value[0] == x_1 and
            bb1[0].value[1] == bb1[4].destination and
            bb1[1].destination == bb1[2].value and
            bb1[1].value[0] == y_1 and
            bb1[1].value[1] == x_2 and
            bb1[2].destination == y_2 and
            bb1[3].destination == x_2 and
            bb1[4].value == y_2
    )

def test_sreedhar_Step2_Case1_2():
    '''
                  +----------------------+
                  |          1.          |
                  |      x#1 = 0x4       |
                  +----------------------+
                    |
                    |
                    v
+-----------+     +----------------------+
|           |     |          4.          |
|           |     | x#4 = ϕ(x#1,x#2,x#3) |
|           |     |      x#6 = 0x5       |
|           |     |      x#7 = 0xf       |
|    2.     |     |      x#5 = y#1       |
| x#2 = 0x5 |     |   x#5 = x#5 + 0x1    |
| y#1 = 0x8 |     |   x#7 = x#7 + 0x1    |
|           |     |   x#6 = x#6 + 0x1    |
|           |     |      x#6 = x#4       |
|           |     |      x#7 = x#4       |
|           | --> |   x#7 = x#7 + 0x1    |
+-----------+     +----------------------+
                    ^
                    |
                    |
                  +----------------------+
                  |          3.          |
                  |      x#3 = 0x8       |
                  +----------------------+
                  '''
    
    y_1 = Variable("y",vartype=Integer.int32_t(),ssa_label="1")
    x_1 = Variable("x",vartype=Integer.int32_t(),ssa_label="1")
    x_2 = Variable("x",vartype=Integer.int32_t(),ssa_label="2")
    x_3 = Variable("x",vartype=Integer.int32_t(),ssa_label="3")
    x_4 = Variable("x",vartype=Integer.int32_t(),ssa_label="4")
    x_5 = Variable("x",vartype=Integer.int32_t(),ssa_label="5")
    x_6 = Variable("x",vartype=Integer.int32_t(),ssa_label="6")
    x_7 = Variable("x",vartype=Integer.int32_t(),ssa_label="7")

    px = Phi(x_4,[x_1,x_2,x_3])

    bb = [BasicBlock(1),BasicBlock(2),BasicBlock(3),BasicBlock(4)]

    px.update_phi_function({bb[0]: x_1, bb[1]: x_2,bb[2]:x_3})

    bb[0].instructions = [
            Assignment(x_1,Constant(4)),
    ]
    bb[1].instructions = [
            Assignment(x_2,Constant(5)),
            Assignment(y_1,Constant(8)),
    ]
    bb[2].instructions = [
            Assignment(x_3,Constant(8)),
    ]
    bb[3].instructions = [
            px,
            Assignment(x_6,Constant(5)),
            Assignment(x_7,Constant(15)),
            Assignment(x_5,y_1),
            Assignment(x_5,BinaryOperation(OperationType.plus,[x_5,Constant(1)])),
            Assignment(x_7,BinaryOperation(OperationType.plus,[x_7,Constant(1)])),
            Assignment(x_6,BinaryOperation(OperationType.plus,[x_6,Constant(1)])),
            Assignment(x_6,x_4),
            Assignment(x_7,x_4),
            Assignment(x_7,BinaryOperation(OperationType.plus,[x_7,Constant(1)])),
    ]

    cfg = ControlFlowGraph()
    cfg.add_node(bb[0])
    cfg.add_node(bb[1])
    cfg.add_node(bb[2])
    cfg.add_node(bb[3])
    cfg.add_edge(UnconditionalEdge(bb[0],bb[3]))
    cfg.add_edge(UnconditionalEdge(bb[1],bb[3]))
    cfg.add_edge(UnconditionalEdge(bb[2],bb[3]))

    decompTask = DecompilerTask("test_task",None)
    decompTask.cfg = cfg

    soossa = SreedharOutOfSsa(decompTask)
    soossa._phi_congruence_class[x_4] = set([x_4,x_1,x_2,x_3])
    soossa._phi_congruence_class[x_1] = x_4
    soossa._phi_congruence_class[x_2] = x_4
    soossa._phi_congruence_class[x_3] = x_4
    soossa._remove_unnecessary_copies()

    assert(
            len(bb[3].instructions) == 8 and
            px in bb[3].instructions and
            Assignment(x_6,Constant(5)) in bb[3].instructions and
            Assignment(x_7,Constant(15)) in bb[3].instructions and
            Assignment(x_5,y_1) not in bb[3].instructions and #Removed due to Case 1
            Assignment(x_5,BinaryOperation(OperationType.plus,[x_5,Constant(1)])) in bb[3].instructions and
            Assignment(x_7,BinaryOperation(OperationType.plus,[x_7,Constant(1)])) in bb[3].instructions and
            Assignment(x_6,BinaryOperation(OperationType.plus,[x_6,Constant(1)])) in bb[3].instructions and
            Assignment(x_6,x_4) not in bb[3].instructions and
            Assignment(x_7,x_4) in bb[3].instructions and
            Assignment(x_7,BinaryOperation(OperationType.plus,[x_7,Constant(1)])) in bb[3].instructions
    )


def test_no_dependency_unconditional_edge_sreedhar(graph_no_dependency, variable_x, variable_x_new):
    '''Here we test whether Phi-functions, without dependency and where one ingoing edge is not unconditional, are lifted correctly.
        +------------------------+
        |           0.           |
        |   printf(0x804b00c)    |
        +------------------------+
        |
        |
        v
        +------------------------+
        |           1.           |
        |    x#3 = ϕ(x#2,x#4)    |
        |    v#2 = ϕ(v#1,v#3)    |
        |    u#2 = ϕ(u#1,u#3)    |
        |    y#4 = ϕ(y#3,y#5)    |
        |       u#3 = y#4        |
        |     if(v#2 <= u#3)     |
        +------------------------+
        ^
        |
        |
        +------------------------+
        |           2.           |
        |       x#4 = v#2        |
        | printf(0x804b045, x#4) |
        |     if(x#4 == 0x5)     |
        +------------------------+
    '''
    nodes, instructions, cfg = graph_no_dependency
    cfg.substitute_edge(cfg.get_edge(nodes[2], nodes[1]), TrueCase(nodes[2], nodes[1]))
    nodes[2].instructions.append(Branch(Condition(OperationType.equal, [variable_x[4], Constant(5)])))
    
    run_out_of_ssa(cfg, SSAOptions.sreedhar)
    cfgascii = DecoratedCFG.get_ascii(cfg)
    
    assert(
                len(cfg.nodes[0].instructions) == 1 and
                len(cfg.nodes[1].instructions) == 3 and
                len(cfg.nodes[2].instructions) == 2 and
                cfgascii.count("var_1") == 4 and
                cfgascii.count("var_2") == 2 and
                cfgascii.count("var_3") == 1 and
                cfgascii.count("var_4") == 1 and
                cfgascii.count("var_1 = var_4") == 1 and
                cfgascii.count("var_2 = var_3") == 1                
    )

def test_no_dependency_phi_target_value_same_sreedhar(graph_no_dependency,variable_v):
    """Here we test whether we do not insert the definition when the Phi-function target is the same as a Phi-function value.
        +------------------------+
        |           0.           |
        |   printf(0x804b00c)    |
        +------------------------+
          |
          |
          v
        +------------------------+
        |           1.           |
        |    x#3 = ϕ(x#2,x#4)    |
        |    v#2 = ϕ(v#1,v#2)    |
        |    u#2 = ϕ(u#1,u#3)    |
        |    y#4 = ϕ(y#3,y#5)    |
        |       u#3 = y#4        |
        |     if(v#2 <= u#3)     |
        +------------------------+
          ^
          |
          |
        +------------------------+
        |           2.           |
        |       x#4 = v#2        |
        | printf(0x804b045, x#4) |
        +------------------------+
    """
    nodes, instructions, cfg = graph_no_dependency
    nodes[1].instructions[1].substitute(variable_v[3], variable_v[2])
        
    run_out_of_ssa(cfg, SSAOptions.sreedhar)

    cfgascii = DecoratedCFG.get_ascii(cfg)

    assert(
        len(cfg.nodes[0].instructions) == 1 and
        len(cfg.nodes[1].instructions) == 2 and
        len(cfg.nodes[2].instructions) == 2 and
        cfgascii.count("var_1") == 2 and
        cfgascii.count("var_2") == 2 and
        cfgascii.count("var_3") == 2 and
        cfgascii.count("var_4") == 1 and
        cfgascii.count("var_3 = var_4") == 1 and
        cfgascii.count("var_1 = var_2") == 1
    )

def test_dependency_but_no_circle_some_same_values_sreedhar(graph_dependency_but_not_circular, aliased_variable_y, variable_u):
    """Here we test whether Phi-functions, with dependency, but no circular dependency and where one ingoing edge is not unconditional,
    are lifted correctly.
                                       +--------------------------+
                                       |            0.            |
                                       |    printf(0x804a00c)     |
                                       | scanf(0x804a025, &(y#1)) |
                                       |  printf(0x804a028, y#1)  |
                                       +--------------------------+
                                         |
                                         |
                                         v
        +------------------------+     +------------------------------------+
        |           2.           |     |                 1.                 |
        | printf(0x804a049, u#3) |     |        u#3 = ϕ(y#1,y#4,y#4)        |
        |       return 0x0       |     |        y#4 = ϕ(y#1,y#7,v#4)        |
        |                        | <-- |           if(y#4 <= 0x0)           |
        +------------------------+     +------------------------------------+
                                         |                           ^    ^
                                         |                           |    |
                                         v                           |    |
                                       +--------------------------+  |    |
                                       |            3.            |  |    |
                                       |  printf(0x804a045, y#4)  |  |    |
                                       |     y#7 = y#4 - 0x2      |  |    |
                                       |    v#2 = is_odd(y#7)     |  |    |
                                       | if((v#2 & 0xff) == 0x0)  | -+    |
                                       +--------------------------+       |
                                         |                                |
                                         |                                |
                                         v                                |
                                       +--------------------------+       |
                                       |            4.            |       |
                                       |     v#4 = y#7 - 0x1      | ------+
                                       +--------------------------+
    """

    nodes, instructions, cfg = graph_dependency_but_not_circular
    new_phi = Phi(variable_u[3], [aliased_variable_y[1], aliased_variable_y[4], aliased_variable_y[4]])
    new_phi._origin_block = {nodes[0]: aliased_variable_y[1], nodes[3]: aliased_variable_y[4], nodes[4]: aliased_variable_y[4]}
    nodes[1].instructions[0] = new_phi

    run_out_of_ssa(cfg, SSAOptions.sreedhar)

    asciicfg = DecoratedCFG.get_ascii(cfg)

    assert(
                len(cfg.nodes[0].instructions) == 4 and
                len(cfg.nodes[1].instructions) == 2 and
                len(cfg.nodes[2].instructions) == 2 and
                len(cfg.nodes[3].instructions) == 5 and
                len(cfg.nodes[4].instructions) == 2
    )
    assert(
                asciicfg.count("var_1") == 6 and
                asciicfg.count("var_2") == 6 and
                asciicfg.count("var_3") == 6 and
                asciicfg.count("var_4") == 2 and
                asciicfg.count("var_1 = var_3") == 2 and
                asciicfg.count("var_3 = var_2") == 1
    )
    