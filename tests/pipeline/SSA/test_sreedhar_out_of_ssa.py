from typing import List
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
    ig = InterferenceGraph(cfg)

    soossa = SreedharOutOfSsa(decompTask,ig,None)
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

def test_sreedhar_Step2_Case3_Step3():
    '''
                  +----------------------+
                  |          1.          |
                  |      x#1 = 0x1       |
                  |      y#1 = 0x2       |
                  +----------------------+
                    |
                    |
                    v
+-----------+     +----------------------+
|           |     |          4.          |
|           |     | x#4 = ϕ(x#1,x#2,x#3) |
|           |     | y#4 = ϕ(y#1,y#2,y#3) |
|    2.     |     |     x#6 = 0x7e9      |
| x#2 = 0x3 |     |      x#5 = x#4       |
| y#2 = 0x4 |     |      y#5 = y#4       |
|           |     |   x#6 = x#6 + 0x1    |
|           |     |      x#5 = x#6       |
|           |     |      x#4 = y#4       |
|           | --> |   x#5 = x#5 + y#5    |
+-----------+     +----------------------+
                    ^
                    |
                    |
                  +----------------------+
                  |          3.          |
                  |      x#3 = 0x5       |
                  |      y#3 = 0x6       |
                  +----------------------+
    '''
    y_1 = Variable("y",vartype=Integer.int32_t(),ssa_label="1")
    y_2 = Variable("y",vartype=Integer.int32_t(),ssa_label="2")
    y_3 = Variable("y",vartype=Integer.int32_t(),ssa_label="3")
    y_4 = Variable("y",vartype=Integer.int32_t(),ssa_label="4")
    y_5 = Variable("y",vartype=Integer.int32_t(),ssa_label="5")
    x_1 = Variable("x",vartype=Integer.int32_t(),ssa_label="1")
    x_2 = Variable("x",vartype=Integer.int32_t(),ssa_label="2")
    x_3 = Variable("x",vartype=Integer.int32_t(),ssa_label="3")
    x_4 = Variable("x",vartype=Integer.int32_t(),ssa_label="4")
    x_5 = Variable("x",vartype=Integer.int32_t(),ssa_label="5")
    x_6 = Variable("x",vartype=Integer.int32_t(),ssa_label="6")

    px = Phi(x_4,[x_1,x_2,x_3])
    py = Phi(y_4,[y_1,y_2,y_3])

    bb = [BasicBlock(1),BasicBlock(2),BasicBlock(3),BasicBlock(4)]

    px.update_phi_function({bb[0]: x_1, bb[1]: x_2,bb[2]:x_3})
    py.update_phi_function({bb[0]: y_1, bb[1]: y_2,bb[2]:y_3})

    bb[0].instructions = [
            Assignment(x_1,Constant(1)),
            Assignment(y_1,Constant(2)),
    ]
    bb[1].instructions = [
            Assignment(x_2,Constant(3)),
            Assignment(y_2,Constant(4)),
    ]
    bb[2].instructions = [
            Assignment(x_3,Constant(5)),
            Assignment(y_3,Constant(6)),
    ]
    bb[3].instructions = [
            px,
            py,
            Assignment(x_6,Constant(2025)),
            Assignment(x_5,x_4),
            Assignment(y_5,y_4),
            Assignment(x_6,BinaryOperation(OperationType.plus,[x_6,Constant(1)])),
            Assignment(x_5,x_6),
            Assignment(x_4,y_4),
            Assignment(x_5,BinaryOperation(OperationType.plus,[x_5,y_5])),
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
    ig = InterferenceGraph(cfg)

    soossa = SreedharOutOfSsa(decompTask,ig,None)
    soossa._phi_congruence_class[x_4] = set([x_4,x_1,x_2,x_3])
    soossa._phi_congruence_class[x_1] = x_4
    soossa._phi_congruence_class[x_2] = x_4
    soossa._phi_congruence_class[x_3] = x_4
    soossa._phi_congruence_class[y_4] = set([y_4,y_1,y_2,y_3])
    soossa._phi_congruence_class[y_1] = y_4
    soossa._phi_congruence_class[y_2] = y_4
    soossa._phi_congruence_class[y_3] = y_4
    soossa._remove_unnecessary_copies()

    assert(
            len(bb[3].instructions) == 7 and
            px in bb[3].instructions and
            py in bb[3].instructions and 
            Assignment(x_6,Constant(2025)) in bb[3].instructions and 
            Assignment(x_5,x_4) not in bb[3].instructions and 
            Assignment(y_5,y_4) not in bb[3].instructions and 
            Assignment(x_6,BinaryOperation(OperationType.plus,[x_6,Constant(1)])) in bb[3].instructions and 
            Assignment(x_5,x_6) in bb[3].instructions and 
            Assignment(x_4,y_4) in bb[3].instructions and 
            Assignment(x_5,BinaryOperation(OperationType.plus,[x_5,y_5])) in bb[3].instructions
    )
    soossa._leave_CSSA()
    asciicfg = DecoratedCFG.get_ascii(cfg)

    assert(
            "x_1" not in asciicfg and
            "x_2" not in asciicfg and
            "x_3" not in asciicfg and
            "x_4" not in asciicfg and
            "x_5" not in asciicfg and
            "x_6" not in asciicfg and
            "y_1" not in asciicfg and
            "y_2" not in asciicfg and
            "y_3" not in asciicfg and
            "y_4" not in asciicfg and
            "y_5" not in asciicfg and
            asciicfg.count("var_1") == 7 and
            asciicfg.count("var_2") == 5 and 
            asciicfg.count("var_3") == 4
    )