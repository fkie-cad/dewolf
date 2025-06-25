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

def test_sreedhar_Step2():
    pass

def test_sreedhar_Step3():
    pass

if __name__ == "__main__":
    test_sreedhar_Step1_Swap()
    test_sreedhar_Step2()
    test_sreedhar_Step3()
