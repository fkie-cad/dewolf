"""Module implementing tests for the ClassifiedGraph class."""

from decompiler.structures.graphs.basic import BasicEdge, BasicNode
from decompiler.structures.graphs.classifiedgraph import ClassifiedGraph, EdgeProperty

v = [BasicNode(i) for i in range(6)]


class TestEdgeClassification:
    def test1(self):
        DG = ClassifiedGraph()
        DG.add_edge(BasicEdge(v[0], v[1]))
        DG.add_edge(BasicEdge(v[0], v[3]))
        DG.add_edge(BasicEdge(v[1], v[2]))
        DG.add_edge(BasicEdge(v[2], v[0]))
        DG.add_edge(BasicEdge(v[1], v[3]))
        DG.add_edge(BasicEdge(v[3], v[4]))
        DG.add_edge(BasicEdge(v[2], v[4]))

        edge_properties = DG.classify_edges()
        assert edge_properties == {
            DG.get_edge(v[0], v[1]): EdgeProperty.tree,
            DG.get_edge(v[0], v[3]): EdgeProperty.forward,
            DG.get_edge(v[1], v[2]): EdgeProperty.tree,
            DG.get_edge(v[1], v[3]): EdgeProperty.tree,
            DG.get_edge(v[2], v[0]): EdgeProperty.back,
            DG.get_edge(v[2], v[4]): EdgeProperty.tree,
            DG.get_edge(v[3], v[4]): EdgeProperty.cross,
        }

    def test2(self):
        DG = ClassifiedGraph()
        DG.add_edge(BasicEdge(v[0], v[1]))
        DG.add_edge(BasicEdge(v[1], v[3]))
        DG.add_edge(BasicEdge(v[2], v[4]))
        DG.add_edge(BasicEdge(v[0], v[2]))
        DG.add_edge(BasicEdge(v[2], v[3]))
        DG.add_edge(BasicEdge(v[3], v[4]))
        DG.add_edge(BasicEdge(v[4], v[2]))

        edge_properties = DG.classify_edges()
        assert edge_properties == {
            DG.get_edge(v[0], v[1]): EdgeProperty.tree,
            DG.get_edge(v[0], v[2]): EdgeProperty.forward,
            DG.get_edge(v[1], v[3]): EdgeProperty.tree,
            DG.get_edge(v[2], v[3]): EdgeProperty.retreating,
            DG.get_edge(v[2], v[4]): EdgeProperty.retreating,
            DG.get_edge(v[3], v[4]): EdgeProperty.tree,
            DG.get_edge(v[4], v[2]): EdgeProperty.tree,
        }

    def test3(self):
        DG = ClassifiedGraph()
        DG.add_edge(BasicEdge(v[0], v[1]))
        DG.add_edge(BasicEdge(v[0], v[4]))
        DG.add_edge(BasicEdge(v[1], v[3]))
        DG.add_edge(BasicEdge(v[1], v[2]))
        DG.add_edge(BasicEdge(v[2], v[1]))
        DG.add_edge(BasicEdge(v[3], v[4]))
        DG.add_edge(BasicEdge(v[4], v[1]))

        edge_properties = DG.classify_edges()
        assert edge_properties == {
            DG.get_edge(v[0], v[1]): EdgeProperty.tree,
            DG.get_edge(v[0], v[4]): EdgeProperty.forward,
            DG.get_edge(v[1], v[2]): EdgeProperty.tree,
            DG.get_edge(v[1], v[3]): EdgeProperty.tree,
            DG.get_edge(v[2], v[1]): EdgeProperty.back,
            DG.get_edge(v[3], v[4]): EdgeProperty.tree,
            DG.get_edge(v[4], v[1]): EdgeProperty.retreating,
        }


def test_back_edges():
    DG = ClassifiedGraph()
    DG.add_edge(BasicEdge(v[0], v[1]))
    DG.add_edge(BasicEdge(v[0], v[3]))
    DG.add_edge(BasicEdge(v[1], v[2]))
    DG.add_edge(BasicEdge(v[2], v[0]))
    DG.add_edge(BasicEdge(v[1], v[3]))
    DG.add_edge(BasicEdge(v[3], v[4]))
    DG.add_edge(BasicEdge(v[2], v[4]))

    assert DG.back_edges() == {v[0]: {DG.get_edge(v[2], v[0])}}

    DG.add_edge(BasicEdge(v[3], v[0]))

    assert DG.back_edges() == {v[0]: {DG.get_edge(v[2], v[0]), DG.get_edge(v[3], v[0])}}

    DG.add_edge(BasicEdge(v[4], v[5]))
    DG.add_edge(BasicEdge(v[5], v[4]))
    assert DG.back_edges() == {v[0]: {DG.get_edge(v[2], v[0]), DG.get_edge(v[3], v[0])}, v[4]: {DG.get_edge(v[5], v[4])}}

    DG.add_edge(BasicEdge(v[4], v[1]))
    assert DG.back_edges() == {v[0]: {DG.get_edge(v[2], v[0]), DG.get_edge(v[3], v[0])}, v[4]: {DG.get_edge(v[5], v[4])}}

    DG.add_edge(BasicEdge(v[2], v[5]))
    assert DG.back_edges() == {v[0]: {DG.get_edge(v[2], v[0]), DG.get_edge(v[3], v[0])}}


def test_retreating_edges():
    DG = ClassifiedGraph()
    v = [BasicNode(i) for i in range(5)]
    DG.add_edge(BasicEdge(v[0], v[1]))
    DG.add_edge(BasicEdge(v[1], v[3]))
    DG.add_edge(BasicEdge(v[2], v[4]))
    DG.add_edge(BasicEdge(v[0], v[2]))
    DG.add_edge(BasicEdge(v[3], v[4]))
    DG.add_edge(BasicEdge(v[4], v[2]))

    assert DG.retreating_edges() == {DG.get_edge(v[2], v[4])}

    DG.add_edge(BasicEdge(v[2], v[3]))

    assert DG.retreating_edges() == {DG.get_edge(v[2], v[3]), DG.get_edge(v[2], v[4])}

    DG.add_edge(BasicEdge(v[1], v[0]))

    assert DG.retreating_edges() == {DG.get_edge(v[2], v[3]), DG.get_edge(v[2], v[4])}
