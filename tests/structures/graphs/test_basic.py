"""Module implementing tests for the most basic node and edge implementations."""
from decompiler.structures.graphs.basic import BasicEdge, BasicNode


class TestBaseNode:
    """Tests for the basic node interface."""

    def test_representation(self):
        n1, n2, n3 = BasicNode(1), BasicNode("test"), BasicNode(0.7)
        assert str(n1) == "1" and str(n2) == "test" and str(n3) == "0.7"
        assert repr(n1) == "Node(1)" and repr(n2) == "Node(test)" and repr(n3) == "Node(0.7)"

    def test_copy(self):
        n1 = BasicNode(1)
        assert n1 == n1.copy() and id(n1) != id(n1.copy())
        n2 = BasicNode(object())
        assert n1 != n2
        assert n2 == n2.copy()


class TestBaseEdge:
    """Tests for the basic edge interface."""

    def test_copy(self):
        n1, n2, n3 = BasicNode(1), BasicNode(2), BasicNode(3)
        e1, e2 = BasicEdge(n1, n2), BasicEdge(n2, n3)
        assert e1 != e2
        assert e1 == e1.copy() and id(e1) != id(e1.copy())
        assert e2 == e2.copy() and id(e2) != id(e2.copy())
