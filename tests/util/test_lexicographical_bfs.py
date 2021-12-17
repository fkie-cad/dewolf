"""Pytest for lexicographical BFS."""
from dewolf.structures.interferencegraph import InterferenceGraph
from dewolf.util.lexicographical_bfs import LexicographicalBFS


def test_lexicographical_order_no_interference():
    interference_graph = InterferenceGraph()
    lex_bfs = LexicographicalBFS(interference_graph)

    assert list(lex_bfs.reverse_lexicographic_bfs()) == []


def test_lexicographical_bfs_1a():
    interference_graph = InterferenceGraph()
    interference_graph.add_edges_from([(1, 4), (3, 4), (5, 4), (3, 2), (1, 5)])
    interference_graph.add_node(6)

    lex_bfs = LexicographicalBFS(interference_graph)

    assert list(lex_bfs.reverse_lexicographic_bfs()) == [1, 4, 5, 3, 2, 6]


def test_lexicographical_bfs_2():
    interference_graph = InterferenceGraph()
    interference_graph.add_edges_from(
        [(1, 4), (1, 6), (2, 3), (2, 7), (3, 7), (3, 8), (4, 6), (4, 7), (4, 8), (5, 6), (5, 7), (6, 7), (6, 8), (7, 8)]
    )

    lex_bfs = LexicographicalBFS(interference_graph)

    assert list(lex_bfs.reverse_lexicographic_bfs()) == [1, 4, 6, 7, 8, 5, 3, 2]
