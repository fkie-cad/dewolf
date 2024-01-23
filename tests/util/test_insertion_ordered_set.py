from decompiler.util.insertion_ordered_set import InsertionOrderedSet


def test_insertion_ordered_set_operations():
    set_1 = InsertionOrderedSet([1, 2])
    set_2 = InsertionOrderedSet([4, 3])
    set_3 = InsertionOrderedSet([1, 2, 3, 4, 5])
    difference = set_3 - set_1
    intersection = set_1 & set_3
    symmetric_difference = set_1 ^ set_3
    union = set_1 | set_2
    assert isinstance(difference, InsertionOrderedSet) and (difference == InsertionOrderedSet([3, 4, 5]))
    assert isinstance(intersection, InsertionOrderedSet) and (intersection == InsertionOrderedSet([1, 2]))
    assert isinstance(symmetric_difference, InsertionOrderedSet) and (symmetric_difference == InsertionOrderedSet([3, 4, 5]))
    assert isinstance(union, InsertionOrderedSet) and (union == InsertionOrderedSet([1, 2, 4, 3]))
