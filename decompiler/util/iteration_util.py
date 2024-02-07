from collections.abc import Iterable
from itertools import groupby


def all_equal(iterable: Iterable):
    """See https://stackoverflow.com/a/3844832"""
    g = groupby(iterable)
    return next(g, True) and not next(g, False)
