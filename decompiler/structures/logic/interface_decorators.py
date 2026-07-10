from functools import wraps
from typing import Callable


def ensure_cnf(method: Callable):
    """Decorate to ensure that the formula is in cnf-form and simplified after applying the method."""

    @wraps(method)
    def wrapper(self, *args, **kwargs):
        result = method(self, *args, **kwargs)
        # simplify()/to_cnf() are cheap no-ops for already-normalized formulas: simplify_z3_condition
        # short-circuits literals/true/false, and to_cnf() returns early when already in CNF form.
        self.simplify()
        self.to_cnf()
        return result

    return wrapper
