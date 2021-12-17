from functools import wraps
from typing import Callable


def ensure_cnf(method: Callable):
    """Decorate to ensure the the formula is in cnf-form and simplified after applying the method."""

    @wraps(method)
    def wrapper(self, *args, **kwargs):
        result = method(self, *args, **kwargs)
        self.simplify()
        self.to_cnf()
        return result

    return wrapper
