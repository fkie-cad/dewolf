from decompiler.structures.logic.interface_decorators import ensure_cnf


class StupidBaseCase:
    def simplify(self):
        pass

    def to_cnf(self):
        pass


class BaseCase:
    @ensure_cnf
    def __init__(self, inp):
        self._input = inp

    @ensure_cnf
    def __str__(self):
        return str(self._input)

    def simplify(self):
        self._input = self._input - 1

    def to_cnf(self):
        self._input = 3 * self._input


def test_classes_without_methods_can_be_wrapped():
    class TestCase(StupidBaseCase): ...

    a = TestCase()
    assert a


def test_classes_with_init():
    class TestCase(StupidBaseCase):
        def __init__(self, inp):
            self._input = inp

    a = TestCase(5)
    assert a


def test_classes_with_return_value():
    class TestCase(BaseCase): ...

    a = TestCase(5)
    assert a._input == 12
    assert a._input == 12
    assert str(a) == "12"
    assert a._input == 33


def test_classes_no_cnf():
    class TestCase(BaseCase):
        @ensure_cnf
        def get_input(self):
            return self._input

    a = TestCase(5)
    assert a.get_input() == 12


def test_class_method():
    class TestCase(BaseCase):
        @classmethod
        def initialize(cls, inp=5):
            return cls(inp)

    a = TestCase.initialize()
    assert a._input == 12
