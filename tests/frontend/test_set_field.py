"""A field write into an aliased struct must modify the struct version before the write (BN: `prev`), not the one after it.

BN: a.filled @ mem#33 -> mem#34 = a.filled @ mem#33 + 1
If the struct operand were a#34 (dest), a#34 would be used before insert-missing-definitions adds `a#34 -> a#33`
after the write. a#34 is then live from the function entry, interferes with a#0 and out-of-SSA fails
(coreutils users add_utmp, df canonicalize_filename_mode).
"""

from unittest.mock import MagicMock

import binaryninja
from decompiler.frontend.binaryninja.handlers.assignments import AssignmentHandler
from decompiler.structures.pseudo import Constant, Integer, Variable
from decompiler.structures.pseudo.complextypes import ComplexTypeMember, Struct
from decompiler.structures.pseudo.operations import MemberAccess


def test_struct_field_write_modifies_the_previous_version():
    struct_type = Struct(16, "utmp_alloc", {8: ComplexTypeMember(64, "filled", 8, Integer.int64_t())})
    a33 = Variable("a", struct_type, ssa_label=33, is_aliased=True)
    a34 = Variable("a", struct_type, ssa_label=34, is_aliased=True)
    one = Constant(1, Integer.int64_t())

    instruction = MagicMock(offset=8)
    instruction.dest.type = MagicMock(spec=binaryninja.NamedTypeReferenceType)
    instruction.dest.version = 34
    lifted = {id(instruction.dest.type): struct_type, id(instruction.prev): a33, id(instruction.dest): a34, id(instruction.src): one}
    handler = MagicMock()
    handler._lifter.lift.side_effect = lambda obj, **kwargs: lifted[id(obj)]

    assignment = AssignmentHandler.lift_set_field(handler, instruction, is_aliased=True)

    assert isinstance(assignment.destination, MemberAccess)
    assert assignment.destination.struct_variable == a33
    assert assignment.destination.writes_memory == 34
    assert assignment.requirements == [a33]
    assert assignment.definitions == []
