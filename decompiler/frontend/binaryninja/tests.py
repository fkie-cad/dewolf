"""WIP test suite for binaryninja lifter."""
from os import listdir
from os.path import abspath, dirname, isfile, join, realpath
from sys import path

from binaryninja import BinaryViewType

# TODO: clean this up (kinda nasty hack)
current_dir = dirname(realpath(__file__))
path.append(abspath(join(current_dir, "../../..")))

from decompiler.frontend.binaryninja.lifter import BinaryninjaLifter
from decompiler.structures.pseudo import UnknownExpression

SAMPLE_PATH = "/bin"

for path in [join(SAMPLE_PATH, filename) for filename in listdir(SAMPLE_PATH)]:
    if not isfile(path):
        continue
    bv = BinaryViewType.get_view_of_file(path)
    lifter = BinaryninjaLifter()

    print(f"lifting {path}")
    n, miss = (0, 0)
    for mlil_instruction in bv.mlil_instructions:
        liftee = mlil_instruction.ssa_form
        lifted = lifter.lift(liftee)
        if isinstance(lifted, UnknownExpression):
            miss += 1
            print(f"Could not lift {liftee.operation}: {liftee} @@ {hex(liftee.address)}")
        n += 1
    if not n:
        print("---")
    else:
        print("%.2f%%" % ((miss / max(n, 1)) * 100))
