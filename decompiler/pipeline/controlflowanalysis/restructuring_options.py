from dataclasses import dataclass
from enum import Enum

from decompiler.util.options import Options


class LoopBreakOptions(Enum):
    """Enumerator for the different optimization options for the variable renaming in out of SSA"""

    none = "None"
    structural_variable = "structural_variable"
    # loop_break


@dataclass
class RestructuringOptions:
    reconstruct_switch: bool
    allow_nested_switch: bool
    min_switch_cases: int
    loop_break_strategy: LoopBreakOptions

    @classmethod
    def generate(cls, options: Options):
        reconstruct_switch = options.getboolean("pattern-independent-restructuring.switch_reconstruction", fallback=True)
        allow_nested_switch = options.getboolean("pattern-independent-restructuring.nested_switch_nodes", fallback=True)
        min_switch_cases = options.getint("pattern-independent-restructuring.min_switch_case_number", fallback=2)
        loop_break_strategy = options.getstring("pattern-independent-restructuring.loop_break_switch", fallback="structural_variable")
        try:
            loop_break_option = LoopBreakOptions(loop_break_strategy)
        except:
            raise NameError(f"The option {loop_break_strategy} does not exist.")
        return cls(reconstruct_switch, allow_nested_switch, min_switch_cases, loop_break_option)
