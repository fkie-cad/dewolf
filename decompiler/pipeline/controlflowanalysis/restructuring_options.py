from dataclasses import dataclass

from decompiler.util.options import Options


@dataclass
class RestructuringOptions:
    reconstruct_switch: bool
    allow_nested_switch: bool
    min_switch_cases: int

    @classmethod
    def generate(cls, options: Options):
        reconstruct_switch = options.getboolean("pattern-independent-restructuring.switch_reconstruction", fallback=True)
        allow_nested_switch = options.getboolean("pattern-independent-restructuring.nested_switch_nodes", fallback=True)
        min_switch_cases = options.getint("pattern-independent-restructuring.min_switch_case_number", fallback=2)
        return cls(reconstruct_switch, allow_nested_switch, min_switch_cases)
