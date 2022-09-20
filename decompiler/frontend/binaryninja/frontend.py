"""Class implementing the main binaryninja frontend interface."""
from typing import List, Tuple, Union

from binaryninja import BinaryView, BinaryViewType, Function
from binaryninja.types import SymbolType
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo.expressions import Variable
from decompiler.structures.pseudo.typing import Type
from decompiler.task import DecompilerTask
from decompiler.util.options import Options

from ..frontend import Frontend
from .lifter import BinaryninjaLifter
from .parser import BinaryninjaParser


class BinaryninjaFrontend(Frontend):
    """Frontend implementation for binaryninja."""

    BLACKLIST = {
        "_init",
        "_fini",
        "_start",
        "__cxa_finalize",
        "__x86.get_pc_thunk.bx",
        "deregister_tm_clones",
        "register_tm_clones",
        "__do_global_dtors_aux",
        "frame_dummy",
        "__x86.get_pc_thunk.dx",
        "__libc_start_main",
        "__libc_csu_init",
        "__libc_csu_fini",
        "__x86.get_pc_thunk.bp",
    }

    def __init__(self, bv: BinaryView):
        """Create a new binaryninja view with the given path."""
        self._bv = bv

    @classmethod
    def from_path(cls, path: str, options: Options):
        """Create a frontend object by invoking binaryninja on the given sample."""
        file_options = {"analysis.limits.maxFunctionSize": options.getint("binaryninja.max_function_size")}
        return cls(BinaryViewType.get_view_of_file_with_options(path, options=file_options))

    @classmethod
    def from_raw(cls, view: BinaryView):
        """Create a binaryninja frontend instance based on an initialized binary view."""
        return cls(view)

    def create_task(self, function: Union[str, Function], options: Options) -> DecompilerTask:
        """Create a task from the given function identifier."""
        if not isinstance(function, Function):
            function = self._find_function(function)
        return_type, params = self._extract_return_type_and_params(function)
        cfg = self._extract_cfg(function, options)
        task = DecompilerTask(function.name, cfg, function_return_type=return_type, function_parameters=params, options=options)
        task.function = function
        return task

    def get_all_function_names(self):
        """Returns the entire list of all function names in the binary. Ignores blacklisted functions and imported functions."""
        functions = list()
        for function in self._bv.functions:
            if function.name in BinaryninjaFrontend.BLACKLIST:
                continue
            if function.symbol.type == SymbolType.ImportedFunctionSymbol:
                continue
            functions.append(function.name)
        return functions

    def _find_function(self, function: str) -> Function:
        """Return the function at the given address."""
        address = self._get_address(function)
        return self._bv.get_function_at(address)

    def _extract_cfg(self, function: Function, options: Options = None) -> ControlFlowGraph:
        """Extract a control flow graph utilizing the parser and fixing it afterwards."""
        report_threshold = options.getint("lifter.report_threshold", fallback=3)
        no_masks = options.getboolean("lifter.no_bit_masks", fallback=True)
        parser = BinaryninjaParser(BinaryninjaLifter(no_masks), report_threshold)
        return parser.parse(function)

    def _extract_return_type_and_params(self, function: Function) -> Tuple[Type, List[Variable]]:
        """Extracts the type of the return value of the function and the list of its parameters"""
        lifter = BinaryninjaLifter()
        params: List[Variable] = [lifter.lift(param) for param in function.function_type.parameters]
        return_type: Type = lifter.lift(function.function_type.return_value)
        return return_type, params

    def _get_address(self, text: str) -> int:
        """Get the address of the target function by evaluating the given string."""
        if sym := self._bv.symbols.get(text, None):
            if isinstance(sym, list):
                # Sometimes Binja has 2 symbols for a library function, and returns a list:
                # [ImportedFunctionSymbol, ExternalSymbol]
                # We want the address of the Imported Function Symbol
                return sym[0].address
            return sym.address
        if "sub_" in text[0:4]:
            return int(text[4:], 16)
        try:
            return int(text, 16)
        except Exception as _:
            raise ValueError(f"{text} is neither a valid function name or a hex address!")
