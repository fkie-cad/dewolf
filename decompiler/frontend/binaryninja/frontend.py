"""Class implementing the main binaryninja frontend interface."""
import logging
from typing import List, Optional, Tuple, Union

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
        debug_mode = options.getboolean("pipeline.debug", fallback=False)
        if isinstance(function, Function):
            function_obj = function
        elif (function_obj := self._get_function_from_str(function)) is None:
            raise ValueError(f"Could not resolve function symbol {function}")
        return_type, params = self._extract_return_type_and_params(function_obj)
        try:
            cfg = self._extract_cfg(function_obj, options)
            task = DecompilerTask(function_obj.name, cfg, function_return_type=return_type, function_parameters=params, options=options)
        except Exception as e:
            task = DecompilerTask(function_obj.name, None, function_return_type=return_type, function_parameters=params, options=options)
            task.fail(origin="CFG creation")
            logging.error(f"Failed to decompile {task.name}, error during CFG creation: {e}")
            if debug_mode:
                raise e
        task.function = function_obj
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

    def _get_function_from_str(self, symbol_str: str) -> Optional[Function]:
        """Return Function object matching the given symbol string or hex address"""
        if symbols_list := self._bv.symbols.get(symbol_str, []):  # alternative: bv.get_symbols_by_name(..)
            logging.debug(f"symbols list: {symbols_list}")
            for sym in symbols_list:
                if sym.type == SymbolType.FunctionSymbol:
                    if function := self._bv.get_function_at(sym.address):
                        # check if function name matches symbol. 
                        # Sometimes wrong symbols are contained in the list.
                        if function.name == symbol_str:
                            return function
            # Sometimes Binja has 2 symbols for a library function, and returns a list:
            # [ImportedFunctionSymbol, ExternalSymbol]
            # We want the address of the ImportedFunctionSymbol
            logging.debug(f"symbols list: {symbols_list}")
            for sym in symbols_list:
                if sym.type == SymbolType.ImportedFunctionSymbol:
                    return self._bv.get_function_at(sym.address)
        logging.info(f"Did not find matching function for symbol '{symbol_str}'. Try hex address...")
        try:
            hex_address = symbol_str[4:] if symbol_str.startswith("sub_") else symbol_str
            address = int(hex_address, 16)
            return self._bv.get_function_at(address)
        except ValueError:
            logging.info(f"{symbol_str} does not contain a hex value")
        return None


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
