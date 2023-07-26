"""Class implementing the main binaryninja frontend interface."""
from __future__ import annotations

import logging
from typing import List, Optional, Union

from binaryninja import BinaryView, Function
from binaryninja import load as BinaryNinja_load
from binaryninja.types import SymbolType
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo.expressions import Variable
from decompiler.structures.pseudo.typing import Type
from decompiler.task import DecompilerTask
from decompiler.util.options import Options

from ..frontend import Frontend
from .lifter import BinaryninjaLifter
from .parser import BinaryninjaParser
from .tagging import CompilerIdiomsTagging


class FunctionObject:
    """Wrapper class for dealing with Binaryninja Functions"""

    def __init__(self, function: Function):
        self._function = function
        self._lifter = BinaryninjaLifter()
        self._name = self._lifter.lift(self._function.symbol).name

    @classmethod
    def get(cls, bv: BinaryView, identifier: Union[str, Function]) -> FunctionObject:
        """Get a function object from the given identifier."""
        if isinstance(identifier, Function):
            return cls(identifier)
        if isinstance(identifier, str):
            return cls.from_string(bv, identifier)
        raise ValueError(f"Could not parse function identifier of type {type(identifier)}.")

    @classmethod
    def from_string(cls, bv: BinaryView, function_name: str) -> FunctionObject:
        """Given a function identifier, locate Function object in BinaryView"""
        if (function := cls._resolve_by_identifier_name(bv, function_name)) is not None:
            return cls(function)
        if (function := cls._resolve_by_address(bv, function_name)) is not None:
            return cls(function)
        raise RuntimeError(f"Frontend could not resolve function '{function_name}'")

    @property
    def function(self) -> Function:
        """Function object"""
        return self._function

    @property
    def name(self) -> str:
        """Name of function object"""
        return self._name

    @property
    def return_type(self) -> Type:
        """Lifted return type of function"""
        return self._lifter.lift(self._function.type.return_value)

    @property
    def params(self) -> List[Variable]:
        """Lifted function parameters"""
        return [self._lifter.lift(param) for param in self._function.type.parameters]

    @staticmethod
    def _resolve_by_identifier_name(bv: BinaryView, function_name: str) -> Optional[Function]:
        """
        Iterate BinaryView.functions and compare matching names.

        note: we take this approach since bv.get_functions_by_name() may return wrong functions.
        """
        return next(filter(lambda f: f.name == function_name, bv.functions), None)

    @staticmethod
    def _resolve_by_address(bv: BinaryView, hex_str: str) -> Optional[Function]:
        """Get Function object by hex address or 'sub_<address>'"""
        try:
            hex_address = hex_str[4:] if hex_str.startswith("sub_") else hex_str
            address = int(hex_address, 16)
            return bv.get_function_at(address)
        except ValueError:
            logging.info(f"{hex_str} does not contain hex value")


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
        self._bv = bv if type(bv) == BinaryView else bv.getCurrentFunction().view

    @classmethod
    def from_path(cls, path: str, options: Options):
        """Create a frontend object by invoking binaryninja on the given sample."""
        file_options = {"analysis.limits.maxFunctionSize": options.getint("binaryninja.max_function_size"), 
        "analysis.mode": "full"}
        if (bv := BinaryNinja_load(path, options=file_options)) is not None:
            return cls(bv)
        raise RuntimeError("Failed to create binary view")

    @classmethod
    def from_raw(cls, view: BinaryView):
        """Create a binaryninja frontend instance based on an initialized binary view."""
        return cls(view)

    def create_task(self, function_identifier: Union[str, Function], options: Options) -> DecompilerTask:
        """Create a task from the given function identifier."""
        function = FunctionObject.get(self._bv, function_identifier)
        tagging = CompilerIdiomsTagging(self._bv, function.function.start, options)
        tagging.run()
        try:
            cfg = self._extract_cfg(function.function, options)
            task = DecompilerTask(
                function.name, cfg, function_return_type=function.return_type, function_parameters=function.params,
                options=options
            )
        except Exception as e:
            task = DecompilerTask(
                function.name, None, function_return_type=function.return_type, function_parameters=function.params,
                options=options
            )
            task.fail(origin="CFG creation")
            logging.error(f"Failed to decompile {task.name}, error during CFG creation: {e}")
            if options.getboolean("pipeline.debug", fallback=False):
                raise e
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

    def _extract_cfg(self, function: Function, options: Options) -> ControlFlowGraph:
        """Extract a control flow graph utilizing the parser and fixing it afterwards."""
        report_threshold = options.getint("lifter.report_threshold", fallback=3)
        no_masks = options.getboolean("lifter.no_bit_masks", fallback=True)
        parser = BinaryninjaParser(BinaryninjaLifter(no_masks), report_threshold)
        return parser.parse(function)
