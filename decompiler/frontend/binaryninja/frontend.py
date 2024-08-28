"""Class implementing the main binaryninja frontend interface."""

from __future__ import annotations

import logging

import binaryninja
from binaryninja import BinaryView
from binaryninja.types import SymbolType
from decompiler.frontend.binaryninja.rust_string_detection import RustStringDetection
from decompiler.task import DecompilerTask
from decompiler.util.options import Options

from ..frontend import Frontend
from .lifter import BinaryninjaLifter
from .parser import BinaryninjaParser
from .tagging import CompilerIdiomsTagging


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
        file_options = {"analysis.limits.maxFunctionSize": options.getint("binaryninja.max_function_size")}
        if (bv := binaryninja.load(path, options=file_options)) is not None:
            return cls(bv)
        raise RuntimeError("Failed to create binary view")

    @classmethod
    def from_raw(cls, view: BinaryView):
        """Create a binaryninja frontend instance based on an initialized binary view."""
        return cls(view)

    def lift(self, task: DecompilerTask):
        """
        Lifts data from binaryninja into the specified Decompiler task.
        The function to be lifted is identified by the function identifier of the decompiler task (task.function_identifier).

        :param task: Decompiler task to lift data into.
        """
        if task.failed:
            return

        try:
            function = self._get_binninja_function(task.function_identifier)
            lifter, parser = self._create_lifter_parser(task.options)

            rust_string_detection = RustStringDetection(self._bv, task.options)
            rust_string_detection.run()

            task.function_return_type = lifter.lift(function.return_type)
            task.function_parameters = [lifter.lift(param_type) for param_type in function.type.parameters]

            tagging = CompilerIdiomsTagging(self._bv, function.start, task.options)
            tagging.run()

            task.cfg = parser.parse(function)
            task.function_parameter_locations = self._parameter_locations(function)
            task.complex_types = parser.complex_types
        except Exception as e:
            task.fail("Function lifting")
            logging.exception(f"Failed to decompile {task.name}, error during function lifting")

            if task.options.getboolean("pipeline.debug", fallback=False):
                raise e

    def _parameter_locations(self, function: binaryninja.function.Function) -> list[str | None]:
        raw_parameters = function.type.parameters
        parameter_locations = []
        for parameter in raw_parameters:
            name = parameter.location.name if parameter.location is not None else None
            parameter_locations.append(name)
        return parameter_locations


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

    def _get_binninja_function(self, function_identifier: object) -> binaryninja.function.Function:
        """
        Retrieves the Binary Ninja function based on the provided function identifier.

        :param function_identifier: An object representing the identifier of the function.
        :return: The Binary Ninja function object corresponding to the provided identifier.
        :raises ValueError: If the function identifier is of an unsupported type.
        :raises RuntimeError: If Binary Ninja frontend could not resolve the function.
        """
        function: binaryninja.function.Function | None
        match function_identifier:
            case str():
                function = self._get_binninja_function_from_string(function_identifier)
            case binaryninja.function.Function():
                function = function_identifier
            case _:
                raise ValueError(f"BNinja frontend can't handle function identifier of type {type(function_identifier)}")

        if function is None:
            raise RuntimeError(f"BNinja frontend could not resolve function with identifier '{function_identifier}'")

        if function.analysis_skipped:
            raise RuntimeError(
                f"BNinja skipped function analysis for function '{function.name}' with reason '{function.analysis_skip_reason.name}'"
            )

        return function

    def _get_binninja_function_from_string(self, function_name: str) -> binaryninja.function.Function | None:
        """Given a function string identifier, locate Function object in BinaryView"""
        if (function := self._resolve_by_identifier_name(function_name)) is not None:
            return function
        if (function := self._resolve_by_address(function_name)) is not None:
            return function

        return None

    def _resolve_by_identifier_name(self, function_name: str) -> binaryninja.function.Function | None:
        """
        Iterate BinaryView.functions and compare matching names.

        note: we take this approach since bv.get_functions_by_name() may return wrong functions.
        """
        return next(filter(lambda f: f.name == function_name, self._bv.functions), None)

    def _resolve_by_address(self, hex_str: str) -> binaryninja.function.Function | None:
        """Get Function object by hex address or 'sub_<address>'"""
        try:
            hex_address = hex_str[4:] if hex_str.startswith("sub_") else hex_str
            address = int(hex_address, 16)
            return self._bv.get_function_at(address)
        except ValueError:
            logging.info(f"{hex_str} does not contain hex value")

    def _create_lifter_parser(self, options: Options) -> tuple[BinaryninjaLifter, BinaryninjaParser]:
        report_threshold = options.getint("lifter.report_threshold", fallback=3)
        no_masks = options.getboolean("lifter.no_bit_masks", fallback=True)
        lifter = BinaryninjaLifter(no_masks, bv=self._bv)
        parser = BinaryninjaParser(lifter, report_threshold)
        return lifter, parser
