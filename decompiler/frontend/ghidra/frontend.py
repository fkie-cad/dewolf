"""Class implementing the main Ghidra frontend interface."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import List, Optional

from decompiler.frontend.frontend import Frontend
from decompiler.task import DecompilerTask
from decompiler.util.options import Options

from .lifter import GhidraLifter
from .parser import GhidraParser


class GhidraFrontend(Frontend):
    """Frontend implementation backed by Ghidra (via PyGhidra), lifting decompiler High-P-code."""

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

    _pyghidra_started = False

    def __init__(self, program, flat_api):
        """Create a new ghidra frontend from an analyzed program and its FlatProgramAPI."""
        from ghidra.app.decompiler import DecompInterface

        self._program = program
        self._flat_api = flat_api
        self._project = None
        self._decomp = DecompInterface()
        self._decomp.openProgram(program)

    @classmethod
    def _ensure_pyghidra(cls, options: Options) -> None:
        if cls._pyghidra_started:
            return
        try:
            import pyghidra
        except ImportError as exc:  # pyghidra not installed
            raise RuntimeError(
                "The Ghidra frontend requires the 'pyghidra' Python package. "
                "Install it (e.g. `pip install pyghidra`) and a matching Ghidra release, "
                "or use the Binary Ninja frontend (`--frontend binaryninja`)."
            ) from exc

        install_dir = (
            options.getstring("ghidra.install_dir", fallback="") or os.environ.get("GHIDRA_INSTALL_DIR") or cls._autodetect_install_dir()
        )
        try:
            pyghidra.start(install_dir=Path(install_dir) if install_dir else None)
        except Exception as exc:  # noqa: BLE001
            if "GHIDRA_INSTALL_DIR" in str(exc):
                raise RuntimeError(
                    "Ghidra frontend could not locate a Ghidra installation. "
                    "Set GHIDRA_INSTALL_DIR to your unzipped Ghidra directory "
                    "(the folder containing 'ghidraRun'), e.g.:\n"
                    "  export GHIDRA_INSTALL_DIR=/path/to/ghidra_xx.x.x_PUBLIC\n"
                    "or pass --ghidra-install-dir /path/to/ghidra."
                ) from exc
            raise
        cls._pyghidra_started = True

    @staticmethod
    def _autodetect_install_dir() -> Optional[str]:
        """Search a few common locations for a usable unzipped Ghidra install.

        Returns a directory that both contains 'ghidraRun' and the PyGhidra module
        (``Ghidra/Features/PyGhidra/lib/PyGhidra.jar``), or None. pyghidra itself does not
        auto-discover an install, so this avoids forcing every user to set GHIDRA_INSTALL_DIR;
        validating the PyGhidra module skips partial/older installs that lack it.
        """
        candidates: list = []
        for base in (os.path.expanduser("~/Downloads"), "/Applications", "/opt", os.path.expanduser("~")):
            try:
                entries = os.listdir(base)
            except OSError:  # noqa: BLE001
                continue
            for entry in entries:
                if entry.lower().startswith("ghidra"):
                    candidates.append(os.path.join(base, entry))

        def _is_valid(ghidra_dir: str) -> bool:
            return os.path.isfile(os.path.join(ghidra_dir, "ghidraRun")) and os.path.isfile(
                os.path.join(ghidra_dir, "Ghidra", "Features", "PyGhidra", "lib", "PyGhidra.jar")
            )

        for cand in sorted(candidates, reverse=True):  # prefer higher version dirs lexicographically
            if _is_valid(cand):
                return cand
        return None

    @classmethod
    def from_path(cls, path: str, options: Options) -> "GhidraFrontend":
        """Create a frontend by importing and analyzing the given binary with Ghidra."""
        cls._ensure_pyghidra(options)
        from ghidra.app.script import GhidraScriptUtil
        from ghidra.program.flatapi import FlatProgramAPI
        from pyghidra.core import _analyze_program, _setup_project

        project_location = options.getstring("ghidra.project_location", fallback="/tmp/dewolf_ghidra_projects")
        project_name = options.getstring("ghidra.project_name", fallback=Path(path).name)
        project, program = _setup_project(
            path,
            project_location=project_location,
            project_name=project_name,
        )
        GhidraScriptUtil.acquireBundleHostReference()
        flat_api = FlatProgramAPI(program)
        _analyze_program(flat_api, program)
        frontend = cls(program, flat_api)
        frontend._project = project
        return frontend

    @classmethod
    def from_raw(cls, view) -> "GhidraFrontend":
        """Create a frontend from an already-open Ghidra program (FlatProgramAPI or Program)."""
        from ghidra.app.script import GhidraScriptUtil
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.program.model.listing import Program

        cls._ensure_pyghidra(Options.load_default_options())
        if isinstance(view, FlatProgramAPI):
            program = view.getCurrentProgram()
            flat_api = view
        elif isinstance(view, Program):
            program = view
            GhidraScriptUtil.acquireBundleHostReference()
            flat_api = FlatProgramAPI(program)
        else:
            program = view
            GhidraScriptUtil.acquireBundleHostReference()
            flat_api = FlatProgramAPI(program)
        return cls(program, flat_api)

    def close(self) -> None:
        try:
            self._decomp.dispose()
        except Exception:  # noqa: BLE001
            pass
        if self._project is not None:
            try:
                from ghidra.app.script import GhidraScriptUtil

                self._project.save(self._program)
                self._project.close()
                GhidraScriptUtil.releaseBundleHostReference()
            except Exception as exc:  # noqa: BLE001
                logging.debug("[GhidraFrontend] close failed: %s", exc)

    # -- Frontend interface ------------------------------------------------
    def lift(self, task: DecompilerTask) -> None:
        if task.failed:
            return
        try:
            function = self._get_function(task.function_identifier)
            from ghidra.util.task import TaskMonitor

            result = self._decomp.decompileFunction(function, 120, TaskMonitor.DUMMY)
            if not result.decompileCompleted():
                task.fail("Function lifting", RuntimeError(result.getErrorMessage() or "decompile failed"))
                return
            high_function = result.getHighFunction()
            if high_function is None:
                task.fail("Function lifting", RuntimeError("no high function produced"))
                return

            no_masks = task.options.getboolean("lifter.no_bit_masks", fallback=True)
            report_threshold = task.options.getint("lifter.report_threshold", fallback=3)
            lifter = GhidraLifter(self._program, no_bit_masks=no_masks)
            parser = GhidraParser(lifter, report_threshold)

            # Prefer the decompiler-inferred prototype (names/types) over the
            # often-uncommitted listing parameters.
            try:
                proto = high_function.getFunctionPrototype()
                task.function_return_type = lifter.lift_type(proto.getReturnType())
                params, locations = self._lift_parameters_from_proto(lifter, proto)
            except Exception:  # noqa: BLE001
                task.function_return_type = lifter.lift_type(function.getReturnType())
                params = [self._lift_parameter(lifter, p) for p in function.getParameters()]
                locations = [self._parameter_location(p) for p in function.getParameters()]
            task.function_parameters = params
            task.function_parameter_locations = locations
            task.cfg = parser.parse(high_function)
            task.complex_types = parser.complex_types
        except Exception as exc:  # noqa: BLE001
            task.fail("Function lifting", exc)
            if task.options.getboolean("pipeline.debug", fallback=False):
                raise

    def get_all_function_names(self) -> List[str]:
        names: List[str] = []
        for function in self._program.getFunctionManager().getFunctions(True):
            if function.isThunk() or function.isExternal():
                continue
            if function.getName() in GhidraFrontend.BLACKLIST:
                continue
            names.append(function.getName())
        return names

    # -- helpers -----------------------------------------------------------
    def _lift_parameter(self, lifter: GhidraLifter, param):
        from decompiler.structures.pseudo import Variable

        name = param.getName() or f"param_{param.getOrdinal()}"
        vartype = lifter.lift_type(param.getDataType())
        return Variable(name, vartype)

    def _lift_parameters_from_proto(self, lifter: GhidraLifter, proto):
        from decompiler.structures.pseudo import Variable

        params, locations = [], []
        for i in range(proto.getNumParams()):
            psym = proto.getParam(i)
            try:
                if psym.isHiddenReturn():
                    continue
            except Exception:  # noqa: BLE001
                pass
            try:
                name = psym.getName() or f"param_{i}"
                vartype = lifter.lift_type(psym.getDataType())
            except Exception:  # noqa: BLE001
                name, vartype = f"param_{i}", None
            params.append(Variable(name, vartype))
            locations.append(self._storage_location(psym.getStorage()))
        return params, locations

    @staticmethod
    def _storage_location(storage) -> Optional[str]:
        try:
            if storage is None or storage.isEmpty():
                return None
            regs = storage.getRegisters()
            if regs and regs.hasNext():
                return regs.next().getName()
            return str(storage.getFirstVarnode())
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _parameter_location(param) -> Optional[str]:
        try:
            storage = param.getVariableStorage()
            if storage is None or storage.isEmpty():
                return None
            first = storage.getRegisters()
            if first and first.hasNext():
                return first.next().getName()
            return str(storage.getFirstVarnode())
        except Exception:  # noqa: BLE001
            return None

    def _get_function(self, function_identifier):
        from ghidra.program.model.listing import Function as GhidraFunction

        match function_identifier:
            case GhidraFunction():
                return function_identifier
            case str():
                return self._get_function_from_string(function_identifier)
            case int():
                return self._program.getFunctionManager().getFunctionAt(
                    self._program.getAddressFactory().getDefaultAddressSpace().getAddress(function_identifier)
                )
            case _:
                raise ValueError(f"Ghidra frontend can't handle identifier of type {type(function_identifier)}")

    def _get_function_from_string(self, name: str):
        if (function := self._resolve_by_name(name)) is not None:
            return function
        if (function := self._resolve_by_address(name)) is not None:
            return function
        raise RuntimeError(f"Ghidra frontend could not resolve function '{name}'")

    def _resolve_by_name(self, name: str):
        for function in self._program.getFunctionManager().getFunctions(True):
            if function.getName() == name:
                return function
        return None

    def _resolve_by_address(self, hex_str: str):
        try:
            hex_address = hex_str[4:] if hex_str.startswith("sub_") else hex_str
            address = int(hex_address, 16)
            return self._program.getFunctionManager().getFunctionAt(
                self._program.getAddressFactory().getDefaultAddressSpace().getAddress(address)
            )
        except ValueError:
            logging.info(f"{hex_str} does not contain hex value")
            return None
