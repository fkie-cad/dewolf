#!/usr/bin/env python3
"""Main decompiler Interface."""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from decompiler.backend.codegenerator import CodeGenerator
from decompiler.frontend import BinaryninjaFrontend, Frontend
from decompiler.pipeline.pipeline import DecompilerPipeline
from decompiler.task import DecompilerTask
from decompiler.util.options import Options


class Decompiler:
    """Main Interface to the decompiler."""

    def __init__(self, frontend: Frontend):
        """
        Initialize a new decompiler on the given view.

        frontend -- The disassembler frontend to be used.
        """
        self._frontend = frontend
        self._backend = CodeGenerator()

    @classmethod
    def create_options(cls, extra_options: Optional[Dict] = None):
        """Create a dictionary holding user defined settings/options from both command line and default config files"""
        # First retrieve default options
        all_options = Options.load_default_options()
        # Now retrieve the extra options passed via commandline
        all_options.add_cmdline_options(extra_options)
        return all_options

    @classmethod
    def from_path(cls, path: str, options: Optional[Options] = None, frontend: Frontend = BinaryninjaFrontend) -> Decompiler:
        """Create a decompiler instance by invoking the given frontend on the given sample."""
        if not options:
            options = Decompiler.create_options()
        return cls(frontend.from_path(path, options))

    @classmethod
    def from_raw(cls, data, frontend: Frontend = BinaryninjaFrontend) -> Decompiler:
        """Create a decompiler instance from existing frontend instance (e.g. a binaryninja view)."""
        return cls(frontend.from_raw(data))

    def decompile(self, function: str, task_options: Optional[Options] = None) -> DecompilerTask:
        """Decompile the target function."""
        # Sanity check to ensure task_options is populated
        if task_options is None:
            task_options = Decompiler.create_options()
        # Start decompiling
        pipeline = DecompilerPipeline.from_strings(task_options.getlist("pipeline.cfg_stages"), task_options.getlist("pipeline.ast_stages"))
        task = self._frontend.create_task(function, task_options)
        pipeline.run(task)
        task.code = self._backend.generate([task])
        return task

    def decompile_all(self, task_options: Optional[Options] = None) -> str:
        """Decompile all functions in the binary"""
        tasks = list()
        # Sanity check to ensure task_options is populated
        if task_options is None:
            task_options = Decompiler.create_options()
        # Start decompiling
        pipeline = DecompilerPipeline.from_strings(task_options.getlist("pipeline.cfg_stages"), task_options.getlist("pipeline.ast_stages"))
        functions = self._frontend.get_all_function_names()
        for function in functions:
            task = self._frontend.create_task(function, task_options)
            pipeline.run(task)
            tasks.append(task)
        code = self._backend.generate(tasks)
        return code


"""When invoked as a script, run the commandline interface."""
if __name__ == "__main__":
    from decompiler.util.commandline import main

    main(Decompiler)
