#!/usr/bin/env python3
"""Main decompiler Interface."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Collection, Optional

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
    def create_options(cls) -> Options:
        """Create Options from defaults"""
        return Options.load_default_options()

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

    def decompile_all(self, function_ids: Collection[object] | None = None, task_options: Options | None = None) -> Result:
        """
        Decompile a collection of functions specified by their identifiers.

        :param function_ids: A collection of function identifiers to decompile. If None, decompiles all functions.
        :param task_options: Options for the decompilation tasks. If None, default options are used.
        :return: A Result object containing decompiled tasks and generated code.
        """
        if function_ids is None:  # decompile all functions when none are specified
            function_ids = self._frontend.get_all_function_names()
        if task_options is None:
            task_options = Decompiler.create_options()

        pipeline = DecompilerPipeline.from_strings(task_options.getlist("pipeline.cfg_stages"), task_options.getlist("pipeline.ast_stages"))

        tasks = []
        for func_id in function_ids:
            task = DecompilerTask(str(func_id), func_id, task_options)
            tasks.append(task)

            self._frontend.lift(task)
            pipeline.run(task)

        code = self._backend.generate(tasks)

        return Decompiler.Result(tasks, code)

    def decompile(self, function_id: object, task_options: Options | None = None) -> tuple[DecompilerTask, str]:
        """
        Decompile a specific function specified by its identifier.
        This method servers as a shorthand for decompiling a single function and simply delegates to decompile_all.

        :param function_id: The ID of the function to decompile.
        :param task_options: Options for the decompilation task. If None, default options are used.
        :return: A tuple containing the DecompilerTask object and the generated code.
        """
        result = self.decompile_all([function_id], task_options)
        return result.tasks[0], result.code

    @dataclass
    class Result:
        tasks: list[DecompilerTask]
        code: str


"""When invoked as a script, run the commandline interface."""
if __name__ == "__main__":
    from decompiler.util.commandline import main

    main(Decompiler)
