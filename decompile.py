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

    def _decompile(self, function_ids: Collection[object] | None = None, task_options: Options | None = None) -> Result:
        if function_ids is None:  # decompile all functions when none are specified
            function_ids = self._frontend.get_all_function_names()
        if task_options is None:
            task_options = Decompiler.create_options()

        pipeline = DecompilerPipeline.from_strings(
            task_options.getlist("pipeline.cfg_stages"),
            task_options.getlist("pipeline.ast_stages")
        )

        tasks = []
        for function_id in function_ids:
            task = DecompilerTask(str(function_id), function_id, task_options)
            tasks.append(task)

            self._frontend.lift(task)
            pipeline.run(task)

        code = self._backend.generate(tasks)

        return Decompiler.Result(
            tasks,
            code
        )

    def decompile(self, function_id: object, task_options: Options | None = None) -> DecompilerTask:
        """Decompile the target function."""
        output = self._decompile([function_id], task_options)
        output.tasks[0].code = output.code  # because bad api design...
        return output.tasks[0]

    def decompile_all(self, task_options: Optional[Options] = None) -> str:
        """Decompile all functions in the binary"""
        function_ids = self._frontend.get_all_function_names()
        return self._decompile(function_ids, task_options).code

    @dataclass
    class Result:
        tasks: list[DecompilerTask]
        code: str


"""When invoked as a script, run the commandline interface."""
if __name__ == "__main__":
    from decompiler.util.commandline import main

    main(Decompiler)
