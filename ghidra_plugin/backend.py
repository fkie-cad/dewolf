"""dewolf decompilation backend exposed to the Java plugin via JPype."""
from __future__ import annotations

import logging
import re
import traceback
from collections import OrderedDict

from jpype import JArray, JClass, JImplements, JOverride

from ghidra_plugin import options_bridge, tokenizer

CACHE_LIMIT = 128

_DATA_NAME_PATTERN = re.compile(r"^data_0x([0-9a-fA-F]+)$")
_U_UID_PATTERN = re.compile(r"^u(\d+)$")  # lifter name for an unnamed HighVariable: u<rep varnode uid>

logger = logging.getLogger("dewolf.ghidra_gui")


def _raise_if_cancelled(should_cancel) -> None:
    """Abort the current decompilation if the caller signalled cancellation (interactive preempt)."""
    if should_cancel is not None and should_cancel():
        from decompiler.pipeline.pipeline import PipelineInterrupted

        raise PipelineInterrupted()


@JImplements("dewolfghidra.DewolfBackend", deferred=True)
class DewolfPythonBackend:
    """Implements the dewolfghidra.DewolfBackend Java interface.

    Called from the plugin's single decompilation thread, so no locking is needed.
    One dewolf Decompiler (and thus one DecompInterface) is kept per open program;
    results are cached keyed by the program's modification number, so any change to
    the Ghidra database (rename, retype, ...) naturally invalidates the cache.
    """

    def __init__(self):
        self._decompilers: dict[int, object] = {}
        self._cache: OrderedDict[tuple, tuple] = OrderedDict()
        self._tool = None

    @JOverride
    def initialize(self, tool):
        """Register dewolf's options in the tool and remember it for reading them back."""
        self._tool = tool
        try:
            options_bridge.register(tool)
        except Exception:  # noqa: BLE001
            logger.exception("failed to register dewolf options in the tool")

    @JOverride
    def decompile(self, program, function, cancel=None):
        from decompiler.pipeline.pipeline import PipelineInterrupted

        should_cancel = (lambda: bool(cancel.isCancelled())) if cancel is not None else None
        try:
            return self._decompile(program, function, should_cancel)
        except PipelineInterrupted:
            # a newer navigation superseded this decompile; the caller discards null results
            return None
        except Exception:  # noqa: BLE001 - errors are rendered into the code view
            logger.exception("dewolf failed to decompile %s", function.getName())
            trace = "\n".join(f"// {line}" for line in traceback.format_exc().splitlines())
            return self._to_java(f"// dewolf failed to decompile {function.getName()}:\n{trace}", None, None)

    @JOverride
    def programClosed(self, program):
        program_id = int(program.getUniqueProgramID())
        decompiler = self._decompilers.pop(program_id, None)
        if decompiler is not None:
            try:
                decompiler._frontend.close()
            except Exception:  # noqa: BLE001
                logger.debug("closing dewolf frontend failed", exc_info=True)
        self._cache = OrderedDict((key, value) for key, value in self._cache.items() if key[0] != program_id)

    def _decompile(self, program, function, should_cancel=None):
        overrides = options_bridge.read_overrides(self._tool)
        key = (
            int(program.getUniqueProgramID()),
            int(function.getEntryPoint().getOffset()),
            int(program.getModificationNumber()),
            # option changes are not reflected in the modification number, so fold the
            # current option values into the key to invalidate the cache on any change
            hash(tuple(sorted(overrides.items()))),
        )
        if (cached := self._cache.get(key)) is not None:
            self._cache.move_to_end(key)
            return self._to_java(*cached)

        _raise_if_cancelled(should_cancel)
        decompiler = self._get_decompiler(program)
        high_function = self._high_function(decompiler, function)
        _raise_if_cancelled(should_cancel)
        task, code = self._run_pipeline(
            decompiler, function, self._user_defined_names(high_function), overrides, should_cancel
        )
        code = self._reindent(code).strip("\n")  # drop blank lines around the function
        tokens = tokenizer.tokenize(code, self._name_classifier(task, program))
        original_names = self._original_names(task, high_function)

        self._cache[key] = (code, tokens, high_function, original_names)
        while len(self._cache) > CACHE_LIMIT:
            self._cache.popitem(last=False)
        return self._to_java(code, tokens, high_function, original_names)

    def _run_pipeline(
        self, decompiler, function, user_defined_names: set[str], overrides: dict | None = None, should_cancel=None
    ):
        """Decompiler.decompile, unrolled so user-defined names can be applied to the
        AST between the pipeline and code generation (dewolf's out-of-ssa names merged
        locals var_N; the original names survive in each instance's .ssa_name)."""
        from decompiler.backend.codegenerator import CodeGenerator
        from decompiler.pipeline.pipeline import DecompilerPipeline
        from decompiler.task import DecompilerTask

        options = type(decompiler).create_options()
        if overrides:
            options.update(overrides)  # apply the user's Ghidra Tool Options choices
        task = DecompilerTask(str(function), function, options)
        _raise_if_cancelled(should_cancel)
        decompiler._frontend.lift(task)
        pipeline = DecompilerPipeline.from_strings(
            options.getlist("pipeline.cfg_stages"), options.getlist("pipeline.ast_stages")
        )
        pipeline.run(task, should_cancel=should_cancel)
        _raise_if_cancelled(should_cancel)
        self._apply_source_names(task, user_defined_names)
        # Suppress the `extern <type> data_X = 0xX;` global-declaration block: for globals
        # dewolf could not type it degenerates to a self-valued line (value == address),
        # which is pure noise in an interactive view. The globals remain inline in the body
        # (and are click-to-navigate); the reader can inspect their real contents in the
        # Listing. This matches Ghidra's own decompiler, which shows no such block.
        return task, CodeGenerator(declare_globals=False).generate([task])

    @staticmethod
    def _user_defined_names(high_function) -> set[str]:
        """Names the user assigned in the Ghidra database (SourceType.USER_DEFINED)."""
        names: set[str] = set()
        if high_function is None:
            return names
        try:
            from ghidra.program.model.symbol import SourceType

            symbols = high_function.getLocalSymbolMap().getSymbols()
            while symbols.hasNext():
                high_symbol = symbols.next()
                symbol = high_symbol.getSymbol()
                if symbol is not None and symbol.getSource() == SourceType.USER_DEFINED:
                    names.add(str(high_symbol.getName()))
        except Exception:  # noqa: BLE001
            logger.debug("collecting user-defined names failed", exc_info=True)
        return names

    @staticmethod
    def _variable_groups(task) -> dict[tuple, list]:
        """Group the AST's local variable instances by output identity (name, ssa_label)."""
        from collections import defaultdict

        from decompiler.pipeline.controlflowanalysis.variable_name_generation import VariableCollector
        from decompiler.structures.pseudo import GlobalVariable

        if task.failed or task.ast is None:
            return {}
        collector = VariableCollector()
        collector.visit_ast(task.ast)
        groups: dict[tuple, list] = defaultdict(list)
        for variable in collector.variables:
            if not isinstance(variable, GlobalVariable):
                groups[(variable.name, variable.ssa_label)].append(variable)
        return groups

    def _apply_source_names(self, task, user_defined_names: set[str]) -> None:
        """Rename output variables to the user-defined Ghidra name they originate from."""
        from typing import Counter

        from decompiler.pipeline.controlflowanalysis.variable_name_generation import (
            RenamingScheme,
            VariableNameGeneration,
        )

        if not user_defined_names:
            return
        groups = self._variable_groups(task)
        if not groups:
            return
        parameter_names = {parameter.name for parameter in (task.function_parameters or [])}
        taken = {name for name, _label in groups} | parameter_names
        rename_map: dict[tuple, str] = {}
        for (name, label), instances in groups.items():
            if name in parameter_names:
                continue
            origins = Counter(
                instance.ssa_name.name for instance in instances if instance.ssa_name is not None
            )
            for candidate, _count in origins.most_common():
                if candidate in user_defined_names and candidate != name and candidate not in taken:
                    rename_map[(name, label)] = candidate
                    taken.add(candidate)
                    break
        if not rename_map:
            return

        class SourceNameScheme(RenamingScheme):
            def rename_variable(self, variable):
                new_name = rename_map.get((variable.name, variable.ssa_label))
                return variable.copy(name=new_name) if new_name is not None else None

        VariableNameGeneration._rename_with_scheme(task, SourceNameScheme())

    def _original_names(self, task, high_function=None) -> dict[str, str]:
        """Map displayed variable names to the Ghidra HighSymbol names they came from.

        A variable's provenance (``.ssa_name.name``) is the lifter's name for the originating
        varnode. For an unnamed HighVariable that is ``u<rep_uid>`` (a register/temporary Ghidra
        left unnamed in the lifted SSA) — but Ghidra's decompiler still shows and can rename many of
        these as ``uVar2``/``iVar1`` because a HighSymbol *does* back the representative varnode. We
        resolve those here (uid -> HighSymbol name) so the rename maps to a real database variable,
        without giving the name to the SSA identity (that collides — see the lifter's ``_name_for``).
        """
        from typing import Counter

        uid_to_symbol = self._uid_symbol_map(high_function) if high_function is not None else {}
        names: dict[str, str] = {}
        for (name, _label), instances in self._variable_groups(task).items():
            origins = Counter(
                instance.ssa_name.name for instance in instances if instance.ssa_name is not None
            )
            if not origins:
                continue
            origin = origins.most_common(1)[0][0]
            if (match := _U_UID_PATTERN.match(origin)) is not None:
                resolved = uid_to_symbol.get(int(match.group(1)))
                if resolved:
                    origin = resolved
            names[name] = origin
        return names

    @staticmethod
    def _uid_symbol_map(high_function) -> dict[int, str]:
        """varnode uid -> its HighSymbol name, for every symbol-backed varnode in the function.

        Lets ``_original_names`` turn a ``u<rep_uid>`` provenance name into the renameable Ghidra
        symbol name (matching what ``HighFunction.getLocalSymbolMap`` — and the Java rename — use).
        """
        result: dict[int, str] = {}
        try:
            ops = high_function.getPcodeOps()
            while ops.hasNext():
                op = ops.next()
                varnodes = list(op.getInputs())
                if (out := op.getOutput()) is not None:
                    varnodes.append(out)
                for varnode in varnodes:
                    if varnode is None:
                        continue
                    uid = int(varnode.getUniqueId())
                    if uid in result:
                        continue
                    high = varnode.getHigh()
                    if high is None:
                        continue
                    symbol = high.getSymbol()
                    if symbol is not None:
                        symbol_name = str(symbol.getName())
                        if symbol_name and symbol_name != "UNNAMED":
                            result[uid] = symbol_name
        except Exception:  # noqa: BLE001
            logger.debug("building uid->symbol map failed", exc_info=True)
        return result

    # -- token classification ------------------------------------------------
    def _name_classifier(self, task, program):
        """Classify identifiers in the output using the task's AST and the symbol table."""
        local_names: set[str] = set()
        global_names: set[str] = set()
        # name -> address for call targets. dewolf names callees `sub_<hex>` from the
        # address (e.g. `sub_401278`), which never matches Ghidra's `FUN_00401278`
        # symbol-table name, so classifying these by the address the FunctionSymbol
        # already carries is the only reliable way to make them navigable.
        function_addresses: dict[str, int] = {}
        parameter_names = {variable.name for variable in (task.function_parameters or [])}
        if task is not None and not task.failed and task.ast is not None:
            from decompiler.pipeline.controlflowanalysis.variable_name_generation import VariableCollector
            from decompiler.structures.pseudo import FunctionSymbol, GlobalVariable, ImportedFunctionSymbol

            collector = VariableCollector()
            collector.visit_ast(task.ast)
            for variable in collector.variables:
                if isinstance(variable, GlobalVariable):
                    global_names.add(variable.name)
                elif variable.name not in parameter_names:
                    local_names.add(variable.name)

            for symbol in self._collect_function_symbols(task):
                if isinstance(symbol, (FunctionSymbol, ImportedFunctionSymbol)) and isinstance(symbol.value, int):
                    # a call through a data pointer is lifted as an ImportedFunctionSymbol named
                    # `data_<hex>`; classify it as data (GLOBAL) so it renders/navigates as data
                    if not symbol.name.startswith("data_"):
                        function_addresses[symbol.name] = symbol.value

        symbol_cache: dict[str, tuple[int, int]] = {}

        def lookup_symbol(name: str) -> tuple[int, int] | None:
            from ghidra.program.model.symbol import SymbolType

            try:
                for symbol in program.getSymbolTable().getGlobalSymbols(name):
                    address = int(symbol.getAddress().getOffset())
                    if symbol.getSymbolType() == SymbolType.FUNCTION:
                        return tokenizer.FUNCTION, address
                    return tokenizer.GLOBAL, address
            except Exception:  # noqa: BLE001
                logger.debug("symbol lookup failed for %s", name, exc_info=True)
            return None

        def classify(name: str) -> tuple[int, int]:
            if name in function_addresses:
                return tokenizer.FUNCTION, function_addresses[name]
            if name in parameter_names:
                return tokenizer.PARAMETER, -1
            if name in local_names:
                return tokenizer.VARIABLE, -1
            if (match := _DATA_NAME_PATTERN.match(name)) is not None:
                return tokenizer.GLOBAL, int(match.group(1), 16)
            if (cached := symbol_cache.get(name)) is not None:
                return cached
            result = lookup_symbol(name)
            if result is None:
                result = (tokenizer.GLOBAL, -1) if name in global_names else (tokenizer.DEFAULT, -1)
            symbol_cache[name] = result
            return result

        return classify

    @staticmethod
    def _collect_function_symbols(task) -> list:
        """Collect all FunctionSymbol/ImportedFunctionSymbol constants from the AST."""
        from decompiler.structures.pseudo import FunctionSymbol, ImportedFunctionSymbol
        from decompiler.structures.visitors.ast_dataflowobjectvisitor import BaseAstDataflowObjectVisitor

        class FunctionSymbolCollector(BaseAstDataflowObjectVisitor):
            def __init__(self):
                self.symbols: list = []

            def visit_constant(self, expression):
                if isinstance(expression, (FunctionSymbol, ImportedFunctionSymbol)):
                    self.symbols.append(expression)

        collector = FunctionSymbolCollector()
        collector.visit_ast(task.ast)
        return collector.symbols

    # -- helpers ---------------------------------------------------------------
    def _to_java(self, code: str, tokens, high_function, original_names: dict[str, str] | None = None):
        TokenData = JClass("dewolfghidra.DewolfTokenData")
        Decompilation = JClass("dewolfghidra.DewolfDecompilation")
        HashMap = JClass("java.util.HashMap")
        if tokens is None:
            tokens = tokenizer.message_tokens(code)
        token_array = JArray(TokenData)(
            [TokenData(kind, text, address, indent) for kind, text, address, indent in tokens]
        )
        name_map = HashMap()
        for displayed, original in (original_names or {}).items():
            name_map.put(displayed, original)
        return Decompilation(code, token_array, high_function, name_map)

    @staticmethod
    def _high_function(decompiler, function):
        """Ghidra's decompiler model of the function, for panel features needing one."""
        try:
            from ghidra.util.task import TaskMonitor

            result = decompiler._frontend._decomp.decompileFunction(function, 60, TaskMonitor.DUMMY)
            if result is not None and result.decompileCompleted():
                return result.getHighFunction()
        except Exception:  # noqa: BLE001
            logger.debug("fetching HighFunction failed", exc_info=True)
        return None

    @staticmethod
    def _reindent(code: str) -> str:
        """Indent the raw codegen output with astyle (as the Binary Ninja widget does)."""
        from decompiler.util.decoration import DecoratedCode

        try:
            return DecoratedCode.formatted_plain(code)
        except Exception:  # noqa: BLE001 - astyle missing: show unformatted code instead
            logger.warning("astyle failed or is not installed; showing unformatted code", exc_info=True)
            return code

    def _get_decompiler(self, program):
        from decompile import Decompiler
        from decompiler.frontend.ghidra import GhidraFrontend

        # The JVM is already running (we are inside it); skip pyghidra.start().
        GhidraFrontend._pyghidra_started = True

        program_id = int(program.getUniqueProgramID())
        if (decompiler := self._decompilers.get(program_id)) is None:
            decompiler = Decompiler.from_raw(program, frontend="ghidra")
            self._decompilers[program_id] = decompiler
        return decompiler
