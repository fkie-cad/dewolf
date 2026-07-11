"""Module for removing Windows SEH ExceptionList (FS:[0]) handler-chain bookkeeping."""

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.pseudo.expressions import Constant, Variable
from decompiler.task import DecompilerTask


class RemoveSEHExceptionList(PipelineStage):
    """
    Removes Windows Structured-Exception-Handling (SEH) bookkeeping of the FS:[0] handler-chain head,
    which Ghidra models as an aliased global named ``ExceptionList``.

    The MSVC SEH prologue/epilogue reads and writes this location in tight sequence
    (``mov eax, fs:[0]; mov fs:[0], esp; ... mov fs:[0], eax``). The Ghidra frontend's memory-SSA
    versioning gives two of those accesses the same SSA label, so ``insert-missing-definitions``
    later finds two identically-labelled copies and raises
    ``duplicate entries in copy pool for ExceptionList`` -- failing the whole function (it was the
    single most common Ghidra-frontend failure on Windows binaries).

    ``ExceptionList`` is pure compiler bookkeeping (it installs/removes the exception handler; it is
    not part of the program's data flow, and Ghidra's own decompiler hides it), so we drop it: every
    write to it is removed, and every read of it is replaced by 0 so the reading variable stays
    defined. Analogous to :class:`RemoveStackCanary`.

    Caution: this stage changes code semantics (it removes the SEH handler registration).
    """

    name = "remove-seh-exception-list"
    EXCEPTION_LIST = "ExceptionList"

    def run(self, task: DecompilerTask):
        if not task.options.getboolean(f"{self.name}.remove_seh", fallback=True):
            return
        for block in task.graph.nodes:
            kept = []
            for instruction in block.instructions:
                if self._defines_exception_list(instruction):
                    # a write to / phi of ExceptionList: the handler install/restore -- drop it
                    continue
                for used in list(instruction.requirements):
                    if self._is_exception_list(used):
                        # a read of ExceptionList: neutralize so its reader keeps a definition
                        instruction.substitute(used, Constant(0, used.type))
                kept.append(instruction)
            block.instructions = kept

    def _defines_exception_list(self, instruction) -> bool:
        return any(self._is_exception_list(variable) for variable in instruction.definitions)

    @staticmethod
    def _is_exception_list(expression) -> bool:
        return isinstance(expression, Variable) and expression.name == RemoveSEHExceptionList.EXCEPTION_LIST
