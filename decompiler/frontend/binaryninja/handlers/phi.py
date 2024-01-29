"""Module implementing lifting of phi and memphi instructions."""

from typing import List

from binaryninja import MediumLevelILMemPhi, MediumLevelILVarPhi
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import MemPhi, Phi, Variable


class PhiHandler(Handler):
    """Handler for phi instructions emitted by binaryninja."""

    def register(self):
        """Register the handler at the parent lifter."""
        self._lifter.HANDLERS.update(
            {
                MediumLevelILVarPhi: self.lift_phi,
                MediumLevelILMemPhi: self.lift_mem_phi,
            }
        )

    def lift_phi(self, phi: MediumLevelILVarPhi, **kwargs) -> Phi:
        """Lift a phi instruction, lifting all subexpressions."""
        return Phi(self._lifter.lift(phi.dest, parent=phi), [self._lifter.lift(op, parent=phi) for op in phi.src])

    def lift_mem_phi(self, phi: MediumLevelILMemPhi, **kwargs) -> MemPhi:
        """Lift Binary Ninja's memory phi function.

        Binja's mem_phi actually relates to several aliased variables.
        Hence, we save all info from mem_phi in MemPhi class, so that later we can generate a separate Phi function
        for each involved aliased variable.
        :param  phi -- mem#x = phi(mem#y,...,mem#z)
        """
        destination_memory_version: Variable = Variable("mem", ssa_label=phi.dest_memory)
        source_memory_versions: List[Variable] = [(Variable("mem", ssa_label=version)) for version in phi.src_memory]
        return MemPhi(destination_memory_version, source_memory_versions)
