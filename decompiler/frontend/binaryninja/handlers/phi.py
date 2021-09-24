from typing import List

from binaryninja import MediumLevelILVar_phi, MediumLevelILMem_phi

from dewolf.frontend.lifter import Handler
from dewolf.structures.pseudo import Variable, Phi, MemPhi


class PhiHandler(Handler):
    def register(self):
        self._lifter.HANDLERS.update(
            {
                MediumLevelILVar_phi: self.lift_phi,
                MediumLevelILMem_phi: self.lift_mem_phi,
            }
        )

    def lift_phi(self, phi: MediumLevelILVar_phi, **kwargs) -> Phi:
        """Lift a phi instruction, lifting all subexpressions."""
        return Phi(self._lifter.lift(phi.dest, parent=phi), [self._lifter.lift(op, parent=phi) for op in phi.src])

    def lift_mem_phi(self, phi: MediumLevelILMem_phi, **kwargs) -> MemPhi:
        """Lift Binary Ninja's memory phi function.

        Binja's mem_phi actually relates to several aliased variables.
        Hence, we save all info from mem_phi in MemPhi class, so that later we can generate a separate Phi function
        for each involved aliased variable.
        :param  phi -- mem#x = phi(mem#y,...,mem#z)
        """
        destination_memory_version: Variable = Variable("mem", ssa_label=phi.dest_memory)
        source_memory_versions: List[Variable] = [(Variable("mem", ssa_label=version)) for version in phi.src_memory]
        return MemPhi(destination_memory_version, source_memory_versions)
