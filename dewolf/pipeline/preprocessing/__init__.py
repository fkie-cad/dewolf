"""Module containing all stages of the preprocessing pipeline."""

from .coherence import Coherence
from .compiler_idiom_handling import CompilerIdiomHandling
from .mem_phi_conversion import MemPhiConverter
from .missing_definitions import InsertMissingDefinitions
from .phi_predecessors import PhiFunctionFixer
from .register_pair_handling import RegisterPairHandling
from .remove_stack_canary import RemoveStackCanary
from .switch_variable_detection import BackwardSliceSwitchVariableDetection as SwitchVariableDetection
