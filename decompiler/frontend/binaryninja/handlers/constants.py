"""Module implementing the ConstantHandler for the binaryninja frontend."""
from binaryninja import mediumlevelil, BinaryView
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import Constant, Integer, GlobalVariable


class ConstantHandler(Handler):
    def register(self):
        """Register the handler at its parent lifter."""
        self._lifter.HANDLERS.update(
            {
                mediumlevelil.MediumLevelILConst: self.lift_constant,
                mediumlevelil.MediumLevelILFloatConst: self.lift_constant,
                mediumlevelil.MediumLevelILExternPtr: self.lift_constant_pointer,
                mediumlevelil.MediumLevelILConstPtr: self.lift_constant_pointer,
                mediumlevelil.MediumLevelILImport: self.lift_constant_pointer,
                int: self.lift_integer_literal,
            }
        )

    def lift_constant(self, constant: mediumlevelil.MediumLevelILConst, **kwargs) -> Constant:
        """Lift the given constant value."""
        return Constant(constant.constant, vartype=self._lifter.lift(constant.expr_type))

    @staticmethod
    def lift_integer_literal(value: int, **kwargs) -> Constant:
        """Lift the given literal, which is most likely an artefact from shift operations and the like."""
        return Constant(value, vartype=Integer.int32_t())

    def lift_constant_pointer(self, pointer: mediumlevelil.MediumLevelILConstPtr, **kwargs) -> Constant:
        """Lift the given constant pointer, e.g. &0x80000."""
        view = pointer.function.view
        if pointer.constant == 0: # nullptr check
            return Constant(0, vartype=Integer.uint64_t() if view.address_size == 8 else Integer.uint32_t())
        if variable := view.get_data_var_at(pointer.constant):
            return self._lifter.lift(variable, view=view, parent=pointer)
        if symbol := view.get_symbol_at(pointer.constant):
            return self._lifter.lift(symbol, view=view, parent=pointer)

        string = view.get_string_at(pointer.constant, partial=True) or view.get_ascii_string_at(pointer.constant, min_length=2)
        if string:
            return Constant(pointer.constant, vartype=self._lifter.lift(pointer.expr_type), pointee=Constant(string.value))
        else:
            return GlobalVariable("data_" + f"{variable.address:x}",
            vartype=self._lifter.lift(view.parse_type_string("char*")[0]), # cast to char*, because symbol does not have a type 
            ssa_label=pointer.ssa_memory_version if pointer else 0, # give correct ssa_label if there is one
            initial_value=self._get_raw_bytes(view, variable.address)
            )

    def _get_raw_bytes(self, view: BinaryView, addr: int) -> bytes:
        """ Returns raw bytes after a given address to the next data structure (or section)"""
        if next_data_var := view.get_next_data_var_after(addr):
            return view.read(addr, next_data_var.address - addr)
        else:
            return view.read(addr, view.get_sections_at(addr)[0].end)