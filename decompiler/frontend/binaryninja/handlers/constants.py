"""Module implementing the ConstantHandler for the binaryninja frontend."""
from binaryninja import mediumlevelil, BinaryView, SymbolType
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import Constant, Integer, GlobalVariable, Symbol


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
        """Lift the given constant pointer, e.g. &0x80000.

            For clarity all cases:
                1. NULL (&0x0)
                    - is the definition of NULL in C, therefore a seperate case (otherwise elf/dos header lifting)
                2. Address has datavariable with non void type (pointer/void pointer are allowed)
                    - lift via datavariable
                3. Adress has a datavariable with void type, but a 'Symbol' with type 'DataSymbol'
                    - lift via datavariable (into char*/void*)
                4. Adress has a symbol there (not 'DataSymbol' type)
                    - lift via symbol
                5. Adress has no symbol and the datavariable has type void
                    - lift as void* data_addr
        """
        view = pointer.function.view
        symbol = view.get_symbol_at(pointer.constant)
        variable = view.get_data_var_at(pointer.constant)

        if pointer.constant == 0:
            return Constant(0, vartype=Integer.uint64_t() if view.address_size == 8 else Integer.uint32_t())

        if variable or (symbol and symbol.type == SymbolType.DataSymbol):
            return self._lifter.lift(variable, view=view, parent=pointer)

        if symbol:
            return self._lifter.lift(symbol)

        return GlobalVariable("data_" + f"{variable.address:x}",
            vartype=self._lifter.lift(view.parse_type_string("void*")[0]),
            ssa_label=pointer.ssa_memory_version if pointer else 0,
            initial_value=self._get_raw_bytes(view, variable.address)
        )

    def _get_raw_bytes(self, view: BinaryView, addr: int) -> bytes:
        """Returns raw bytes after a given address to the next data structure or section"""
        if next_data_var := view.get_next_data_var_after(addr):
            return view.read(addr, next_data_var.address - addr)
        return view.read(addr, view.get_sections_at(addr)[0].end)