"""Module implementing the ConstantHandler for the binaryninja frontend."""
from binaryninja import BinaryView, PointerType, SymbolType, Type, VoidType, mediumlevelil
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import Constant, GlobalVariable, Integer, OperationType, Symbol, UnaryOperation


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
                    - is the definition of NULL in C, therefore a separate case (otherwise elf/dos header lifting)
                2. Address has datavariable with a basic type (everything except void/void*)
                    - lift as datavariable
                3. Address has a symbol, which is not a datasymbol
                    - lift as symbol
                4. Address has a function there 
                    - lift the function symbol as symbol
                5. Address has a datasymbol or void/void* datavariable or None there 
                    - lift as char* if there is a string, otherwise as void* with raw bytes (if the datavariable was a ptr, lift as &ptr*, otherwise as ptr*)

                    - there were symbols which call them self recursively, therefore a small check before the end
        """
        view = pointer.function.view

        if pointer.constant == 0:
            return Constant(pointer.constant, vartype=Integer.uint64_t() if view.address_size == 8 else Integer.uint32_t())

        if (variable := view.get_data_var_at(pointer.constant)) and not (isinstance(variable.type, PointerType) and isinstance(variable.type.target, VoidType)):
            return self._lifter.lift(variable, view=view, parent=pointer)

        if (symbol := view.get_symbol_at(pointer.constant)) and symbol.type != SymbolType.DataSymbol:
            return self._lifter.lift(symbol)

        if function := view.get_function_at(pointer.constant):
            return self._lifter.lift(function.symbol)

        var_ref_string = (view.get_string_at(variable.value, True) or view.get_ascii_string_at(variable.value, min_length=2)) if variable and variable.value else None
        var_ref_value = view.get_data_var_at(variable.value) if variable and variable.value else None

        if var_ref_value and pointer.constant == var_ref_value.address: # Recursive ptr to itself (0x4040 := 0x4040), lift symbol if there, else just make a data_addr symbol
            data_symbol =  view.get_symbol_at(variable.value)
            var_ref_value = data_symbol if data_symbol else Symbol("data_" + f"{pointer.constant:x}", pointer.constant, vartype=Integer.uint32_t())    

        g_var = GlobalVariable(
            name=symbol.name[:-2] + "_" + view.get_sections_at(variable.address)[0].name[1:] if symbol and symbol.name.find(".0") != -1 \
                else symbol.name if symbol else "data_" + f"{pointer.constant:x}",
            vartype=self._lifter.lift(Type.pointer(view.arch, Type.char())) if var_ref_string else self._lifter.lift(Type.pointer(view.arch, Type.void())),
            ssa_label=pointer.ssa_memory_version if pointer else 0,
            initial_value=self._lifter.lift(var_ref_value, view=view, parent=pointer) if var_ref_value else Constant(var_ref_string.value) \
            if var_ref_string else self._get_raw_bytes(view, pointer.constant)
        ) 

        return UnaryOperation(OperationType.address,[g_var]) if variable is not None and isinstance(variable.type, PointerType) else g_var


    def _get_raw_bytes(self, view: BinaryView, addr: int) -> bytes:
        """ Returns raw bytes after a given address to the next data structure or section"""
        if (next_data_var := view.get_next_data_var_after(addr)) is not None:
            return view.read(addr, next_data_var.address - addr)
        else:
            return view.read(addr, view.get_sections_at(addr)[0].end)
