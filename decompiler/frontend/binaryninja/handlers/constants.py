"""Module implementing the ConstantHandler for the binaryninja frontend."""
import math
from typing import Optional, Union

from binaryninja import BinaryView, DataVariable, FunctionType, PointerType, SectionSemantics, SymbolType, Type, VoidType, mediumlevelil
from decompiler.frontend.lifter import Handler
from decompiler.structures.pseudo import (
    Constant,
    GlobalVariable,
    ImportedFunctionSymbol,
    Integer,
    NotUseableConstant,
    OperationType,
    Pointer,
    StringSymbol,
    Symbol,
    UnaryOperation,
)


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

    def lift_constant(self, constant: mediumlevelil.MediumLevelILConst, **kwargs) -> Union[NotUseableConstant, Constant]:
        """Lift the given constant value."""
        if(constant.constant in [math.inf, -math.inf, math.nan]):
            return NotUseableConstant(str(constant.constant))
        return Constant(constant.constant, vartype=self._lifter.lift(constant.expr_type))

    @staticmethod
    def lift_integer_literal(value: int, **kwargs) -> Constant:
        """Lift the given literal, which is most likely an artefact from shift operations and the like."""
        return Constant(value, vartype=Integer.int32_t())

    def lift_constant_pointer(self, pointer: mediumlevelil.MediumLevelILConstPtr, **kwargs) -> Union[Constant, StringSymbol, UnaryOperation, GlobalVariable]:
        """Lift the given constant pointer, e.g. &0x80000.
            For clarity all cases:
                1. Address is not in a section
                    - bninja type error, bninja wants the constant value instead of the address (and NULL case: &0x00)
                2. Address is a constant read only string
                    - lift as StringSymbol right into code (without pointer; purge NULL byte)
                3. Address is a external function pointer
                    - lift as ImportedFunctionSymbol right into code
                4. Address has datavariable with a basic type (everything except void/void*)
                    - lift as datavariable
                5. Address has a symbol, which is not a datasymbol
                    - lift as symbol
                6. Address has a function there 
                    - lift the function symbol as symbol
                7. Lift as raw address
        """
        view = pointer.function.view

        if not self._addr_in_section(view, pointer.constant):
            return Constant(pointer.constant, vartype=Integer(view.address_size*8, False))

        if string_variable := self._get_read_only_string_data_var(view, pointer.constant):
            return StringSymbol(str(string_variable.value)[2:-1].rstrip("\\x00"), string_variable.address, vartype=Pointer(Integer.char(), view.address_size * 8))

        if (variable := view.get_data_var_at(pointer.constant)) and isinstance(variable.type, PointerType) and isinstance(variable.type.target, FunctionType):
            return ImportedFunctionSymbol(variable.name, variable.address, vartype=Pointer(Integer.char(),  view.address_size * 8))

        if variable and not (isinstance(variable.type, PointerType) and isinstance(variable.type.target, VoidType)):
            return self._lifter.lift(variable, view=view, parent=pointer)

        if (symbol := view.get_symbol_at(pointer.constant)) and symbol.type != SymbolType.DataSymbol:
            return self._lifter.lift(symbol)

        if function := view.get_function_at(pointer.constant):
            return self._lifter.lift(function.symbol)

        return self.lift_const_addr(view, pointer)

  
    def lift_const_addr(self, view: BinaryView, pointer : mediumlevelil.MediumLevelILConstPtr):
        """Lift a raw address:
            - lift as char* if there is a string, otherwise as void* with raw bytes (if the datavariable was a ptr, lift as &ptr*, otherwise as ptr*)
            - there were symbols which call them self recursively, therefore a small check before the end
        """
        variable = view.get_data_var_at(pointer.constant)
        symbol = view.get_symbol_at(pointer.constant)

        var_ref_string = (view.get_string_at(variable.value, True) or view.get_ascii_string_at(variable.value, min_length=2)) if variable and variable.value else None
        var_ref_value = view.get_data_var_at(variable.value) if variable and variable.value else None

        if var_ref_value and pointer.constant == var_ref_value.address: # Recursive ptr to itself (0x4040 := 0x4040), lift symbol if there, else just make a data_addr symbol
            data_symbol =  view.get_symbol_at(variable.value)
            var_ref_value = data_symbol if data_symbol else Symbol("data_" + f"{pointer.constant:x}", pointer.constant, vartype=Integer.uint32_t())    

        g_var = GlobalVariable(
            name=symbol.name[:-2] if symbol and symbol.name.find(".0") != -1 else symbol.name if symbol else "data_" + f"{pointer.constant:x}",
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


    def _addr_in_section(self, view: BinaryView, addr: int) -> bool:
        """Returns True if address is contained in a section, False otherwise"""
        for _, section in view.sections.items():
            if addr >= section.start and addr <= section.end:
                return True
        return False


    def _in_read_only_section(self, view: BinaryView, addr: int) -> bool:
        """Returns True if address is contained in a read only section, False otherwise"""
        for _, section in view.sections.items():
            if addr >= section.start and addr <= section.end and section.semantics == SectionSemantics.ReadOnlyDataSectionSemantics:
                return True
        return False

    def _get_read_only_string_data_var(self, view: BinaryView, addr: int) -> Optional[DataVariable]:
        """Return a read only string datavariable which should be propagated into the code."""
        data_var = view.get_data_var_at(addr)
        if data_var and not isinstance(data_var.value, bytes):
            return None
        if not self._in_read_only_section(view, addr):
            return None    
        data_var = DataVariable(view, addr, Type.array(Type.char(), len(self._get_raw_bytes(view, addr))), False)
        try:
            data_var.value.decode("utf-8")
        except UnicodeDecodeError:
            return None

        return data_var
