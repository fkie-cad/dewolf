"""Module implementing the lifter for the binaryninja backend."""
from logging import error, warning
from math import log2
from typing import List, Optional, Tuple, Union

from binaryninja import BinaryView, FunctionParameter, MediumLevelILInstruction, MediumLevelILOperation, SSAVariable
from binaryninja import Symbol as bSymbol
from binaryninja import SymbolType
from binaryninja import Type as bType
from binaryninja import TypeClass
from binaryninja import Variable as bVariable
from decompiler.frontend.lifter import Lifter
from decompiler.structures.pseudo import (
    Assignment,
    BinaryOperation,
    Branch,
    Call,
    Condition,
    Constant,
    CustomType,
    DataflowObject,
    Expression,
    Float,
    FunctionSymbol,
    GlobalVariable,
    ImportedFunctionSymbol,
    IndirectBranch,
    Integer,
    IntrinsicSymbol,
    ListOperation,
    MemPhi,
    Operation,
    OperationType,
    Phi,
    Pointer,
    RegisterPair,
    Return,
    Symbol,
    Tag,
    Type,
    UnaryOperation,
    UnknownExpression,
    Variable,
)

BYTE_SIZE = int(log2(256))  # A byte is the amount of bits utilized to represent 256
LITTLE_ENDIAN = "little"
BIG_ENDIAN = "big"


class BinaryninjaLifter(Lifter):
    """Lifter class for binaryninja medium level intermediate language."""

    OPERATIONS = {
        MediumLevelILOperation.MLIL_ADD: OperationType.plus,
        MediumLevelILOperation.MLIL_ADC: OperationType.plus,
        MediumLevelILOperation.MLIL_FADD: OperationType.plus_float,
        MediumLevelILOperation.MLIL_SUB: OperationType.minus,
        MediumLevelILOperation.MLIL_FSUB: OperationType.minus_float,
        MediumLevelILOperation.MLIL_SBB: OperationType.plus,
        MediumLevelILOperation.MLIL_MUL: OperationType.multiply,
        MediumLevelILOperation.MLIL_MULU_DP: OperationType.multiply_us,
        MediumLevelILOperation.MLIL_MULS_DP: OperationType.multiply,
        MediumLevelILOperation.MLIL_FMUL: OperationType.multiply_float,
        MediumLevelILOperation.MLIL_NEG: OperationType.negate,
        MediumLevelILOperation.MLIL_NOT: OperationType.logical_not,
        MediumLevelILOperation.MLIL_AND: OperationType.bitwise_and,
        MediumLevelILOperation.MLIL_OR: OperationType.bitwise_or,
        MediumLevelILOperation.MLIL_XOR: OperationType.bitwise_xor,
        MediumLevelILOperation.MLIL_LSL: OperationType.left_shift,
        MediumLevelILOperation.MLIL_ASR: OperationType.right_shift,
        MediumLevelILOperation.MLIL_LSR: OperationType.right_shift_us,
        MediumLevelILOperation.MLIL_DIVU: OperationType.divide_us,
        MediumLevelILOperation.MLIL_DIVU_DP: OperationType.divide_us,
        MediumLevelILOperation.MLIL_DIVS: OperationType.divide,
        MediumLevelILOperation.MLIL_DIVS_DP: OperationType.divide,
        MediumLevelILOperation.MLIL_FDIV: OperationType.divide_float,
        MediumLevelILOperation.MLIL_MODU: OperationType.modulo_us,
        MediumLevelILOperation.MLIL_MODU_DP: OperationType.modulo_us,
        MediumLevelILOperation.MLIL_MODS: OperationType.modulo,
        MediumLevelILOperation.MLIL_MODS_DP: OperationType.modulo,
        MediumLevelILOperation.MLIL_ROL: OperationType.left_rotate,
        MediumLevelILOperation.MLIL_ROR: OperationType.right_rotate,
        MediumLevelILOperation.MLIL_ZX: OperationType.cast,
        MediumLevelILOperation.MLIL_SX: OperationType.cast,
        MediumLevelILOperation.MLIL_ADDRESS_OF: OperationType.address,
        MediumLevelILOperation.MLIL_LOAD_SSA: OperationType.dereference,
    }

    CONDITIONS = {
        MediumLevelILOperation.MLIL_CMP_E: OperationType.equal,
        MediumLevelILOperation.MLIL_CMP_NE: OperationType.not_equal,
        MediumLevelILOperation.MLIL_CMP_SLT: OperationType.less,
        MediumLevelILOperation.MLIL_CMP_ULT: OperationType.less_us,
        MediumLevelILOperation.MLIL_CMP_SLE: OperationType.less_or_equal,
        MediumLevelILOperation.MLIL_CMP_ULE: OperationType.less_or_equal_us,
        MediumLevelILOperation.MLIL_CMP_SGE: OperationType.greater_or_equal,
        MediumLevelILOperation.MLIL_CMP_UGE: OperationType.greater_or_equal_us,
        MediumLevelILOperation.MLIL_CMP_SGT: OperationType.greater,
        MediumLevelILOperation.MLIL_CMP_UGT: OperationType.greater_us,
    }

    ALIASED = {
        MediumLevelILOperation.MLIL_SET_VAR_ALIASED,
        MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD,
        MediumLevelILOperation.MLIL_VAR_ALIASED,
        MediumLevelILOperation.MLIL_VAR_ALIASED_FIELD,
    }

    def __init__(self, no_masks: bool = True):
        self._no_masks = no_masks

    def lift(self, liftee: Union[bVariable, SSAVariable, MediumLevelILInstruction], **kwargs) -> Expression:
        """Invoke the lift handler for the given object."""
        handler = self.HANDLERS.get(type(liftee), BinaryninjaLifter.report_error)
        return handler(self, liftee, **kwargs)

    def lift_variable(self, variable: bVariable, parent: Optional[MediumLevelILInstruction] = None) -> Variable:
        """
        Lift an normal variable. Interpolating the ssa-version from the parents memory version.

        keyword args:
        parent -- the parent instruction to deduce an ssa version
        """
        memory_version = parent.ssa_memory_version if parent and hasattr(parent, "ssa_memory_version") else 0
        var = Variable(variable.name, vartype=self.lift_type(variable.type), ssa_label=memory_version)
        var.is_aliased = True
        return var

    def lift_variable_ssa(self, ssa_var: SSAVariable, is_aliased=False, **kwargs) -> Variable:
        """
        Lift an ssa variable.

        keyword args:
        is_aliased -- whether the variable should be marked as aliased based on the context it was lifted in.
        """
        var = Variable(ssa_var.var.name, vartype=self.lift_type(ssa_var.var.type), ssa_label=ssa_var.version)
        var.is_aliased = is_aliased
        return var

    def lift_expression(self, instruction: MediumLevelILInstruction, **kwargs) -> Optional[DataflowObject]:
        """Lift the given Binaryninja instruction to an expression."""
        handler = self.TRANSLATORS.get(instruction.operation, BinaryninjaLifter._lift_unknown)
        if expression := handler(self, instruction, **kwargs):
            expression.tags = self.lift_tags(instruction)
            return expression
        return None

    def lift_tags(self, instruction: MediumLevelILInstruction) -> Tuple[Tag, ...]:
        """Lift the Tags of the given Binaryninja instruction"""
        if function := instruction.function:
            binja_tags = function.source_function.view.get_data_tags_at(instruction._address)
            return tuple(Tag(tag.type.name, tag.data) for tag in binja_tags)
        else:
            warning(f"Cannot lift tags for instruction because binary view cannot be accessed.")
            return ()

    def lift_type(self, basetype: bType, **kwargs) -> Type:
        """Translate the given binaryninja type to a pseudo type."""
        if not basetype:
            return CustomType.void()
        if basetype.type_class in [TypeClass.PointerTypeClass, TypeClass.ArrayTypeClass]:
            return Pointer(self.lift_type(basetype.target), basetype.width * BYTE_SIZE)
        if basetype.type_class == TypeClass.FunctionTypeClass:
            return self.lift_type(basetype.target)
        return self.TYPES.get(basetype.type_class, lambda x: CustomType(str(basetype), basetype.width))(basetype)

    def lift_function_parameter(self, parameter: FunctionParameter, **kwargs) -> Variable:
        return Variable(parameter.name, self.lift_type(parameter.type), ssa_label=None)

    """Functions dedicated to lifting MLIL instructructions."""

    def _lift_unknown(self, instruction: MediumLevelILInstruction, **kwargs) -> UnknownExpression:
        """Lift a unknown/invalid instruction returned by Binaryninja."""
        view = instruction.function.source_function.view
        warning(
            f"Lifting for {str(instruction.operation)} operations has not been implemented emitting an UnknownExpression for {instruction} instead."
        )
        return UnknownExpression(str(view.get_disassembly(instruction.address)))

    def _lift_nop(self, _: MediumLevelILInstruction, **kwargs) -> None:
        """Return no instruction at all (used for nop, goto, etc.)"""
        return None

    def _lift_variable_operation(self, instruction: MediumLevelILInstruction, **kwargs) -> Variable:
        """Lift the given variable expression."""
        return self.lift(instruction.src, parent=instruction, is_aliased=instruction.operation in self.ALIASED)

    def _lift_constant(self, instruction: MediumLevelILInstruction, **kwargs) -> Constant:
        """Lift the given constant value."""
        bv = instruction.function.source_function.view
        address: int = instruction.constant
        if isinstance(address, int) and (string := bv.get_string_at(address)):
            return Constant(address, Pointer(Integer.char()), Constant(string.value, Integer.char()))
        return Constant(address, vartype=self.lift_type(instruction.expr_type))

    def _lift_constant_pointer(
        self, instruction: MediumLevelILInstruction, **kwargs
    ) -> Union[Constant, GlobalVariable, FunctionSymbol, ImportedFunctionSymbol]:
        """Lift a constant pointer."""
        bv: BinaryView = instruction.function.source_function.view
        address: int = instruction.constant  # Retrieve the dst addr
        if address == 0:
            # TODO: hack - Binja thinks that 0 is a null pointer, even though it may be just integer 0.
            return Constant(0, vartype=Integer.uint64_t() if bv.address_size == 8 else Integer.uint32_t())

        if symbol := self._get_symbol(instruction):
            if symbol.type == SymbolType.FunctionSymbol:
                return FunctionSymbol(symbol.name, address, vartype=Pointer(Integer.char()))
            if symbol.type in (SymbolType.ImportedFunctionSymbol, SymbolType.ExternalSymbol):
                return ImportedFunctionSymbol(symbol.name, address, vartype=Pointer(Integer.char()))
            return self._lift_global_variable(bv, None, address)

        if string := bv.get_string_at(address, partial=True) or bv.get_ascii_string_at(address, min_length=2):
            return Constant(address, Pointer(Integer.char()), Constant(string.value, Integer.char()))

        return self._lift_constant(instruction)

    def _lift_global_variable(self, bv: BinaryView, parent_addr: int, addr: int) -> Union[Constant, GlobalVariable, Symbol, UnaryOperation]:
        """Lift a global variable."""
        if (variable := bv.get_data_var_at(addr)) is None:
            if string := bv.get_string_at(addr):
                return Constant(addr, Pointer(Integer.char()), Constant(string.value, Integer.char()))
            # TODO: hack - Binja thinks that 0 is a null pointer, even though it may be just integer 0. Thus we lift this as a NULL Symbol
            if self._get_pointer(bv, addr) == 0:
                return Symbol("NULL", 0)
            # return as raw bytes for now.
            return Constant(addr, Pointer(Integer.char()), Constant(self._get_bytes(bv, addr), Integer.char()))
        variable_name = self._get_global_var_name(bv, addr)
        vartype = self.lift_type(variable.type)
        if "jump_table" in variable_name:
            # TODO: hack - otherwise the whole jumptable is set as initial_value
            return UnaryOperation(
                OperationType.address,
                [GlobalVariable(variable_name, ssa_label=0, vartype=vartype, initial_value=addr)],
                vartype=Pointer(vartype),
            )
        if parent_addr == addr:
            # We have cases like:
            # void* __dso_handle = __dso_handle
            # Prevent unlimited recursion and return the pointer.
            vartype = Integer.uint64_t() if bv.address_size == 8 else Integer.uint32_t()
            return GlobalVariable(variable_name, vartype=vartype, ssa_label=0, initial_value=addr)

        # Retrieve the initial value of the global variable if there is any
        type_tokens = [t.text for t in variable.type.tokens]
        if variable.type == variable.type.void():
            # If there is no type, just retrieve all the bytes from the current to the next address where a data variable is present.
            initial_value = self._get_bytes(bv, addr)
        elif variable.type.type_class == TypeClass.IntegerTypeClass:
            initial_value = self._get_integer(bv, addr, variable.type.width)
        else:
            # If pointer type, convert indirect_pointer to a label, otherwise leave it as it is.
            if "*" in type_tokens:
                indirect_ptr_addr = self._get_pointer(bv, addr)
                initial_value = self._lift_global_variable(bv, addr, indirect_ptr_addr)
            else:
                initial_value = bv.read(addr, variable.type.width)
        # Create the global variable.
        # Convert all void and void* to char*
        if "void" in type_tokens:
            vartype = self.lift_type(bv.parse_type_string("char*")[0])
        return UnaryOperation(
            OperationType.address,
            [GlobalVariable(variable_name, vartype=vartype, ssa_label=0, initial_value=initial_value)],
            vartype=Pointer(vartype),
        )

    def _get_global_var_name(self, bv: BinaryView, addr: int) -> str:
        """Get a name for the GlobalVariable."""
        if (symbol := bv.get_symbol_at(addr)) is not None:
            name = symbol.name.replace(".", "_")  # If there is an existing symbol, use it as the name
            if symbol.type == SymbolType.ImportAddressSymbol:
                # In Binja, ImportAddressSymbol will always reference a DataSymbol of the same name
                # To prevent name conflicts, we add a _1 to the name to make it a different variable.
                name += "_1"
            return name
        return f"data_{addr:x}"

    def _get_bytes(self, bv: BinaryView, addr: int) -> bytes:
        """Given an address, retrive all bytes from the current data point to the next data point."""
        next_data_var_addr = None
        next_data_var = bv.get_next_data_var_after(addr)
        if next_data_var is not None:
            next_data_var_addr = next_data_var.address
        # No data point after this, so read till the end of this section instead.
        else:
            next_data_var_addr = bv.get_sections_at(addr)[0].end
        num_bytes = next_data_var_addr - addr
        return bv.read(addr, num_bytes)

    def _get_pointer(self, bv: BinaryView, addr: int) -> int:
        """Retrieve and convert a value at an address from bytes to an integer."""
        raw_value = bv.read(addr, bv.arch.address_size)
        return int.from_bytes(raw_value, LITTLE_ENDIAN if bv.endianness.value == 0 else BIG_ENDIAN)

    def _get_integer(self, bv: BinaryView, addr: int, size: int) -> int:
        """Retrieve and convert a value at an address from bytes to an integer specified size."""
        raw_value = bv.read(addr, size)
        return int.from_bytes(raw_value, LITTLE_ENDIAN if bv.endianness.value == 0 else BIG_ENDIAN)

    def _lift_binary_operation(self, instruction: MediumLevelILInstruction, **kwargs) -> BinaryOperation:
        """Lift all binary expressions directly."""
        return BinaryOperation(
            self.OPERATIONS[instruction.operation],
            [self.lift(x, parent=instruction) for x in instruction.operands],
            vartype=self.lift_type(instruction.expr_type),
        )

    def _lift_zx_operation(self, instruction: MediumLevelILInstruction, **kwargs) -> UnaryOperation:
        """Lift zero-extension operation."""
        inner = self.lift(instruction.operands[0], parent=instruction)
        if isinstance(inner.type, Integer) and inner.type.is_signed:
            unsigned_type = Integer(size=inner.type.size, signed=False)
            return UnaryOperation(
                self.OPERATIONS[instruction.operation],
                [UnaryOperation(OperationType.cast, [inner], unsigned_type)],
                vartype=self.lift_type(instruction.expr_type),
            )
        return self._lift_unary_operation(instruction, **kwargs)

    def _lift_unary_operation(self, instruction: MediumLevelILInstruction, **kwargs) -> UnaryOperation:
        """Lift unary operations."""
        return UnaryOperation(
            self.OPERATIONS[instruction.operation],
            [self.lift(instruction.operands[0], parent=instruction)],
            vartype=self.lift_type(instruction.expr_type),
        )

    def _lift_assignment(self, instruction: MediumLevelILInstruction, **kwargs) -> Assignment:
        """Lift assignment operations (most instructions should end up here)."""
        return Assignment(
            self.lift(instruction.dest, parent=instruction, is_aliased=instruction.operation in self.ALIASED),
            self.lift(instruction.src, parent=instruction),
        )

    def _lift_branch(self, instruction: MediumLevelILInstruction) -> Branch:
        """Lift a branch instruction.. by lifting its condition."""
        condition = self.lift(instruction.condition, parent=instruction)
        if not isinstance(condition, Condition):
            condition = Condition(OperationType.not_equal, [condition, Constant(0, condition.type.copy())])
        return Branch(condition)

    def _lift_split_assignment(self, instruction: MediumLevelILInstruction, **kwargs) -> Assignment:
        """Lift an instruction writing to a register pair."""
        return Assignment(
            RegisterPair(
                high := self.lift(instruction.high, parent=instruction),
                low := self.lift(instruction.low, parent=instruction),
                vartype=high.type.resize((high.type.size + low.type.size)),
            ),
            self.lift(instruction.src, parent=instruction),
        )

    def _lift_split(self, instruction: MediumLevelILInstruction, **kwargs) -> RegisterPair:
        """Lift register pair expression"""
        return RegisterPair(
            high := self.lift(instruction.high, parent=instruction),
            low := self.lift(instruction.low, parent=instruction),
            vartype=high.type.resize((high.type.size + low.type.size)),
        )

    def _lift_call_parameter_names(self, instruction: MediumLevelILInstruction, **kwargs) -> List[str]:
        """Lift parameter names of call from type string of instruction.dest.expr_type"""
        clean_type_string_of_parameters = instruction.dest.expr_type.get_string_after_name().strip("()")
        parameter_names = [type_parameter.rsplit(" ", 1)[-1] for type_parameter in clean_type_string_of_parameters.split(",")]
        return parameter_names

    def _lift_call(self, instruction: MediumLevelILInstruction, **kwargs) -> Assignment:
        """Lift a call instruction, possibly returning values."""
        if isinstance(instruction.params, MediumLevelILInstruction):
            # Binaryninja returned an invalid parameter list
            parameters = []
        else:
            parameters = [self.lift(x, parent=instruction) for x in instruction.params]
        call = Call(
            self.lift(instruction.dest),
            parameters,
            vartype=self.lift_type(instruction.dest.expr_type),
            writes_memory=instruction.output.dest_memory,
            meta_data={
                "param_names": self._lift_call_parameter_names(instruction),
                "is_tailcall": True if instruction.operation == MediumLevelILOperation.MLIL_TAILCALL_SSA else False,
            },
        )
        if instruction.output.dest:
            return_values = ListOperation([self.lift(x, parent=instruction) for x in instruction.output.dest])
            return Assignment(return_values, call)
        return Assignment(ListOperation([]), call)

    def _lift_return(self, instruction: MediumLevelILInstruction, **kwargs) -> Return:
        """Lift a return instruction."""
        return Return([self.lift(x, parent=instruction) for x in instruction.src])

    def _lift_phi(self, instruction: MediumLevelILInstruction, **kwargs) -> Phi:
        """Lift a phi instruction, lifting all subexpressions."""
        return Phi(self.lift(instruction.dest, parent=instruction), [self.lift(x, parent=instruction) for x in instruction.src])

    def _lift_mem_phi(self, instruction: MediumLevelILInstruction, **kwargs) -> MemPhi:
        """Lift Binary Ninja's memory phi function.

        Binja's mem_phi actually relates to several aliased variables.
        Hence, we save all info from mem_phi in MemPhi class, so that later we can generate a separate Phi function
        for each involved aliased variable.
        :param  instruction -- mem#x = phi(mem#y,...,mem#z)
        """
        destination_memory_version: Variable = Variable("mem", ssa_label=instruction.dest_memory)
        source_memory_versions: List[Variable] = [(Variable("mem", ssa_label=version)) for version in instruction.src_memory]
        return MemPhi(destination_memory_version, source_memory_versions)

    def _lift_condition(self, instruction: MediumLevelILInstruction, **kwargs) -> Condition:
        """Lift an expression evaluating to a boolean value."""
        return Condition(
            self.CONDITIONS[instruction.operation],
            [self.lift(instruction.left, parent=instruction), self.lift(instruction.right, parent=instruction)],
        )

    def _lift_cast(self, instruction: MediumLevelILInstruction, **kwargs) -> UnaryOperation:
        """Lift a cast operation, casting one type to another."""
        return UnaryOperation(
            OperationType.cast, [self.lift(instruction.src, parent=instruction)], vartype=self.lift_type(instruction.expr_type)
        )

    def _lift_ftrunc(self, instruction: MediumLevelILInstruction, **kwargs) -> Call:
        """Lift a MLIL_FTRUNC operation."""
        parameters = [self.lift(instruction.src)]
        call = Call(
            IntrinsicSymbol("trunc"),
            parameters,
        )
        return Assignment(ListOperation([]), call)

    def _lift_write_memory(self, instruction: MediumLevelILInstruction, **kwargs) -> Assignment:
        """Lift a write access to a memory location."""
        return Assignment(
            UnaryOperation(
                OperationType.dereference,
                [op := self.lift(instruction.dest, parent=instruction)],
                vartype=op.type,
                writes_memory=instruction.dest_memory,
            ),
            self.lift(instruction.src, parent=instruction),
        )

    def _lift_load_struct_ssa(self, instruction: MediumLevelILInstruction, **kwargs) -> UnaryOperation:
        """Lift a MLIL_LOAD_STRUCT_SSA instruction."""
        base = UnaryOperation(OperationType.cast, [self.lift(instruction.src)], vartype=Pointer(Integer.char()))
        offset = Constant(instruction.offset)
        vartype = self.lift_type(instruction.src.expr_type)
        return UnaryOperation(
            OperationType.dereference,
            [
                BinaryOperation(OperationType.plus, [base, offset], vartype=vartype),
            ],
            vartype=Pointer(vartype),
        )

    def _lift_store_struct_ssa(self, instruction: MediumLevelILInstruction, **kwargs) -> Assignment:
        """Lift a MLIL_STORE_STRUCT_SSA instruction."""
        base = UnaryOperation(OperationType.cast, [self.lift(instruction.dest)], vartype=Pointer(Integer.char()))
        offset = Constant(instruction.offset)
        vartype = self.lift_type(instruction.dest.expr_type)
        lhs = UnaryOperation(
            OperationType.dereference,
            [
                BinaryOperation(OperationType.plus, [base, offset], vartype=vartype),
            ],
            vartype=Pointer(vartype),
        )
        rhs = self.lift(instruction.src)
        return Assignment(lhs, rhs)

    def _lift_address_of_field(self, instruction: MediumLevelILInstruction, **kwargs) -> UnaryOperation:
        """Lift a MLIL_ADDRESS_OF_FIELD instruction."""
        base = UnaryOperation(OperationType.cast, [self.lift(instruction.src)], vartype=Pointer(Integer.char()))
        offset = Constant(instruction.offset)
        vartype = self.lift_type(instruction.expr_type)
        return UnaryOperation(
            OperationType.address,
            [
                BinaryOperation(OperationType.plus, [base, offset], vartype=vartype),
            ],
            vartype=Pointer(vartype),
        )

    def _lift_test_bit(self, instruction: MediumLevelILInstruction, **kwargs):
        """Lift a MLIL_TEST_BIT instruction."""
        return BinaryOperation(
            OperationType.bitwise_and,
            [self.lift(x, parent=instruction) for x in instruction.operands],
            vartype=self.lift_type(instruction.expr_type),
        )

    def _lift_mask_high(self, instruction: MediumLevelILInstruction, **kwargs) -> BinaryOperation:
        """
        Lift an instruction masking the higher part of a value.
        e.g. eax.al = eax & 0x000000ff
        """
        return BinaryOperation(
            OperationType.bitwise_and,
            [op := self.lift(instruction.src), Constant(self._get_all_ones_mask_for_type(instruction.size))],
            vartype=op.type.resize(instruction.size * BYTE_SIZE),
        )

    def _lift_set_field(self, instruction: MediumLevelILInstruction, **kwargs) -> Assignment:
        """
        Lift an instruction writing to a subset of the given value.

        In case of lower register (offset 0) lift as contraction
        E.g. eax.al = .... <=> contraction(eax, vartype=char)

        In case higher registers use masking
        e.g. eax.ah = x <=> eax = (eax & 0xffff00ff) + (x << 2)
        """
        if not instruction.offset and self._no_masks:
            return self._lift_set_lower_register_field_as_contraction_assignment(instruction)

        mask = self._get_all_ones_mask_for_type(instruction.dest.var.type.width)
        mask -= self._get_all_ones_mask_for_type(instruction.size) << (instruction.offset * BYTE_SIZE)
        destination = self.lift(instruction.dest, parent=instruction, is_aliased=instruction.operation in self.ALIASED)
        value = self.lift(instruction.src, parent=instruction)
        if instruction.offset:
            value = BinaryOperation(OperationType.left_shift, [value, Constant(instruction.offset * BYTE_SIZE)], vartype=value.type)
        previous = self.lift(instruction.prev, parent=instruction, is_aliased=instruction.operation in self.ALIASED)
        return Assignment(
            destination,
            BinaryOperation(
                OperationType.bitwise_or,
                [BinaryOperation(OperationType.bitwise_and, [previous, Constant(mask)], vartype=value.type), value],
                vartype=destination.type,
            ),
        )

    def _lift_set_lower_register_field_as_contraction_assignment(self, instruction: MediumLevelILInstruction) -> Assignment:
        """
        We lift assignment to lower register part (offset 0 from register start) as contraction (cast)

        E.g.:
        eax.al = 10;
        becomes:
        (byte) eax = 10; // Assign(Cast([eax], byte, contraction=true), Constant(10))
        :param instruction: instruction of type MLIL_SET_VAR_FIELD
        """
        destination_operand = self.lift(instruction.dest, parent=instruction)
        contraction_type = destination_operand.type.resize(instruction.size * BYTE_SIZE)
        contraction = UnaryOperation(OperationType.cast, [destination_operand], vartype=contraction_type, contraction=True)
        return Assignment(contraction, self.lift(instruction.src, parent=instruction))

    def _lift_get_field(self, instruction: MediumLevelILInstruction, **kwargs) -> Operation:
        """
        Lift an instruction accessing a field from the outside.
        e.g. x = eax.ah <=> x = eax & 0x0000ff00
        """
        if not instruction.offset:
            source = self.lift(instruction.src, parent=instruction)
            cast_type = source.type.resize(instruction.size * BYTE_SIZE)
            return UnaryOperation(OperationType.cast, [self.lift(instruction.src, parent=instruction)], vartype=cast_type, contraction=True)
        mask: Constant = Constant(self._get_all_ones_mask_for_type(instruction.size) << instruction.offset)
        return BinaryOperation(
            OperationType.bitwise_and,
            [op := self.lift(instruction.src, parent=instruction), mask],
            vartype=op.type.resize(instruction.size * BYTE_SIZE),
        )

    def _get_all_ones_mask_for_type(self, type_size: int) -> int:
        """Generate a bit mask for the given type_size."""
        return int(2 ** (type_size * BYTE_SIZE) - 1)

    def report_error(self, liftee: object, **kwargs) -> None:
        """
        Report that we tried to lift an illegal object.
        -> The type passed was neither an MediumLevelILInstruction, nor a Variable.
        """
        error(f"Can not lift {liftee} of type {type(liftee)} (too heavy)!")

    def _lift_jump(self, instruction: MediumLevelILInstruction, **kwargs) -> IndirectBranch:
        """Lift a non-trivial jump instruction."""
        return IndirectBranch(self.lift(instruction.dest, parent=instruction))

    def _lift_binary_operation_with_carry(self, instruction: MediumLevelILInstruction, **kwargs) -> BinaryOperation:
        """Lift the adc assembler instruction as two nested BinaryOperations."""
        operands = [self.lift(x, parent=instruction) for x in instruction.operands]
        return BinaryOperation(
            self.OPERATIONS[instruction.operation],
            [operands[0], BinaryOperation(OperationType.plus, [operands[1], operands[2]])],
            vartype=operands[0].type,
        )

    def _lift_intrinsic_ssa(self, instruction: MediumLevelILInstruction, **kwargs) -> Assignment:
        """Lift MLIL_INTRINSIC_SSA e.g. temp0_1#2 = _mm_add_epi32(zmm1#2, zmm5#1) as call assignment"""
        operands = [self.lift(param) for param in instruction.params]
        return_values = ListOperation([self.lift(value) for value in instruction.output])
        function = IntrinsicSymbol(str(instruction.intrinsic))
        return Assignment(return_values, Call(function, operands))

    def _lift_unknown_operation(self, instruction: MediumLevelILInstruction, **kwargs) -> Call:
        """Return a function as a placeholder for an unknown operation."""
        warning(
            f"Could not lift the given {str(instruction.operation)} operation at {instruction.address}, emitting a function call instead"
        )
        operands = [self.lift(x, parent=instruction) for x in instruction.operands]
        return Call(FunctionSymbol(str(instruction.operation), instruction.address, Pointer(Integer.char())), operands)

    @staticmethod
    def _get_symbol(instruction: MediumLevelILInstruction) -> Optional[bSymbol]:
        bv: BinaryView = instruction.function.source_function.view
        address: int = instruction.value.value
        if symbol := bv.get_symbol_at(address):
            return symbol
        elif function := bv.get_function_at(address):
            return function.symbol
        return None

    HANDLERS = {
        MediumLevelILInstruction: lift_expression,
        SSAVariable: lift_variable_ssa,
        bVariable: lift_variable,
        bType: lift_type,
        FunctionParameter: lift_function_parameter,
    }

    TYPES = {
        TypeClass.IntegerTypeClass: lambda x: Integer(x.width * BYTE_SIZE, signed=x.signed.value),
        TypeClass.FloatTypeClass: lambda x: Float(x.width * BYTE_SIZE),
        TypeClass.VoidTypeClass: lambda x: CustomType.void(),
        TypeClass.BoolTypeClass: lambda x: CustomType.bool(),
    }

    TRANSLATORS = {
        MediumLevelILOperation.MLIL_NOP: _lift_nop,
        MediumLevelILOperation.MLIL_SET_VAR: _lift_assignment,
        # MediumLevelILOperation.MLIL_SET_VAR_FIELD: None,
        # MediumLevelILOperation.MLIL_SET_VAR_SPLIT: None,
        # MediumLevelILOperation.MLIL_LOAD: None,
        # MediumLevelILOperation.MLIL_LOAD_STRUCT: None,
        # MediumLevelILOperation.MLIL_STORE: None,
        # MediumLevelILOperation.MLIL_STORE_STRUCT: None,
        MediumLevelILOperation.MLIL_VAR: _lift_variable_operation,
        # MediumLevelILOperation.MLIL_VAR_FIELD: None,
        # MediumLevelILOperation.MLIL_VAR_SPLIT: None,
        MediumLevelILOperation.MLIL_ADDRESS_OF: _lift_unary_operation,
        MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD: _lift_address_of_field,
        MediumLevelILOperation.MLIL_CONST: _lift_constant,
        MediumLevelILOperation.MLIL_CONST_PTR: _lift_constant_pointer,
        # MediumLevelILOperation.MLIL_EXTERN_PTR: None,
        MediumLevelILOperation.MLIL_FLOAT_CONST: _lift_constant,
        MediumLevelILOperation.MLIL_IMPORT: _lift_constant_pointer,
        # Binary Operations
        MediumLevelILOperation.MLIL_ADD: _lift_binary_operation,
        MediumLevelILOperation.MLIL_ADC: _lift_binary_operation_with_carry,
        MediumLevelILOperation.MLIL_SUB: _lift_binary_operation,
        MediumLevelILOperation.MLIL_SBB: _lift_binary_operation_with_carry,
        MediumLevelILOperation.MLIL_AND: _lift_binary_operation,
        MediumLevelILOperation.MLIL_OR: _lift_binary_operation,
        MediumLevelILOperation.MLIL_XOR: _lift_binary_operation,
        MediumLevelILOperation.MLIL_LSL: _lift_binary_operation,
        MediumLevelILOperation.MLIL_LSR: _lift_binary_operation,
        MediumLevelILOperation.MLIL_ASR: _lift_binary_operation,
        MediumLevelILOperation.MLIL_ROL: _lift_binary_operation,
        MediumLevelILOperation.MLIL_RLC: _lift_binary_operation,
        MediumLevelILOperation.MLIL_ROR: _lift_binary_operation,
        MediumLevelILOperation.MLIL_RRC: _lift_unknown_operation,
        MediumLevelILOperation.MLIL_MUL: _lift_binary_operation,
        MediumLevelILOperation.MLIL_MULU_DP: _lift_binary_operation,
        MediumLevelILOperation.MLIL_MULS_DP: _lift_binary_operation,
        MediumLevelILOperation.MLIL_DIVU: _lift_binary_operation,
        MediumLevelILOperation.MLIL_DIVU_DP: _lift_binary_operation,
        MediumLevelILOperation.MLIL_DIVS: _lift_binary_operation,
        MediumLevelILOperation.MLIL_DIVS_DP: _lift_binary_operation,
        MediumLevelILOperation.MLIL_MODU: _lift_binary_operation,
        MediumLevelILOperation.MLIL_MODU_DP: _lift_binary_operation,
        MediumLevelILOperation.MLIL_MODS: _lift_binary_operation,
        MediumLevelILOperation.MLIL_MODS_DP: _lift_binary_operation,
        # Unary Operations
        MediumLevelILOperation.MLIL_NEG: _lift_unary_operation,
        MediumLevelILOperation.MLIL_NOT: _lift_unary_operation,
        MediumLevelILOperation.MLIL_SX: _lift_unary_operation,
        MediumLevelILOperation.MLIL_ZX: _lift_zx_operation,
        MediumLevelILOperation.MLIL_LOW_PART: _lift_mask_high,
        # float
        MediumLevelILOperation.MLIL_FADD: _lift_binary_operation,
        MediumLevelILOperation.MLIL_FSUB: _lift_binary_operation,
        MediumLevelILOperation.MLIL_FMUL: _lift_binary_operation,
        MediumLevelILOperation.MLIL_FDIV: _lift_binary_operation,
        # MediumLevelILOperation.MLIL_FSQRT:				None,
        # MediumLevelILOperation.MLIL_FNEG:					None,
        # MediumLevelILOperation.MLIL_FABS:					None,
        # Control flow and branches
        MediumLevelILOperation.MLIL_JUMP: _lift_jump,
        MediumLevelILOperation.MLIL_JUMP_TO: _lift_jump,
        MediumLevelILOperation.MLIL_IF: _lift_branch,
        MediumLevelILOperation.MLIL_GOTO: _lift_nop,
        # MediumLevelILOperation.MLIL_RET_HINT:				_lift_return,
        MediumLevelILOperation.MLIL_CALL: _lift_call,
        MediumLevelILOperation.MLIL_CALL_UNTYPED: _lift_call,
        # MediumLevelILOperation.MLIL_CALL_OUTPUT:			None,
        # MediumLevelILOperation.MLIL_CALL_PARAM: 			None,
        MediumLevelILOperation.MLIL_RET: _lift_return,
        # MediumLevelILOperation.MLIL_NORET: None,
        MediumLevelILOperation.MLIL_CMP_E: _lift_condition,
        MediumLevelILOperation.MLIL_CMP_NE: _lift_condition,
        MediumLevelILOperation.MLIL_CMP_SLT: _lift_condition,
        MediumLevelILOperation.MLIL_CMP_ULT: _lift_condition,
        MediumLevelILOperation.MLIL_CMP_SLE: _lift_condition,
        MediumLevelILOperation.MLIL_CMP_ULE: _lift_condition,
        MediumLevelILOperation.MLIL_CMP_SGE: _lift_condition,
        MediumLevelILOperation.MLIL_CMP_UGE: _lift_condition,
        MediumLevelILOperation.MLIL_CMP_SGT: _lift_condition,
        MediumLevelILOperation.MLIL_CMP_UGT: _lift_condition,
        # float
        # MediumLevelILOperation.MLIL_FCMP_E:				None,
        # MediumLevelILOperation.MLIL_FCMP_NE:				None,
        # MediumLevelILOperation.MLIL_FCMP_LT:				None,
        # MediumLevelILOperation.MLIL_FCMP_LE:				None,
        # MediumLevelILOperation.MLIL_FCMP_GE:				None,
        # MediumLevelILOperation.MLIL_FCMP_GT:				None,
        # MediumLevelILOperation.MLIL_FCMP_O:				None,
        # MediumLevelILOperation.MLIL_FCMP_UO:				None,
        MediumLevelILOperation.MLIL_TEST_BIT: _lift_test_bit,
        MediumLevelILOperation.MLIL_BOOL_TO_INT: _lift_cast,
        # MediumLevelILOperation.MLIL_ADD_OVERFLOW: None,
        # MediumLevelILOperation.MLIL_SYSCALL: None,
        # MediumLevelILOperation.MLIL_SYSCALL_UNTYPED: None,
        # MediumLevelILOperation.MLIL_TAILCALL: None,
        # MediumLevelILOperation.MLIL_TAILCALL_UNTYPED: None,
        # MediumLevelILOperation.MLIL_BP: None,
        # MediumLevelILOperation.MLIL_TRAP: None,
        # MediumLevelILOperation.MLIL_INTRINSIC: None,
        # MediumLevelILOperation.MLIL_INTRINSIC_SSA: None,
        # MediumLevelILOperation.MLIL_FREE_VAR_SLOT: None,
        # MediumLevelILOperation.MLIL_FREE_VAR_SLOT_SSA: None,
        # MediumLevelILOperation.MLIL_UNDEF: None,
        # MediumLevelILOperation.MLIL_UNIMPL: None,
        # MediumLevelILOperation.MLIL_UNIMPL_MEM: None,
        MediumLevelILOperation.MLIL_FLOAT_TO_INT: _lift_cast,
        MediumLevelILOperation.MLIL_INT_TO_FLOAT: _lift_cast,
        MediumLevelILOperation.MLIL_FLOAT_CONV: _lift_cast,
        # MediumLevelILOperation.MLIL_ROUND_TO_INT: None,
        # MediumLevelILOperation.MLIL_FLOOR: None,
        # MediumLevelILOperation.MLIL_CEIL: None,
        MediumLevelILOperation.MLIL_FTRUNC: _lift_ftrunc,
        # SSA operations
        MediumLevelILOperation.MLIL_SET_VAR_SSA: _lift_assignment,
        MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD: _lift_set_field,
        MediumLevelILOperation.MLIL_SET_VAR_SPLIT_SSA: _lift_split_assignment,
        MediumLevelILOperation.MLIL_SET_VAR_ALIASED: _lift_assignment,
        MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD: _lift_set_field,
        MediumLevelILOperation.MLIL_VAR_SSA: _lift_variable_operation,
        MediumLevelILOperation.MLIL_VAR_SSA_FIELD: _lift_get_field,
        MediumLevelILOperation.MLIL_VAR_ALIASED: _lift_variable_operation,
        MediumLevelILOperation.MLIL_VAR_ALIASED_FIELD: _lift_get_field,
        MediumLevelILOperation.MLIL_VAR_SPLIT_SSA: _lift_split,
        MediumLevelILOperation.MLIL_CALL_SSA: _lift_call,
        MediumLevelILOperation.MLIL_CALL_UNTYPED_SSA: _lift_call,
        # MediumLevelILOperation.MLIL_SYSCALL_SSA: None,
        # MediumLevelILOperation.MLIL_SYSCALL_UNTYPED_SSA: None,
        MediumLevelILOperation.MLIL_TAILCALL_SSA: _lift_call,
        MediumLevelILOperation.MLIL_TAILCALL_UNTYPED_SSA: _lift_call,
        MediumLevelILOperation.MLIL_VAR_PHI: _lift_phi,
        MediumLevelILOperation.MLIL_MEM_PHI: _lift_mem_phi,
        # MediumLevelILOperation.MLIL_CALL_OUTPUT_SSA:        None,
        # MediumLevelILOperation.MLIL_CALL_PARAM_SSA: None,
        MediumLevelILOperation.MLIL_LOAD_SSA: _lift_unary_operation,
        MediumLevelILOperation.MLIL_LOAD_STRUCT_SSA: _lift_load_struct_ssa,
        MediumLevelILOperation.MLIL_STORE_SSA: _lift_write_memory,
        MediumLevelILOperation.MLIL_STORE_STRUCT_SSA: _lift_store_struct_ssa,
        MediumLevelILOperation.MLIL_INTRINSIC_SSA: _lift_intrinsic_ssa,
    }
