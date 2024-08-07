import pytest
from decompiler.structures.pseudo import Float, Integer, Pointer
from decompiler.structures.pseudo.complextypes import (
    Class,
    ComplexTypeMap,
    ComplexTypeMember,
    ComplexTypeName,
    ComplexTypeSpecifier,
    Enum,
    Struct,
    Union,
    UniqueNameProvider,
)
from pydot import frozendict


class TestStruct:
    def test_declaration(self, book: Struct, record_id: Union):
        assert book.declaration() == "struct Book {\n\tchar * title;\n\tint num_pages;\n\tchar * author;\n}"
        # nest complex type
        book.add_member(
            m := ComplexTypeMember(size=64, name="id", offset=12, type=record_id),
        )
        result = f"struct Book {{\n\tchar * title;\n\tint num_pages;\n\tchar * author;\n\t{m.declaration()};\n}}"
        assert book.declaration() == result

    def test_str(self, book: Struct):
        assert str(book) == "Book"

    def test_copy(self, book: Struct):
        new_book: Struct = book.copy()
        assert id(new_book) != id(book)
        assert new_book.size == book.size
        assert new_book.type_specifier == book.type_specifier == ComplexTypeSpecifier.STRUCT
        assert id(new_book.members) != id(book.members)
        assert new_book.get_member_by_offset(0) == book.get_member_by_offset(0)
        assert id(new_book.get_member_by_offset(0)) != id(book.get_member_by_offset(0))
        assert len(new_book.members) == len(book.members)

    def test_add_members(self, book, title, num_pages, author):
        empty_book = Struct(name="Book", members={}, size=96)
        empty_book.add_member(title)
        empty_book.add_member(author)
        empty_book.add_member(num_pages)
        assert empty_book == book

    def test_get_member_by_offset(self, book, title, num_pages, author):
        assert book.get_member_by_offset(0) == title
        assert book.get_member_by_offset(4) == num_pages
        assert book.get_member_by_offset(8) == author

    def test_get_member_name_by_offset(self, book, title, num_pages, author):
        assert book.get_member_name_by_offset(0) == title.name
        assert book.get_member_name_by_offset(4) == num_pages.name
        assert book.get_member_name_by_offset(8) == author.name
        assert book.get_member_name_by_offset(0x100) == "field_0x100"
        assert book.get_member_name_by_offset(-0x100) == "field_minus_0x100"

    def test_get_complex_type_name(self, book):
        assert book.complex_type_name == (ComplexTypeName(0, "Book"))


class TestClass:
    def test_declaration(self, record_id: Union):
        m = ComplexTypeMember(size=64, name="id", offset=12, type=record_id)
        class_book = Struct(
            name="Book",
            members=frozendict({
                0: ComplexTypeMember(size=32, name="title", offset=0, type=Pointer(Integer.char())),
                4: ComplexTypeMember(size=32, name="num_pages", offset=4, type=Integer.int32_t()),
                8: ComplexTypeMember(size=32, name="author", offset=8, type=Pointer(Integer.char())),
                12: m
            }),
            size=96,
        )
        result = f"class ClassBook {{\n\tchar * title;\n\tint num_pages;\n\tchar * author;\n\t{m.declaration()};\n}}"
        assert class_book.declaration() == result

    def test_str(self, class_book: Struct):
        assert str(class_book) == "ClassBook"

    def test_copy(self, class_book: Struct):
        new_class_book: Struct = class_book.copy()
        assert id(new_class_book) != id(class_book)
        assert new_class_book.size == class_book.size
        assert new_class_book.type_specifier == class_book.type_specifier == ComplexTypeSpecifier.CLASS
        assert id(new_class_book.members) != id(class_book.members)
        assert new_class_book.get_member_by_offset(0) == class_book.get_member_by_offset(0)
        assert id(new_class_book.get_member_by_offset(0)) != id(class_book.get_member_by_offset(0))
        assert len(new_class_book.members) == len(class_book.members)

    def test_add_members(self, class_book, title, num_pages, author):
        empty_class_book = Class(name="ClassBook", members={}, size=96)
        empty_class_book.add_member(title)
        empty_class_book.add_member(author)
        empty_class_book.add_member(num_pages)
        assert empty_class_book == class_book

    def test_get_member_by_offset(self, class_book, title, num_pages, author):
        assert class_book.get_member_by_offset(0) == title
        assert class_book.get_member_by_offset(4) == num_pages
        assert class_book.get_member_by_offset(8) == author

    def test_get_member_name_by_offset(self, class_book, title, num_pages, author):
        assert class_book.get_member_name_by_offset(0) == title.name
        assert class_book.get_member_name_by_offset(4) == num_pages.name
        assert class_book.get_member_name_by_offset(8) == author.name
        assert class_book.get_member_name_by_offset(0x100) == "field_0x100"
        assert class_book.get_member_name_by_offset(-0x100) == "field_minus_0x100"

    def test_get_complex_type_name(self, class_book):
        assert class_book.complex_type_name == (ComplexTypeName(0, "ClassBook"))

    def test_class_not_struct(self, class_book, book):
        assert book != class_book


@pytest.fixture
def book() -> Struct:
    return Struct(
        name="Book",
        members={
            0: ComplexTypeMember(size=32, name="title", offset=0, type=Pointer(Integer.char())),
            4: ComplexTypeMember(size=32, name="num_pages", offset=4, type=Integer.int32_t()),
            8: ComplexTypeMember(size=32, name="author", offset=8, type=Pointer(Integer.char())),
        },
        size=96,
    )


@pytest.fixture
def class_book() -> Class:
    return Class(
        name="ClassBook",
        members={
            0: ComplexTypeMember(size=32, name="title", offset=0, type=Pointer(Integer.char())),
            4: ComplexTypeMember(size=32, name="num_pages", offset=4, type=Integer.int32_t()),
            8: ComplexTypeMember(size=32, name="author", offset=8, type=Pointer(Integer.char())),
        },
        size=96,
    )


@pytest.fixture
def title() -> ComplexTypeMember:
    return ComplexTypeMember(size=32, name="title", offset=0, type=Pointer(Integer.char()))


@pytest.fixture
def num_pages() -> ComplexTypeMember:
    return ComplexTypeMember(size=32, name="num_pages", offset=4, type=Integer.int32_t())


@pytest.fixture
def author() -> ComplexTypeMember:
    return ComplexTypeMember(size=32, name="author", offset=8, type=Pointer(Integer.char()))


class TestUnion:
    def test_declaration(self, record_id):
        assert record_id.declaration() == "union RecordID {\n\tfloat float_id;\n\tint int_id;\n\tdouble double_id;\n}"

    def test_str(self, record_id):
        assert str(record_id) == "RecordID"

    def test_copy(self, record_id):
        new_record_id: Union = record_id.copy()
        assert new_record_id == record_id
        assert id(new_record_id) != id(record_id)
        assert id(new_record_id.members) != id(record_id.members)
        assert new_record_id.get_member_by_type(Float.float()) == record_id.get_member_by_type(Float.float())
        assert id(new_record_id.get_member_by_type(Float.float())) != id(record_id.get_member_by_type(Float.float()))

    def test_add_members(self, empty_record_id, record_id, float_id, int_id, double_id):
        empty_record_id.add_member(float_id)
        empty_record_id.add_member(int_id)
        empty_record_id.add_member(double_id)
        assert empty_record_id == record_id

    def test_get_member_by_type(self, record_id, float_id, int_id, double_id):
        assert record_id.get_member_by_type(Float.float()) == float_id
        assert record_id.get_member_by_type(Integer.int32_t()) == int_id
        assert record_id.get_member_by_type(Float.double()) == double_id

    def test_get_member_name_by_type(self, record_id, float_id, int_id, double_id):
        assert record_id.get_member_name_by_type(Float.float()) == float_id.name
        assert record_id.get_member_name_by_type(Integer.int32_t()) == int_id.name
        assert record_id.get_member_name_by_type(Float.double()) == double_id.name
        assert record_id.get_member_name_by_type(record_id) == "unknown_field"

    def test_get_complex_type_name(self, record_id):
        assert record_id.complex_type_name == (ComplexTypeName(0, "RecordID"))


@pytest.fixture
def record_id() -> Union:
    return Union(
        name="RecordID",
        size=64,
        members=[
            ComplexTypeMember(size=32, name="float_id", offset=0, type=Float.float()),
            ComplexTypeMember(size=32, name="int_id", offset=0, type=Integer.int32_t()),
            ComplexTypeMember(size=Float.double().size, name="double_id", offset=0, type=Float.double()),
        ],
    )


@pytest.fixture
def empty_record_id() -> Union:
    return Union(name="RecordID", size=64, members=[])


@pytest.fixture
def float_id() -> ComplexTypeMember:
    return ComplexTypeMember(size=32, name="float_id", offset=0, type=Float.float())


@pytest.fixture
def int_id() -> ComplexTypeMember:
    return ComplexTypeMember(size=32, name="int_id", offset=0, type=Integer.int32_t())


@pytest.fixture
def double_id() -> ComplexTypeMember:
    return ComplexTypeMember(size=Float.double().size, name="double_id", offset=0, type=Float.double())


class TestEnum:
    def test_declaration(self, color):
        assert color.declaration() == "enum Color {\n\tred = 0,\n\tgreen = 1,\n\tblue = 2\n}"

    def test_str(self, color):
        assert str(color) == "Color"

    def test_copy(self, color):
        new_color = color.copy()
        assert new_color == color
        assert id(new_color) != color

    def test_add_members(self, empty_color, color, red, green, blue):
        empty_color.add_member(red)
        empty_color.add_member(green)
        empty_color.add_member(blue)
        assert empty_color == color

    def test_get_complex_type_name(self, color):
        assert color.complex_type_name == (ComplexTypeName(0, "Color"))


@pytest.fixture
def color():
    return Enum(
        0,
        "Color",
        {
            0: ComplexTypeMember(0, "red", value=0, offset=0, type=Integer.int32_t()),
            1: ComplexTypeMember(0, "green", value=1, offset=0, type=Integer.int32_t()),
            2: ComplexTypeMember(0, "blue", value=2, offset=0, type=Integer.int32_t()),
        },
    )


@pytest.fixture
def empty_color():
    return Enum(0, "Color", {})


@pytest.fixture
def red():
    return ComplexTypeMember(0, "red", value=0, offset=0, type=Integer.int32_t())


@pytest.fixture
def green():
    return ComplexTypeMember(0, "green", value=1, offset=0, type=Integer.int32_t())


@pytest.fixture
def blue():
    return ComplexTypeMember(0, "blue", value=2, offset=0, type=Integer.int32_t())


class TestComplexTypeMap:
    def test_declarations(self, complex_types: ComplexTypeMap, book: Struct, class_book: Class, color: Enum, record_id: Union):
        assert (
            complex_types.declarations()
            == f"{book.declaration()};\n{color.declaration()};\n{record_id.declaration()};\n{class_book.declaration()};"
        )
        complex_types.add(book, 0)
        assert (
            complex_types.declarations()
            == f"{book.declaration()};\n{color.declaration()};\n{record_id.declaration()};\n{class_book.declaration()};"
        )

    def test_retrieve_by_name(self, complex_types: ComplexTypeMap, book: Struct, class_book: Class, color: Enum, record_id: Union):
        assert complex_types.retrieve_by_name(ComplexTypeName(0, "Book")) == book
        assert complex_types.retrieve_by_name(ComplexTypeName(0, "RecordID")) == record_id
        assert complex_types.retrieve_by_name(ComplexTypeName(0, "Color")) == color
        assert complex_types.retrieve_by_name(ComplexTypeName(0, "ClassBook")) == class_book

    def test_retrieve_by_id(self, complex_types: ComplexTypeMap, book: Struct, class_book: Class, color: Enum, record_id: Union):
        assert complex_types.retrieve_by_id(0) == book
        assert complex_types.retrieve_by_id(1) == color
        assert complex_types.retrieve_by_id(2) == record_id
        assert complex_types.retrieve_by_id(3) == class_book

    @pytest.fixture
    def complex_types(self, book: Struct, class_book: Class, color: Enum, record_id: Union):
        complex_types = ComplexTypeMap()
        complex_types.add(book, 0)
        complex_types.add(color, 1)
        complex_types.add(record_id, 2)
        complex_types.add(class_book, 3)
        return complex_types


class TestUniqueNameProvider:
    def test_unique_names(self):
        unique_name_provider = UniqueNameProvider()
        input_names = ["aa", "", "b", "", "c", "c", "d", "c"]
        excepted_output = ["aa", "", "b", "__2", "c", "c__2", "d", "c__3"]
        output_names = [unique_name_provider.get_unique_name(name) for name in input_names]
        assert output_names == excepted_output
        assert len(set(output_names)) == len(output_names)  # uniqueness
