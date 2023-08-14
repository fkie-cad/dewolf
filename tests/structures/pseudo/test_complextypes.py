# import pytest
# from decompiler.structures.pseudo import Float, Integer, Pointer
# from decompiler.structures.pseudo.complextypes import (
#     ComplexTypeMap,
#     ComplexTypeMember,
#     ComplexTypeName,
#     ComplexTypeSpecifier,
#     Enum,
#     Struct,
#     Union,
# )
#
#
# class TestStruct:
#     def test_declaration(self, book: Struct, record_id: Union):
#         assert book.declaration() == "struct Book {\n\tchar * title;\n\tint num_pages;\n\tchar * author;\n}"
#         # nest complex type
#         book.add_member(
#             m := ComplexTypeMember(size=64, name="id", offset=12, type=record_id),
#         )
#         # TODO if union is defined not within the struct itself?
#         result = f"struct Book {{\n\tchar * title;\n\tint num_pages;\n\tchar * author;\n\t{m.declaration()};\n}}"
#         # TODO nest enum
#         assert book.declaration() == result
#
#     def test_str(self, book: Struct):
#         assert str(book) == "Book"
#
#     def test_copy(self, book: Struct):
#         new_book: Struct = book.copy()
#         assert id(new_book) != id(book)
#         assert new_book.size == book.size
#         assert new_book.type_specifier == book.type_specifier == ComplexTypeSpecifier.STRUCT
#         assert id(new_book.members) != id(book.members)
#         assert new_book.get_member_by_offset(0) == book.get_member_by_offset(0)
#         assert id(new_book.get_member_by_offset(0)) != id(book.get_member_by_offset(0))
#         assert len(new_book.members) == len(book.members)
#
#     def test_add_members(self, book, title, num_pages, author):
#         empty_book = Struct(name="Book", members={}, size=96)
#         empty_book.add_member(title)
#         empty_book.add_member(author)
#         empty_book.add_member(num_pages)
#         assert empty_book == book
#
#     def test_get_member_by_offset(self, book, title, num_pages, author):
#         assert book.get_member_by_offset(0) == title
#         assert book.get_member_by_offset(4) == num_pages
#         assert book.get_member_by_offset(8) == author
#
#
# @pytest.fixture
# def book() -> Struct:
#     return Struct(
#         name="Book",
#         members={
#             0: ComplexTypeMember(size=32, name="title", offset=0, type=Pointer(Integer.char())),
#             4: ComplexTypeMember(size=32, name="num_pages", offset=4, type=Integer.int32_t()),
#             8: ComplexTypeMember(size=32, name="author", offset=8, type=Pointer(Integer.char())),
#         },
#         size=96,
#     )
#
#
# @pytest.fixture
# def title() -> ComplexTypeMember:
#     return ComplexTypeMember(size=32, name="title", offset=0, type=Pointer(Integer.char()))
#
#
# @pytest.fixture
# def num_pages() -> ComplexTypeMember:
#     return ComplexTypeMember(size=32, name="num_pages", offset=4, type=Integer.int32_t())
#
#
# @pytest.fixture
# def author() -> ComplexTypeMember:
#     return ComplexTypeMember(size=32, name="author", offset=8, type=Pointer(Integer.char()))
#
#
# class TestUnion:
#     def test_declaration(self, record_id):
#         assert record_id.declaration() == "union RecordID {\n\tfloat float_id;\n\tint int_id;\n\tdouble double_id;\n}"
#
#     def test_str(self, record_id):
#         assert str(record_id) == "RecordID"
#
#     def test_copy(self, record_id):
#         new_record_id: Union = record_id.copy()
#         assert new_record_id == record_id
#         assert id(new_record_id) != id(record_id)
#         assert id(new_record_id.members) != id(record_id.members)
#         assert new_record_id.get_member_by_type(Float.float()) == record_id.get_member_by_type(Float.float())
#         assert id(new_record_id.get_member_by_type(Float.float())) != id(record_id.get_member_by_type(Float.float()))
#
#     def test_add_members(self, empty_record_id, record_id, float_id, int_id, double_id):
#         empty_record_id.add_member(float_id)
#         empty_record_id.add_member(int_id)
#         empty_record_id.add_member(double_id)
#         assert empty_record_id == record_id
#
#     def test_get_member_by_type(self, record_id, float_id, int_id, double_id):
#         assert record_id.get_member_by_type(Float.float()) == float_id
#         assert record_id.get_member_by_type(Integer.int32_t()) == int_id
#         assert record_id.get_member_by_type(Float.double()) == double_id
#
#
# @pytest.fixture
# def record_id() -> Union:
#     return Union(
#         name="RecordID",
#         size=64,
#         members=[
#             ComplexTypeMember(size=32, name="float_id", offset=0, type=Float.float()),
#             ComplexTypeMember(size=32, name="int_id", offset=0, type=Integer.int32_t()),
#             ComplexTypeMember(size=Float.double().size, name="double_id", offset=0, type=Float.double()),
#         ],
#     )
#
#
# @pytest.fixture
# def empty_record_id() -> Union:
#     return Union(name="RecordID", size=64, members=[])
#
#
# @pytest.fixture
# def float_id() -> ComplexTypeMember:
#     return ComplexTypeMember(size=32, name="float_id", offset=0, type=Float.float())
#
#
# @pytest.fixture
# def int_id() -> ComplexTypeMember:
#     return ComplexTypeMember(size=32, name="int_id", offset=0, type=Integer.int32_t())
#
#
# @pytest.fixture
# def double_id() -> ComplexTypeMember:
#     return ComplexTypeMember(size=Float.double().size, name="double_id", offset=0, type=Float.double())
#
#
# class TestEnum:
#     def test_declaration(self, color):
#         assert color.declaration() == "enum Color {\n\tred = 0,\n\tgreen = 1,\n\tblue = 2\n}"
#
#     def test_str(self, color):
#         assert str(color) == "Color"
#
#     def test_copy(self, color):
#         new_color = color.copy()
#         assert new_color == color
#         assert id(new_color) != color
#
#     def test_add_members(self, empty_color, color, red, green, blue):
#         empty_color.add_member(red)
#         empty_color.add_member(green)
#         empty_color.add_member(blue)
#         assert empty_color == color
#
#
# @pytest.fixture
# def color():
#     return Enum(
#         0,
#         "Color",
#         {
#             0: ComplexTypeMember(0, "red", value=0, offset=0, type=Integer.int32_t()),
#             1: ComplexTypeMember(0, "green", value=1, offset=0, type=Integer.int32_t()),
#             2: ComplexTypeMember(0, "blue", value=2, offset=0, type=Integer.int32_t()),
#         },
#     )
#
#
# @pytest.fixture
# def empty_color():
#     return Enum(0, "Color", {})
#
#
# @pytest.fixture
# def red():
#     return ComplexTypeMember(0, "red", value=0, offset=0, type=Integer.int32_t())
#
#
# @pytest.fixture
# def green():
#     return ComplexTypeMember(0, "green", value=1, offset=0, type=Integer.int32_t())
#
#
# @pytest.fixture
# def blue():
#     return ComplexTypeMember(0, "blue", value=2, offset=0, type=Integer.int32_t())
#
#
# class TestComplexTypeMap:
#     def test_declarations(self, complex_types: ComplexTypeMap, book: Struct, color: Enum, record_id: Union):
#         assert complex_types.declarations() == f"{book.declaration()};\n{color.declaration()};\n{record_id.declaration()};"
#         complex_types.add(book)
#         assert complex_types.declarations() == f"{book.declaration()};\n{color.declaration()};\n{record_id.declaration()};"
#
#     def test_retrieve_by_name(self, complex_types: ComplexTypeMap, book: Struct, color: Enum, record_id: Union):
#         assert complex_types.retrieve_by_name(ComplexTypeName(0, "Book")) == book
#         assert complex_types.retrieve_by_name(ComplexTypeName(0, "RecordID")) == record_id
#         assert complex_types.retrieve_by_name(ComplexTypeName(0, "Color")) == color
#
#     @pytest.fixture
#     def complex_types(self, book: Struct, color: Enum, record_id: Union):
#         complex_types = ComplexTypeMap()
#         complex_types.add(book)
#         complex_types.add(color)
#         complex_types.add(record_id)
#         return complex_types
