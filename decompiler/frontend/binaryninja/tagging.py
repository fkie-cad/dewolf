import binaryninja
from binaryninja import TagType
from compiler_idioms.matcher import Matcher


class CompilerIdiomsTagging:
    TAG_SYMBOL = "⚙"

    def __init__(self, bv: binaryninja.BinaryView, path: str):
        self._bv = bv
        self._path = path

    def run(self):
        matches = Matcher().find_idioms_in_file(self._path)
        for match in matches:
            for address in match.addresses:
                self._set_tag(self._bv, tag_name=f"compiler_idiom: {match.operation}", address=address,
                              text=f"{match.operand},{match.constant}")

    @staticmethod
    def _set_tag(binary_view: binaryninja.BinaryView, tag_name: str, address: int, text: str):
        tag_type = CompilerIdiomsTagging._get_tag_type(binary_view, tag_name)
        binary_view.create_user_data_tag(address, tag_type, text, unique=True)

    @staticmethod
    def _get_tag_type(binary_view: binaryninja.BinaryView, tag_type_name: str) -> TagType:
        if tag_type_name in binary_view.tag_types.keys():
            return binary_view.tag_types[tag_type_name]
        return binary_view.create_tag_type(tag_type_name, CompilerIdiomsTagging.TAG_SYMBOL)
