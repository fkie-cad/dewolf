import logging

from binaryninja import BinaryView, TagType
from compiler_idioms.matcher import Matcher
from decompiler.util.options import Options


class CompilerIdiomsTagging:
    """Generates binary view tags for the matched compiler idioms."""
    TAG_SYMBOL = "⚙"
    TAG_PREFIX = "compiler_idiom: "

    def __init__(self, binary_view: BinaryView, start: int, options: Options):
        self._bv = binary_view
        self._function_start = start
        self._enabled = options.getboolean("compiler-idioms-tagging.enabled", fallback=True)
        self._debug = options.getboolean("pipeline.debug")

    def run(self):
        """
        Matches idioms in the function (disassembly) currently being decompiled.
        For each found match creates a tag that contains info for original computation reconstruction.
        """
        if not self._enabled:
            return
        try:
            matches = Matcher().find_idioms_in_function(self._bv.file.filename, self._function_start)
        except Exception as e:
            if self._debug:
                raise RuntimeError(e)
            logging.warning("Compiler idioms matching failed, continue without compiler idioms.")
            return

        for match in matches:
            for address in match.addresses:
                self._set_tag(self._bv, tag_name=f"{self.TAG_PREFIX}{match.operation}", address=address,
                              text=f"{match.operand},{match.constant}")

    @staticmethod
    def _set_tag(binary_view: BinaryView, tag_name: str, address: int, text: str):
        """Sets tag in the given binary view at the corresponding address.
        Does nothing if there is already compiler idiom tag set at address"""
        if tags := binary_view.get_user_data_tags_at(address):
            if any(CompilerIdiomsTagging.TAG_PREFIX in tag.type.name for tag in tags):
                return
        tag_type = CompilerIdiomsTagging._get_tag_type(binary_view, tag_name)
        binary_view.create_user_data_tag(address, tag_type, text, unique=True)

    @staticmethod
    def _get_tag_type(binary_view: BinaryView, tag_type_name: str) -> TagType:
        """Creates the tag type [compiler-idioms] in the binary view if id does not exist and returns it."""
        if tag_type_name in binary_view.tag_types.keys():
            return binary_view.tag_types[tag_type_name]
        return binary_view.create_tag_type(tag_type_name, CompilerIdiomsTagging.TAG_SYMBOL)
