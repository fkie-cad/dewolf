import logging

import binaryninja.function
from binaryninja import BinaryView
from compiler_idioms.disassembly.smda_disassembly import SMDADisassembly
from compiler_idioms.matcher import Matcher
from decompiler.util.options import Options


class CompilerIdiomsTagging:
    """Generates binary view tags for the matched compiler idioms."""

    TAG_SYMBOL = "⚙"
    TAG_PREFIX = "compiler_idiom: "

    def __init__(self, binary_view: BinaryView):
        self._bv = binary_view
        self._disassembly = SMDADisassembly(self._bv.file.filename)
        self._matcher = Matcher()

    def run(self, function: binaryninja.function.Function, options: Options):
        """
        Matches idioms in the function (disassembly) currently being decompiled.
        For each found match creates a tag that contains info for original computation reconstruction.
        """
        enabled = options.getboolean("compiler-idioms-tagging.enabled", fallback=True)
        debug_submodules = options.getboolean("logging.debug-submodules")

        if not enabled:
            return
        try:
            instructions = self._disassembly.get_smda_function_at(function.start)
            matches = self._matcher._match_single_function(instructions)
        except Exception as e:
            if debug_submodules:
                raise RuntimeError(e)
            logging.warning("Compiler idioms matching failed, continue without compiler idioms.")
            return

        for match in matches:
            for address in match.addresses:
                self._set_tag(
                    self._bv, tag_name=f"{self.TAG_PREFIX}{match.operation}", address=address, text=f"{match.operand},{match.constant}"
                )

    @staticmethod
    def _set_tag(binary_view: BinaryView, tag_name: str, address: int, text: str):
        """Sets tag in the given binary view at the corresponding address.
        Does nothing if there is already compiler idiom tag set at address"""
        if tags := binary_view.get_tags_at(address, auto=False):
            if any(CompilerIdiomsTagging.TAG_PREFIX in tag.type.name for tag in tags):
                return
        binary_view.create_tag_type(tag_name, CompilerIdiomsTagging.TAG_SYMBOL)
        binary_view.add_tag(address, tag_name, text)
