import logging
import sys

from binaryninja import BinaryView
from decompiler.util.options import Options

string_slicer_path = "/home/manuel/repos/"


class RustStringDetection:
    """TODO:"""

    def __init__(self, binary_view: BinaryView, options: Options):
        self._bv = binary_view
        # TODO: add to default settings, change fallback
        self._enabled = options.getboolean("rust-string-detection.enabled", fallback=True)
        self._rust_binaries_only = options.getboolean("rust-string-detection.rust_binaries_only", fallback=True)
        self._debug_submodules = options.getboolean("logging.debug-submodules")

    def is_rust_binary(self):
        for _ in self._bv.find_all_data(self._bv.start, self._bv.end, "rustc".encode("utf-8")):
            return True
        for _ in self._bv.find_all_data(self._bv.start, self._bv.end, "cargo".encode("utf-8")):
            return True
        return False

    def run(self):
        """
        TODO:
        """
        if not self._enabled:
            return

        if self._rust_binaries_only and not self.is_rust_binary():
            logging.info("Rust String Slicer not executed: Not a Rust Binary")
            return

        logging.info("Starting Rust String Slicer")
        try:
            sys.path.append(string_slicer_path)
            from rust_string_slicer.binja_plugin.actions import RecoverStringFromReadOnlyDataTask, RustStringSlice

            if not RustStringSlice.check_binary_ninja_type_exists(self._bv):
                RustStringSlice.create_binary_ninja_type(self._bv)
            RecoverStringFromReadOnlyDataTask(bv=self._bv).run()

        except Exception as e:
            if self._debug_submodules:
                raise RuntimeError(e)
            logging.warning("Rust String Slicer failed. Please check if the tool is installed and the path is set correctly!")
            return
