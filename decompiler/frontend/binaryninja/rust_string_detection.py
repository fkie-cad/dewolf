import logging
import sys

from binaryninja import BinaryView
from decompiler.util.options import Options


class RustStringDetection:
    """
    This 'stage' detects certain Rust strings (string slices), which are struct based strings.
    It requires the RustStringSlicer. A path to the tool needs to be configured via the options.

    The stage is executed before lifting, as it uses the Binary Ninja API to identify string slices
    and 'mark' them, by assigning the appropriate type.
    It can be configured to run always, never, or for Rust binaries only.
    """

    def __init__(self, binary_view: BinaryView, options: Options):
        self._bv = binary_view
        self._enabled = options.getboolean("rust-string-detection.enabled", fallback=False)
        self._rust_binaries_only = options.getboolean("rust-string-detection.rust_binaries_only", fallback=False)
        self._string_slicer_path = options.getstring("rust-string-detection.string_slicer_path", fallback="")
        self._debug_submodules = options.getboolean("logging.debug-submodules", fallback=False)

    def is_rust_binary(self):
        """
        Simple heurstic to determine, whether the binary is a Rust binary.

        """
        for _ in self._bv.find_all_data(self._bv.start, self._bv.end, "rustc".encode("utf-8")):
            return True
        for _ in self._bv.find_all_data(self._bv.start, self._bv.end, "cargo".encode("utf-8")):
            return True
        return False

    def run(self):
        """
        Runs the Rust String Slicer, if the required conditions are met.

        String Slicer's path will be added to Python's path before importing the module.
        """
        if not self._enabled:
            logging.info("Rust String Slicer not executed")
            return

        if self._rust_binaries_only and not self.is_rust_binary():
            logging.info("Rust String Slicer not executed: Not a Rust Binary")
            return

        logging.info("Starting Rust String Slicer")
        try:
            sys.path.append(self._string_slicer_path)
            from rust_string_slicer.binja_plugin.actions import RecoverStringFromReadOnlyDataTask, RustStringSlice

            if not RustStringSlice.check_binary_ninja_type_exists(self._bv):
                RustStringSlice.create_binary_ninja_type(self._bv)
            RecoverStringFromReadOnlyDataTask(bv=self._bv).run()

        except Exception as e:
            if self._debug_submodules:
                raise RuntimeError(e)
            logging.warning("Rust String Slicer failed. Please check if the tool is installed and the path is set correctly!")
            return
