"""Main plugin file registering plugin commands in bianryninja."""
from logging import info, warning
from os.path import dirname, realpath
from sys import path
from threading import Lock

from binaryninja import BackgroundTaskThread, BinaryView, Function, MessageBoxButtonSet, PluginCommand, core_ui_enabled, show_html_report
from binaryninja.interaction import show_message_box

# Add dewolf to the path in case it is not in the pythonpath already
current_dir = dirname(realpath(__file__))
path.append(current_dir)

from decompile import Decompiler
from dewolf.logger import configure_logging
from dewolf.util.decoration import DecoratedCode
from dewolf.util.options import Options


def decompile(bv: BinaryView, function: Function):
    """Decompile the target mlil_function."""
    decompiler = Decompiler.from_raw(bv)
    options = Options.from_gui()
    task = decompiler.decompile(function, options)
    show_html_report(
        f"decompile {task.name}", DecoratedCode.generate_html_from_code(task.code, task.options.getstring("code-generator.style_plugin"))
    )


class Decompile(BackgroundTaskThread):
    """Thread wrapper for GUI decompile"""

    def __init__(self, bv, function):
        BackgroundTaskThread.__init__(self, f"Decompiling {function.name}", True)
        self.bv = bv
        self.function = function

    def run(self):
        with gui_thread_lock:
            info(f"[+] started decompilation: {self.function.name}")
            decompile(self.bv, self.function)


def decompile_thread(bv: BinaryView, function: Function):
    configure_logging()  # reload settings
    if gui_thread_lock.locked():
        choice = show_message_box(
            "Decompiler - Error",
            "Only one instance of decompiler may run at a time.",
            MessageBoxButtonSet.OKButtonSet,
        )
    thread = Decompile(bv, function)
    thread.start()


if core_ui_enabled():
    # register the plugin command
    gui_thread_lock = Lock()
    PluginCommand.register_for_function("Decompile", "decompile the current function", decompile_thread)
    Options.from_gui()  # register dewolf config in GUI

    try:
        from dewolf.util.widget import add_dock_widget

        add_dock_widget()
    except Exception as ex:
        warning(f"failed to load widget: {ex}")
