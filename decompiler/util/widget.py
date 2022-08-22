import logging
import re
import sys
import traceback
from functools import wraps
from typing import Dict, List, Optional, Tuple

from binaryninja import BinaryView, Function, core_version
from binaryninja.enums import ThemeColor
from binaryninjaui import Menu, UIAction, UIActionHandler, UIContext, UIContextNotification, ViewFrame, WidgetPane, getThemeColor
from decompile import Decompiler
from decompiler.logger import configure_logging
from decompiler.util.decoration import DecoratedCode
from decompiler.util.options import Options

version_numbers = core_version().split(".")
major, minor = int(version_numbers[0]), int(version_numbers[1])
if major <= 2 and minor <= 4:
    from PySide2.QtCore import QObject, QRunnable, Qt, QThreadPool, Signal, Slot
    from PySide2.QtGui import QFont, QMouseEvent, QSyntaxHighlighter, QTextCharFormat, QTextCursor
    from PySide2.QtWidgets import QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget
else:
    from PySide6.QtCore import QObject, QRunnable, Qt, QThreadPool, Signal, Slot
    from PySide6.QtGui import QFont, QMouseEvent, QSyntaxHighlighter, QTextCharFormat, QTextCursor
    from PySide6.QtWidgets import QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget


class Worker(QRunnable):
    """Worker thread"""

    class Signals(QObject):
        """Defines signals for Worker"""

        task_name = Signal(str)
        result = Signal(tuple)
        error = Signal(tuple)
        finished = Signal()

    def __init__(self, binary_view: BinaryView, function: Function):
        """Initialize Worker subclass from QRunnable"""
        super(Worker, self).__init__()
        self.binary_view = binary_view
        self.function = function
        self.signals = self.Signals()

    @Slot()
    def run(self):
        """Run a worker task for decompilation and emit appropriate signals"""
        try:
            self.signals.task_name.emit(self.function.name)
            code = self.decompile_for_widget(self.binary_view, self.function)
        except:
            traceback.print_exc()
            exctype, value = sys.exc_info()[:2]
            self.signals.error.emit((self.function.name, exctype, value, traceback.format_exc()))
        else:
            self.signals.result.emit((self.function.name, code))
        finally:
            self.signals.finished.emit()

    @staticmethod
    def decompile_for_widget(binary_view: BinaryView, function: Function):
        """Decompile the target mlil_function."""
        configure_logging()  # reload settings
        decompiler = Decompiler.from_raw(binary_view)
        options = Options.from_gui()
        task = decompiler.decompile(function, options)
        return DecoratedCode.formatted_plain(task.code)


class CodeDisplay(QPlainTextEdit):
    """Class for displaying text with mouse events"""

    double_click_word = Signal(str)
    select_token = Signal(str)

    def __init__(self, text: str, parent: QWidget):
        """Initialize CodeDisplay subclass from QPlainTextEdit"""
        super().__init__(text, parent=parent)
        self.setReadOnly(True)
        self.resize(self.sizeHint())
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.set_font()

    def set_font(self):
        """Read font options from GUI settings and set font accordingly"""
        self.options = Options.from_gui()
        font = self.options.getstring("gui.font", fallback="source code pro")
        font_size = self.options.getint("gui.font_size", fallback=16)
        is_font_bold = self.options.getboolean("gui.font_bold", fallback=False)
        is_font_italic = self.options.getboolean("gui.font_italic", fallback=False)
        self.font = QFont(font, font_size)
        if is_font_italic:
            self.font.setItalic(True)
        if is_font_bold:
            self.font.setBold(True)
        self.font.setStyleHint(QFont.Monospace)
        self.font.setFamily(font)
        self.setFont(self.font)

    def _get_word_under_cursor(self, e: QMouseEvent) -> str:
        """Return the word under cursor"""
        cursor = self.cursorForPosition(e.pos())
        cursor.select(QTextCursor.WordUnderCursor)
        return cursor.selectedText()

    def mouseDoubleClickEvent(self, e: QMouseEvent):
        """Emit word under cursor on double click"""
        self.double_click_word.emit(self._get_word_under_cursor(e))

    def mousePressEvent(self, e: QMouseEvent):
        """Emit word under cursor on click"""
        self.select_token.emit(self._get_word_under_cursor(e))

    @classmethod
    def register_widget(cls, parent: QWidget):
        """
        Factory for creating and registering in parent widget
        :param parent - QWidget: needs to have callback functions jump_to_symbol and on_select
        """
        code_display = cls("", parent)
        code_display.double_click_word.connect(parent.jump_to_symbol)
        code_display.select_token.connect(parent.on_select)
        return code_display


class DewolfNotifications(UIContextNotification):
    """Class handling notifications to the dewolf widget."""

    def __init__(self, widget):
        UIContextNotification.__init__(self)
        self.widget = widget
        self.widget.destroyed.connect(self.destroyed)
        UIContext.registerNotification(self)

    def destroyed(self):
        UIContext.unregisterNotification(self)

    def OnViewChange(self, context, frame, type):
        self.widget.updateState()

    def OnAddressChange(self, context, frame, view, location):
        self.widget.updateState()


class DewolfWidget(QWidget, UIContextNotification):
    """Class for docking widget, displaying decompiled code"""

    FOLLOW_BUTTON_STYLES = {
        True: f"background-color : {getThemeColor(ThemeColor.SelectionColor).name()}",
        False: f"background-color : {getThemeColor(ThemeColor.GraphNodeDarkColor).name()}",
    }

    class Decorators(object):
        """Class containing decorators"""

        @classmethod
        def requires_function(cls, decorated):
            """Decorator for checking requirement of self._current_function. No operation if requirement not met"""

            @wraps(decorated)
            def wrapped(self, *args, **kwargs):
                if self._current_function is None:
                    return None
                return decorated(self, *args, **kwargs)

            return wrapped

        @classmethod
        def requires_view(cls, decorated):
            """Decorator for checking requirement of self._current_view. No operation if requirement not met"""

            @wraps(decorated)
            def wrapped(self, *args, **kwargs):
                if self._current_view is None:
                    return None
                return decorated(self, *args, **kwargs)

            return wrapped

    def __init__(self, data: BinaryView):
        """Initialize dock widget"""
        QWidget.__init__(self)
        self._current_function: Optional[Function] = None
        self._current_view: Optional[BinaryView] = None
        self._current_frame: Optional[ViewFrame] = None
        self._cache: Dict[str, str] = {}
        self.create_toolbar_layout()
        self.editor = CodeDisplay.register_widget(self)
        self.highlighter = Highlighter(self.editor.document())
        layout = QVBoxLayout()
        layout.addLayout(self.notify_area)
        layout.addWidget(self.editor)
        layout.setAlignment(Qt.AlignLeft)
        self.setLayout(layout)
        self.threadpool = QThreadPool()
        self.updateState()
        self.notifications = DewolfNotifications(self)
        self.data = data

    @property
    def current_function(self) -> Optional[Function]:
        """Currently selected Function in BinaryView"""
        return self._current_function

    @current_function.setter
    def current_function(self, value: Optional[Function]):
        """Setter for current_function. Updates notification text"""
        self._current_function = value
        if self._current_function is not None:
            self.selection_text.setText(f"{self._current_function.name}@{hex(self._current_function.start)}")
        else:
            self.selection_text.setText("no function selected")

    def create_toolbar_layout(self):
        """Notify bar layout"""
        self.notify_area = QHBoxLayout()
        self.notify_area.addWidget(QLabel("Selected function: "))
        self.selection_text = QLabel("no function selected")
        self.follow_button = QPushButton("follow")
        self.follow_button.setCheckable(True)
        self.follow_button.setChecked(True)
        self.follow_button.clicked.connect(self.on_toggle)
        self.follow_button.setStyleSheet(self.FOLLOW_BUTTON_STYLES[self.follow_button.isChecked()])
        self.config_button = QPushButton("decompile")
        self.config_button.clicked.connect(self.reanalyze)
        self.notify_area.addWidget(self.selection_text)
        self.notify_area.setAlignment(Qt.AlignLeft)
        self.notify_area.addStretch()
        self.notify_area.addWidget(self.follow_button)
        self.notify_area.addWidget(self.config_button)

    def on_toggle(self):
        """Callback for toggling automatic decompilation on or off"""
        self.follow_button.setStyleSheet(self.FOLLOW_BUTTON_STYLES[self.follow_button.isChecked()])
        if self.follow_button.isChecked():
            self.set_code_editor_content_from_cache_or_decompile()

    def on_select(self, word: str):
        """Callback for token highlighting"""
        self.highlighter.selected = word

    @Decorators.requires_view
    @Decorators.requires_function
    def reanalyze(self):
        """Callback for re-decompilation"""
        self.start_worker(self._current_view, self._current_function)

    @Decorators.requires_view
    def jump_to_symbol(self, symbol: str) -> None:
        """Jump GUI to symbol if exists"""
        if symbols := self.data.symbols.get(symbol):
            if function := self.get_function_from_address(symbols[0].address):
                self._current_view.navigateToFunction(function, function.start)
        elif symbol.startswith("sub_"):
            if function := self.data.get_function_at(int(symbol.replace("sub_", "0x"), 16)):
                self._current_view.navigateToFunction(function, function.start)

    @Decorators.requires_view
    def get_function_from_address(self, address: int) -> Optional[Function]:
        """
        Return Function containing address
        :param address - int:
        """
        if function_list := self.data.get_functions_containing(address):
            return function_list[0]
        return None

    @Decorators.requires_view
    @Decorators.requires_function
    def set_code_editor_content_from_cache_or_decompile(self):
        """Set code view to (cached) content or start worker"""
        if self._current_function.name in self._cache.keys():
            self.update_code_view()
            return
        self.start_worker(self._current_view, self._current_function)

    @Decorators.requires_function
    def update_code_view(self):
        """Reload CodeDisplay content from cache"""
        self.editor.set_font()  # responsive gui settings
        self.editor.setPlainText(self._cache.get(self._current_function.name, ""))
        self.highlighter.rehighlight()

    def callback_update_cache(self, result: Tuple[str, str]) -> None:
        """Callback for successful decompilation"""
        function_name, code = result
        self._cache[function_name] = code

    def callback_decompilation_error(self, error: Tuple):
        """Callback for decompilation error"""
        task_name, *error_messages = error
        message = f"Decompilation of `{task_name}` failed with:\n\n" + "\n\n".join(str(e) for e in error_messages)
        self.editor.setPlainText(message)
        self._cache[task_name] = message

    def callback_worker_task_started(self, task_name: str):
        """Callback for decompilation task started"""
        logging.info(f"Started decompilation of {task_name}")
        self._cache[task_name] = "In Queue"
        self.update_code_view()

    def callback_decompilation_finished(self):
        """Callback for finished decompilation (updates code view)"""
        logging.info("Finished decompilation")
        self.update_code_view()

    def start_worker(self, binary_view: BinaryView, function: Function) -> None:
        """Set up Worker with callbacks"""
        worker = Worker(binary_view, function)
        worker.signals.result.connect(self.callback_update_cache)
        worker.signals.task_name.connect(self.callback_worker_task_started)
        worker.signals.error.connect(self.callback_decompilation_error)
        worker.signals.finished.connect(self.callback_decompilation_finished)
        self.threadpool.start(worker)

    def updateState(self):
        """Update the current UI state (frame, view, data, function)"""

        self._current_frame = UIContext.currentViewFrameForWidget(self)

        # Update UI according to the active frame
        if self._current_frame:
            self._current_view = self._current_frame.getCurrentViewInterface()
            self.data = self._current_view.getData()
            self.current_function = self._current_view.getCurrentFunction()
            if self.follow_button.isChecked():
                self.set_code_editor_content_from_cache_or_decompile()

    @staticmethod
    def createPane(context):
        """Create a WidgetPane"""
        if context.context and context.binaryView:
            widget = DewolfWidget(context.binaryView)
            pane = WidgetPane(widget, "dewolf decompiler")
            context.context.openPane(pane)

    @staticmethod
    def canCreatePane(context):
        """Determine if we can create a WidgetPane"""
        return context.context and context.binaryView


class Highlighter(QSyntaxHighlighter):
    """Highlighter class for syntax highlighting in CodeView"""

    KEYWORDS = [
        "longlong",
        "ushort",
        "ulong",
        "byte",
        "false",
        "true",
        "uint",
        "size_t",
        "char",
        "const",
        "double",
        "enum",
        "int",
        "long",
        "short",
        "signed",
        "static",
        "struct",
        "union",
        "unsigned",
        "extern",
        "void",
        "bool",
    ]
    FLOW_WORDS = [
        "return",
        "if",
        "else",
        "switch",
        "case",
        "while",
        "break",
        "for",
        "do",
        "goto",
    ]
    FUNCTION_PATTERN = ["\\b\\w+(?=\\()"]
    STRING_CONSTS = ['"(.*?)"']
    NUMERIC_CONSTANTS = [
        "\\b\\d+\\b",
        "0x[0-9a-f]+\\b",
        "-?\\d+L\\b",
        "-?\\d+UL\\b",
    ]
    EXCLUDE_FROM_HIGHLIGHT = set(""";{[]}()"',*.!-+& =""") | set(["=="])
    KEYWORDS_COLOR = ThemeColor.KeywordColor
    FLOW_WORDS_COLOR = ThemeColor.TokenHighlightColor
    FUNCTION_COLOR = ThemeColor.CodeSymbolColor
    STRING_COLOR = ThemeColor.StringColor
    NUMBER_COLOR = ThemeColor.NumberColor
    SELECTION_COLOR = ThemeColor.TokenSelectionColor

    def __init__(self, document):
        """Initialize Highlighter subclass from QSyntaxHighlighter"""
        super(Highlighter, self).__init__(document)
        self._selected = None

    @property
    def selected(self):
        """Selected word for highlighting"""
        return self._selected

    @selected.setter
    def selected(self, value):
        """Setter for selected word triggers highlighting"""
        self._selected = value
        self.rehighlight()

    def highlightBlock(self, text: str):
        """Function for highlighting with QSyntaxHighlighter"""
        self._highlight_tokens(text, self.KEYWORDS, self.KEYWORDS_COLOR)
        self._highlight_tokens(text, self.FLOW_WORDS, self.FLOW_WORDS_COLOR)
        self._highlight_tokens(text, self.FUNCTION_PATTERN, self.FUNCTION_COLOR, is_text_only_token=False)
        self._highlight_tokens(text, self.STRING_CONSTS, self.STRING_COLOR, is_text_only_token=False)
        self._highlight_tokens(text, self.NUMERIC_CONSTANTS, self.NUMBER_COLOR, is_text_only_token=False)
        self._highlight_selection(text)

    def _highlight_selection(self, text: str):
        """Regex matching for selected word, excluding special characters"""
        if not self.selected or any(c in self.EXCLUDE_FROM_HIGHLIGHT for c in self.selected):
            return
        selection_format = QTextCharFormat()
        selection_format.setBackground(getThemeColor(self.SELECTION_COLOR))
        selection_pattern = f"\\b{self.selected}\\b"
        for match in re.finditer(selection_pattern, text):
            self.setFormat(match.start(), match.end() - match.start(), selection_format)

    def _highlight_tokens(self, text: str, tokens: List[str], color: ThemeColor, is_text_only_token: bool = True) -> None:
        """Regex matching for tokens and coloring. Add word boundaries to text only tokens."""
        text_format = QTextCharFormat()
        text_format.setForeground(getThemeColor(color))
        if is_text_only_token:
            tokens = [f"\\b{token}\\b" for token in tokens]
        for token in tokens:
            for match in re.finditer(token, text):
                self.setFormat(match.start(), match.end() - match.start(), text_format)


def add_dewolf_widget():
    """Add widget to GUI"""
    UIAction.registerAction("dewolf decompiler")
    UIActionHandler.globalActions().bindAction("dewolf decompiler", UIAction(DewolfWidget.createPane, DewolfWidget.canCreatePane))
    Menu.mainMenu("Tools").addAction("dewolf decompiler", "dewolf decompiler")
