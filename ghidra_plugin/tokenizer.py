"""Turn dewolf's formatted C output into a classified token stream for the plugin.

Tokens are (kind, text, address, indent) tuples. `kind` values reuse Ghidra's
ClangToken color constants (see DewolfTokenData.java); BREAK (-1) separates lines,
carrying the indent of the *following* line as a COUNT OF LEADING SPACES (columns) —
Ghidra's panel renders a ClangBreak's indent as that many single-space widths
(PrettyPrinter.INDENT_STRING == " "), so this must be columns, not indent levels.
"""
from __future__ import annotations

import re
from typing import Callable, Iterator

from pygments.lexers.c_cpp import CppLexer
from pygments.token import Comment, Keyword, Literal, Name, String

# ClangToken color constants (must match ghidra.app.decompiler.ClangToken)
KEYWORD = 0
COMMENT = 1
TYPE = 2
FUNCTION = 3
VARIABLE = 4
CONST = 5
PARAMETER = 6
GLOBAL = 7
DEFAULT = 8
BREAK = -1

_INT_TYPE_PATTERN = re.compile(r"^u?int\d+_t$|^size_t$|^ssize_t$|^bool$")

Classifier = Callable[[str], tuple[int, int]]
Token = tuple[int, str, int, int]

_lexer = CppLexer()


def tokenize(code: str, classify_name: Classifier) -> list[Token]:
    """Tokenize formatted C code; `classify_name` maps an identifier to (kind, address)."""
    tokens: list[Token] = []
    for index, line in enumerate(code.splitlines()):
        stripped = line.lstrip(" ")
        # ClangBreak indents by this many single-space widths, so pass the raw leading-space
        # count (astyle already indents the source); dividing to an indent level would render
        # only one space per level.
        indent = len(line) - len(stripped)
        if index > 0:
            tokens.append((BREAK, "", -1, indent))
        tokens.extend(_tokenize_line(stripped, classify_name))
    return tokens


def _tokenize_line(line: str, classify_name: Classifier) -> Iterator[Token]:
    # per-line lexing keeps indentation handling trivial; dewolf emits only
    # single-line ('//') comments, so no lexer state spans lines
    for token_type, value in _lexer.get_tokens(line):
        # we lex line-wise, so any newline is a pygments artifact (appended trailing
        # newline, or one embedded in e.g. a Comment.Single token)
        value = value.replace("\n", "")
        if not value:
            continue
        if token_type in Comment:
            yield (COMMENT, value, -1, 0)
        elif token_type in Keyword.Type:
            yield (TYPE, value, -1, 0)
        elif token_type in Keyword:
            yield (KEYWORD, value, -1, 0)
        elif token_type in Literal or token_type in String:
            yield (CONST, value, -1, 0)
        elif token_type in Name:
            if value in ("true", "false", "NULL"):
                yield (CONST, value, -1, 0)
            elif _INT_TYPE_PATTERN.match(value):
                yield (TYPE, value, -1, 0)
            else:
                kind, address = classify_name(value)
                yield (kind, value, address, 0)
        else:  # operators, punctuation, whitespace
            yield (DEFAULT, value, -1, 0)


def message_tokens(text: str) -> list[Token]:
    """Render a plain (error) message as comment lines."""
    tokens: list[Token] = []
    for index, line in enumerate(text.splitlines()):
        if index > 0:
            tokens.append((BREAK, "", -1, 0))
        tokens.append((COMMENT, line, -1, 0))
    return tokens
