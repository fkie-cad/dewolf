"""Unit tests for the Ghidra GUI plugin's token stream (``ghidra_plugin/tokenizer.py``).

The plugin turns dewolf's formatted C into a classified ``(kind, text, address, indent)`` stream
that the Java ``DewolfProvider`` renders in the panel. This is pure Python (no JVM / no live Ghidra),
so we can pin the classification and the line/indentation handling directly, mirroring how the Binary
Ninja plugin is smoke-tested by ``tests/test_plugin.py`` -- but here at the token level.
"""

from ghidra_plugin.tokenizer import BREAK, COMMENT, CONST, DEFAULT, FUNCTION, GLOBAL, KEYWORD, TYPE, VARIABLE, message_tokens, tokenize


def _classify(name):
    """Fake name classifier: functions/globals carry an address, everything else is a plain variable."""
    table = {"main": (FUNCTION, 0x1000), "g_flag": (GLOBAL, 0x2000)}
    return table.get(name, (VARIABLE, -1))


def _kinds(tokens):
    return [(kind, text) for kind, text, _addr, _indent in tokens]


def test_keywords_types_and_constants_are_classified():
    tokens = _kinds(tokenize("return 0x10;", _classify))
    assert (KEYWORD, "return") in tokens
    assert (CONST, "0x10") in tokens


def test_int_typedefs_render_as_types_not_variables():
    # size_t / uintN_t etc. are matched by the type pattern even though the C lexer sees them as names
    for type_name in ("uint32_t", "int8_t", "size_t", "bool"):
        tokens = _kinds(tokenize(f"{type_name} x;", _classify))
        assert (TYPE, type_name) in tokens


def test_true_false_null_are_constants_not_variables():
    for literal in ("true", "false", "NULL"):
        tokens = _kinds(tokenize(f"x = {literal};", _classify))
        assert (CONST, literal) in tokens


def test_names_are_classified_via_the_callback():
    tokens = tokenize("main(g_flag, local);", _classify)
    by_text = {text: (kind, addr) for kind, text, addr, _ in tokens}
    assert by_text["main"] == (FUNCTION, 0x1000)
    assert by_text["g_flag"] == (GLOBAL, 0x2000)
    assert by_text["local"] == (VARIABLE, -1)


def test_line_breaks_carry_the_following_indent_as_space_columns():
    code = "int f() {\n    return 0;\n}"
    tokens = tokenize(code, _classify)
    breaks = [tok for tok in tokens if tok[0] == BREAK]
    # two newlines -> two BREAK tokens; the first carries the 4-space indent of "    return 0;"
    assert len(breaks) == 2
    assert breaks[0][3] == 4
    assert breaks[1][3] == 0


def test_no_leading_break_before_the_first_line():
    tokens = tokenize("int x;", _classify)
    assert tokens[0][0] != BREAK


def test_comments_are_classified():
    tokens = _kinds(tokenize("// a note", _classify))
    assert tokens and tokens[0][0] == COMMENT


def test_message_tokens_render_each_line_as_a_comment():
    tokens = message_tokens("line one\nline two")
    kinds = [tok[0] for tok in tokens]
    assert kinds == [COMMENT, BREAK, COMMENT]
    assert tokens[0][1] == "line one"
    assert tokens[2][1] == "line two"


def test_operators_and_punctuation_are_default_kind():
    tokens = tokenize("a + b;", _classify)
    assert any(kind == DEFAULT and text.strip() == "+" for kind, text, _, _ in tokens)
