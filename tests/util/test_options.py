import pytest
from decompiler.util.options import Options

cli_options = Options.from_cli()
gui_options = Options.from_gui()
dict_options = Options.from_dict({"opt.bool": True})

cli_options.set("opt.string", "string")
cli_options.set("opt.int", 42)
cli_options.set("opt.bool", True)
cli_options.set("opt.list", ["one", "two"])


def test_cli_get_string():
    assert cli_options.getstring("opt.string") == "string"
    assert cli_options.getstring("opt.string", fallback="fallback") == "string"
    assert cli_options.getstring("opt.int", fallback="fallback") == "42"
    assert cli_options.getstring("opt.bool", fallback="fallback") == "true"
    assert cli_options.getstring("opt.missing", fallback="FALLBACK") == "FALLBACK"
    with pytest.raises(KeyError):
        cli_options.getstring("opt.missing")


def test_cli_get_boolean():
    assert cli_options.getboolean("opt.bool") == True
    assert cli_options.getboolean("opt.bool", fallback=False) == True
    assert cli_options.getboolean("opt.missing", fallback=False) == False
    with pytest.raises(KeyError):
        cli_options.getboolean("opt.missing")
    with pytest.raises(KeyError):
        cli_options.getboolean("opt.int")


def test_cli_get_int():
    assert cli_options.getint("opt.int") == 42
    assert cli_options.getint("opt.int", fallback=43) == 42
    assert cli_options.getint("opt.missing", fallback=43) == 43
    with pytest.raises(KeyError):
        cli_options.getint("opt.missing")
    with pytest.raises(KeyError):
        cli_options.getint("opt.string")


def test_cli_get_list():
    assert cli_options.getlist("opt.list") == ["one", "two"]
    assert cli_options.getlist("opt.list", fallback=[]) == ["one", "two"]
    assert cli_options.getlist("opt.missing", fallback=["fallback"]) == ["fallback"]
    with pytest.raises(KeyError):
        cli_options.getlist("opt.missing")
    with pytest.raises(KeyError):
        cli_options.getlist("opt.int")


def test_from_dict():
    assert dict_options.getboolean("opt.bool")
