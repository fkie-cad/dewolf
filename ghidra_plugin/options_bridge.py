"""Bridge dewolf's options (default.json) into Ghidra's Tool Options.

This mirrors what the Binary Ninja plugin does with BN Settings: it exposes dewolf's
non-hidden options in the native settings UI (Edit -> Tool Options -> dewolf) and reads
the user's choices back at decompile time.

Ghidra options are hierarchical, path-separated by ``.``. We register each dewolf option
under ``dewolf.<Group Title>.<dest>`` so the group titles from default.json become the
subcategories shown in the options tree, and read them back by the same path.
"""

from __future__ import annotations

import logging

from decompiler.util.options import Options

CATEGORY = "dewolf"

# Only scalar option types are exposed in Ghidra's options. Non-scalar types (arrays such
# as `logging.show_selected`) are left at their default: exposing them would require a
# custom editor, and naively round-tripping them through a string corrupts the value
# (e.g. `[]` -> "[]") and breaks Options.getlist at decompile time.
_SCALAR_TYPES = {"boolean", "number", "string"}

logger = logging.getLogger("dewolf.ghidra_gui")


def _option_type(jvm, type_name: str):
    """Map a default.json option 'type' to a Ghidra OptionType."""
    OptionType = jvm("ghidra.framework.options.OptionType")
    return {
        "boolean": OptionType.BOOLEAN_TYPE,
        "number": OptionType.INT_TYPE,
        "string": OptionType.STRING_TYPE,
    }.get(type_name, OptionType.STRING_TYPE)


def _path(group_title: str, dest: str) -> str:
    # Ghidra shows the leading path elements as a tree; keep the raw dest as the leaf so
    # reading back is unambiguous. Category is prepended by tool.getOptions(CATEGORY).
    return f"{group_title}.{dest}"


def register(tool) -> None:
    """Register all non-hidden dewolf options into the tool's 'dewolf' options category."""
    from jpype import JClass

    options = tool.getOptions(CATEGORY)
    defaults = Options._read_json_file(Options.DEFAULT_CONFIG)
    count = 0
    for group in defaults:
        title = group.get("title", "General")
        for option in group.get("options", []):
            if option.get("is_hidden_from_gui", False):
                continue
            if option.get("type", "string") not in _SCALAR_TYPES:
                continue  # arrays etc. are not round-trippable; leave at default
            dest = option["dest"]
            name = _path(title, dest)
            try:
                if options.getType(name) != JClass("ghidra.framework.options.OptionType").NO_TYPE:
                    continue  # already registered (relaunch)
            except Exception:  # noqa: BLE001
                pass
            default_value = _coerce_default(option)
            description = option.get("description", "")
            try:
                options.registerOption(name, _option_type(JClass, option.get("type", "string")), default_value, None, description)
                count += 1
            except Exception:  # noqa: BLE001
                logger.debug("failed to register option %s", name, exc_info=True)
    logger.info("registered %d dewolf options in Ghidra Tool Options", count)


def _coerce_default(option: dict):
    from jpype import JInt

    value = option.get("default")
    type_name = option.get("type", "string")
    if type_name == "number":
        return JInt(int(value))
    if type_name == "boolean":
        return bool(value)
    return str(value)


def read_overrides(tool) -> dict:
    """Read the current dewolf option values from the tool as a {dest: value} dict.

    Only values that differ from being unset are returned; the dict is fed to
    ``Options.update`` so it overrides the defaults loaded from default.json.
    """
    if tool is None:
        return {}
    from jpype import JClass

    OptionType = JClass("ghidra.framework.options.OptionType")
    options = tool.getOptions(CATEGORY)
    overrides: dict = {}
    defaults = Options._read_json_file(Options.DEFAULT_CONFIG)
    for group in defaults:
        title = group.get("title", "General")
        for option in group.get("options", []):
            if option.get("is_hidden_from_gui", False):
                continue
            type_name = option.get("type", "string")
            if type_name not in _SCALAR_TYPES:
                continue  # not registered; keep dewolf's default (do not override)
            dest = option["dest"]
            name = _path(title, dest)
            try:
                if type_name == "boolean":
                    overrides[dest] = bool(options.getBoolean(name, bool(option.get("default", False))))
                elif type_name == "number":
                    overrides[dest] = int(options.getInt(name, int(option.get("default", 0))))
                else:
                    overrides[dest] = str(options.getString(name, str(option.get("default", ""))))
            except Exception:  # noqa: BLE001
                logger.debug("failed to read option %s", name, exc_info=True)
    return overrides
