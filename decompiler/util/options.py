"""File in charge of managing config and commandline options for decompilation."""
import json
import logging
from argparse import ArgumentParser, BooleanOptionalAction, Namespace
from copy import deepcopy
from os.path import dirname, isfile, join
from typing import Dict, Iterator, List, Optional, Tuple, Union

from binaryninja import Settings


def deprecated_option_setter(func):
    """Allow deprecated Options.set("section", "key", value)"""

    def inner(self, *args):
        if len(args) == 2:
            key = args[0]
            value = args[1]
        else:
            key = ".".join(args[:-1])
            value = args[-1]
            logging.warning(
                f'Deprecation warning: use {func.__name__}("section.key", value) instead of {func.__name__}("section", "key", value)'
            )
        return func(self, key, value)

    return inner


def deprecated_option_getter(func):
    """Allow deprecated Options.get..("section", "key")"""

    def inner(self, *args, fallback=None):
        key = ".".join(args)
        if len(args) > 1:
            logging.warning(f'Deprecation warning: use {func.__name__}("section.key") instead of {func.__name__}("section", "key")')
        return func(self, key, fallback=fallback)

    return inner


class Options:
    """Class in charge of parsing the options for the decompiler."""

    base = dirname(__file__)
    DEFAULT_CONFIG = join(base, "default.json")
    USER_CONFIG = join(base, "../../", "config.json")
    BN_OPTION_GROUP = "dewolf"
    BN_GROUP_DESCRIPTION = "Dewolf decompiler"
    BN_PROPERTY_KEYS = {"default", "title", "type", "description", "elementType", "enum", "enumDescriptions"}

    def __init__(
        self, defaults: Optional[List[Dict]] = None, settings_key_values: Optional[Dict[str, Union[str, int, bool, list]]] = None
    ) -> None:
        logging.debug("initialize Options")
        self._defaults = defaults if defaults is not None else {}
        self._settings_key_values = settings_key_values if settings_key_values is not None else {}
        self._is_gui: bool = False
        self._bn_settings: Settings

    def __str__(self) -> str:
        return json.dumps(self._settings_key_values, indent=4)

    @property
    def is_gui(self) -> bool:
        return self._is_gui

    @is_gui.setter
    def is_gui(self, flag: bool):
        """Set is_gui flag and call appropriate functions"""
        self._is_gui = flag
        if self._is_gui:
            self._register_gui_settings()

    def _load_user_config(self):
        """Load additional user settings and override defaults"""
        if isfile(self.USER_CONFIG):
            logging.debug(f"user config found at {self.USER_CONFIG}")
            with open(self.USER_CONFIG, "r") as f:
                try:
                    self._settings_key_values.update(json.load(f))
                except json.JSONDecodeError:
                    logging.warning(f"could not load user config at {self.USER_CONFIG}")

    def _get_binaryninja_option_json(self, option: dict) -> str:
        """Extract binaryninja setting properties from default.json"""
        return json.dumps({k: option[k] for k in self.BN_PROPERTY_KEYS & option.keys()})

    def _register_gui_settings(self) -> None:
        """Register default settings in binaryninja gui"""
        logging.debug("registering default settings in binaryninja")
        self._bn_settings = Settings()
        self._bn_settings.register_group(self.BN_OPTION_GROUP, self.BN_GROUP_DESCRIPTION)
        for option_group in self._defaults:
            for option in option_group["options"]:
                if option.get("is_hidden_from_gui", False):
                    continue
                key = f"{self.BN_OPTION_GROUP}.{option['dest']}"
                if not self._bn_settings.contains(key):
                    properties = self._get_binaryninja_option_json(option)
                    self._bn_settings.register_setting(key, properties)

    @deprecated_option_setter
    def set(self, key: str, value):
        """Set key to value"""
        self._settings_key_values[key] = value

    @deprecated_option_getter
    def getstring(self, key: str, fallback: Optional[str] = None) -> str:
        """
        Return string value for key. Convert value to string (like Settings.get_string)
        :param key - str: setting key ("section.setting")
        :param fallback - str: if given, return fallback on KeyError
        """
        if self.is_gui and self._bn_settings.contains(self.BN_OPTION_GROUP + "." + key):
            return self._bn_settings.get_string(self.BN_OPTION_GROUP + "." + key)
        else:
            if (value := self._settings_key_values.get(key, fallback)) is not None:
                return value if isinstance(value, str) else str(value).lower()
        raise KeyError(f"Invalid setting for {key}")

    @deprecated_option_getter
    def getboolean(self, key: str, fallback: Optional[bool] = None) -> bool:
        """
        Return boolean value for key.
        :param key - str: setting key ("section.setting")
        :param fallback - bool: if given, return fallback on KeyError
        """
        if self.is_gui and self._bn_settings.contains(self.BN_OPTION_GROUP + "." + key):
            return self._bn_settings.get_bool(self.BN_OPTION_GROUP + "." + key)
        else:
            if (value := self._settings_key_values.get(key, fallback)) is not None:
                if isinstance(value, bool):
                    return value
        raise KeyError(f"Invalid setting for {key}")

    @deprecated_option_getter
    def getlist(self, key: str, fallback: Optional[List[str]] = None) -> List[str]:
        """
        Return List[str] value for key.
        :param key - str: setting key ("section.setting")
        :param fallback - List[str]: if given, return fallback on KeyError
        """
        if self.is_gui and self._bn_settings.contains(self.BN_OPTION_GROUP + "." + key):
            return self._bn_settings.get_string_list(self.BN_OPTION_GROUP + "." + key)
        else:
            if (value := self._settings_key_values.get(key, fallback)) is not None:
                if isinstance(value, list):
                    return value
        raise KeyError(f"Invalid setting for {key}")

    @deprecated_option_getter
    def getint(self, key: str, fallback: Optional[int] = None) -> int:
        """
        Return integer value for key.
        :param key - str: setting key ("section.setting")
        :param fallback - int: if given, return fallback on KeyError
        """
        if self.is_gui and self._bn_settings.contains(self.BN_OPTION_GROUP + "." + key):
            return self._bn_settings.get_integer(self.BN_OPTION_GROUP + "." + key)
        else:
            if (value := self._settings_key_values.get(key, fallback)) is not None:
                if isinstance(value, int):
                    return value
        raise KeyError(f"Invalid setting for {key}")

    @classmethod
    def load_default_options(cls):
        """Parse default options for the decompiler."""
        defaults = cls._read_json_file(cls.DEFAULT_CONFIG)
        settings_key_values = {key: value for key, value in cls._get_key_value_pairs_from_defaults(defaults)}
        return cls(defaults=defaults, settings_key_values=settings_key_values)

    @classmethod
    def from_gui(cls):
        """Parse default options and register in binaryninja settings"""
        options = cls.load_default_options()
        options.is_gui = True
        return options

    @classmethod
    def from_cli(cls, args: Optional[Namespace] = None):
        """
        Create Options for CLI invocation. Different option sources are applied in (reverse) order of precedence:
            1. Default options        (recommended settings from default.json)
            2. User config            (config.json from dewolf root, overrides defaults)
            3. Command line arguments (override the previous)
        """
        options = cls.load_default_options()
        options.is_gui = False
        options._load_user_config()
        if args is not None:
            options._settings_key_values.update(vars(args))
        return options

    @classmethod
    def from_dict(cls, options_dict: Dict[str, Union[bool, str, int, list]]):
        """Create Options from dict only"""
        return cls(settings_key_values=deepcopy(options_dict))

    @classmethod
    def register_defaults_in_argument_parser(cls, parser: ArgumentParser):
        """Register default options in ArgumentParser"""
        option_groups = cls._read_json_file(cls.DEFAULT_CONFIG)
        for group in option_groups:
            argument_group = parser.add_argument_group(title=group["title"], description=group["description"])
            for args, kwargs in cls._iter_argparse_kwargs_for_default_options(group["options"]):
                argument_group.add_argument(*args, **kwargs)

    @staticmethod
    def _get_argparse_kwargs_from_dict(option: Dict) -> Tuple[List, Dict]:
        """Create keyword arguments for ArgumentParser.add_argument() from dicts found in default.json"""
        args = [option["argument_name"]]
        kwargs = {
            "dest": option["dest"],
            "help": option["description"],
        }
        if "enum" in option:
            kwargs["choices"] = option["enum"]
        default = option["default"]
        if default and isinstance(default, list):
            default = " ".join(default)
        kwargs["help"] += f" (default: {default})"
        return args, kwargs

    @classmethod
    def _arg_bool(cls, option: Dict):
        """Create additional kwargs for boolean option (flag), and its negation"""
        args, kwargs = cls._get_argparse_kwargs_from_dict(option)
        kwargs["action"] = BooleanOptionalAction
        return args, kwargs

    @classmethod
    def _arg_array(cls, option: Dict):
        """Create additional kwargs for array option"""
        args, kwargs = cls._get_argparse_kwargs_from_dict(option)
        kwargs["nargs"] = "*"
        return args, kwargs

    @classmethod
    def _arg_number(cls, option: Dict):
        """Create additional kwargs for number option"""
        args, kwargs = cls._get_argparse_kwargs_from_dict(option)
        kwargs["type"] = int
        if not "choices" in kwargs:
            kwargs["metavar"] = "INTEGER"
        return args, kwargs

    @classmethod
    def _arg_string(cls, option: Dict):
        """Create additional kwargs for string option"""
        args, kwargs = cls._get_argparse_kwargs_from_dict(option)
        kwargs["type"] = str
        if not "choices" in kwargs:
            kwargs["metavar"] = "STRING"
        return args, kwargs

    @classmethod
    def _iter_argparse_kwargs_for_default_options(cls, options: List[Dict]):
        """Iterate default options and yield args + kwargs for registering in argparse"""

        ARG_TYPE_HANDLER = {"boolean": cls._arg_bool, "array": cls._arg_array, "number": cls._arg_number, "string": cls._arg_string}

        for option in options:
            if option["is_hidden_from_cli"]:
                continue
            yield ARG_TYPE_HANDLER[option["type"]](option)

    @staticmethod
    def _read_json_file(filepath: str):
        """Return parsed JSON file"""
        with open(filepath, "r") as f:
            return json.load(f)

    @staticmethod
    def _get_key_value_pairs_from_defaults(defaults: List[Dict]) -> Iterator[Tuple[str, Union[str, int, list, bool]]]:
        """Extract key value pairs from defaults"""
        for option_group in defaults:
            for option in option_group["options"]:
                yield option["dest"], option["default"]

    def __getitem__(self, item: str) -> dict:
        """Some scripts still use options["a"]["b"]"""
        logging.warning("Deprecation warning: subscripting of Options")
        subscriptable_dict = {}
        for settings_key in [key for key in self._settings_key_values.keys() if key.startswith(item)]:
            setting = settings_key.split(".")[-1]
            subscriptable_dict[setting] = self._settings_key_values[settings_key]
        return subscriptable_dict
