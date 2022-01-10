"""File in charge of managing config and commandline options for decompilation."""
import json
import logging
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
        self, defaults: Optional[Dict[str, dict]] = None, settings_key_values: Optional[Dict[str, Union[str, int, bool, list]]] = None
    ) -> None:
        logging.debug("initialize Options")
        self._defaults = defaults if defaults is not None else {}
        self._settings_key_values = settings_key_values if settings_key_values is not None else {}
        self._is_gui: bool = False
        self._bn_settings: Settings

    @property
    def is_gui(self) -> bool:
        return self._is_gui

    @is_gui.setter
    def is_gui(self, flag: bool):
        """Set is_gui flag and call appropriate functions"""
        self._is_gui = flag
        if self._is_gui:
            self._register_gui_settings()
        else:
            self._load_user_config()

    def _load_user_config(self):
        """Load additional user settings and override defaults"""
        if isfile(self.USER_CONFIG):
            logging.debug(f"user config found at {self.USER_CONFIG}")
            with open(self.USER_CONFIG, "r") as f:
                try:
                    self._settings_key_values.update(json.load(f))
                except json.JSONDecodeError:
                    logging.warning(f"could not load user config at {self.USER_CONFIG}")

    def _get_binary_ninja_settings_properties_json(self, properties_dict: dict) -> str:
        """Extract binaryninja setting properties from default.json"""
        return json.dumps({k: properties_dict[k] for k in self.BN_PROPERTY_KEYS & properties_dict.keys()})

    def _register_gui_settings(self) -> None:
        """Register default settings in binaryninja gui"""
        logging.debug("registering default settings in BN")
        self._bn_settings = Settings()
        self._bn_settings.register_group(self.BN_OPTION_GROUP, self.BN_GROUP_DESCRIPTION)
        for section, section_settings in self._defaults.items():
            for setting, properties_dict in section_settings.items():
                if properties_dict.get("is_hidden_from_gui", False):
                    continue
                key = f"{self.BN_OPTION_GROUP}.{section}.{setting}"
                if not self._bn_settings.contains(key):
                    properties = self._get_binary_ninja_settings_properties_json(properties_dict)
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

    def add_cmdline_options(self, extra_options: Optional[Dict]):
        """Add command line options to the options dictionary"""
        for category, settings in extra_options.items() if extra_options else {}.items():
            for name, value in settings:
                self._settings_key_values[f"{category}.{name}"] = value

    @classmethod
    def from_gui(cls):
        """Parse default options and register in binaryninja settings"""
        options = cls.load_default_options()
        options.is_gui = True
        return options

    @classmethod
    def from_cli(cls):
        """Parse default options and load user config"""
        options = cls.load_default_options()
        options.is_gui = False
        return options

    @classmethod
    def from_dict(cls, options_dict: Dict[str, Union[bool, str, int, list]]):
        """Create Options from dict only (primarily for unittests)"""
        return cls(settings_key_values=deepcopy(options_dict))

    @classmethod
    def load_default_options(cls):
        """Parse default options for the decompiler."""
        defaults = cls._read_json_file(cls.DEFAULT_CONFIG)
        settings_key_values = {key: value for key, value in cls._get_default_key_value_pairs(defaults)}
        return cls(defaults=defaults, settings_key_values=settings_key_values)

    @staticmethod
    def _read_json_file(filepath: str) -> Dict[str, dict]:
        """Parse default.json into dict for further processing"""
        with open(filepath, "r") as f:
            return json.load(f)

    @staticmethod
    def _get_default_key_value_pairs(defaults: Dict[str, dict]) -> Iterator[Tuple[str, Union[str, int, list, bool]]]:
        """Extract key value pairs from defaults"""
        for section, section_settings in defaults.items():
            for setting, properties in section_settings.items():
                yield f"{section}.{setting}", properties["default"]

    def __getitem__(self, item: str) -> dict:
        """Some scripts still use options["a"]["b"]"""
        logging.warning("Deprecation warning: subscripting of Options")
        subscriptable_dict = {}
        for settings_key in [key for key in self._settings_key_values.keys() if key.startswith(item)]:
            setting = settings_key.split(".")[-1]
            subscriptable_dict[setting] = self._settings_key_values[settings_key]
        return subscriptable_dict
