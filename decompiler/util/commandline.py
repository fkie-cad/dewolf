"""Command line interface for the decompiler."""
from argparse import ArgumentParser
from enum import Enum
from os import isatty
from os.path import isfile
from sys import stdout
from typing import Dict, List, Union

from decompiler.logger import configure_logging
from decompiler.util.decoration import DecoratedCode
from decompiler.util.options import Options


class Colorize(str, Enum):
    """Enum specifying if output should be colorized."""

    ALWAYS = "always"
    NEVER = "never"
    AUTO = "auto"

    def __str__(self):
        """Print choices=list(Colorize) as {always, never, auto}"""
        return self.value

def parse_commandline():
    """Parse the current command line options for the arguments required for the decompiler."""

    def _is_valid_decompile_target(path: str):
        """Check if the given path is a valid decompilation target."""
        if not isfile(path):
            raise ValueError(f"{path} is not a valid file for decompilation!")
        else:
            return path

    # register CLI-specific arguments
    parser = ArgumentParser(prog="Decompiler", description="", epilog="")
    parser.add_argument("binary", type=_is_valid_decompile_target, help="Binaryninja input binary file")
    parser.add_argument("function", nargs="*", help="The name or address of a function to decompiled")
    parser.add_argument("--verbose", "-v", dest="verbose", action="count", help="Set logging verbosity, e.g., -vvv for DEBUG logging", default=0)
    parser.add_argument("--color", type=Colorize, choices=list(Colorize), default=Colorize.AUTO)
    parser.add_argument("--output", "-o", dest="outfile", help="The file in which to place decompilation output")
    parser.add_argument("--all", "-a", dest="all", action="store_true", help="Decompile all functions in this binary")
    Options.register_args(parser) # register expert arguments
    return parser.parse_known_args()


def switch_to_dict(options: List[str]) -> Dict[str, Dict[str, Union[str, int]]]:
    """Function reformatting command line options for usage by the Options module."""
    parsed = {}
    while options and (option := options.pop(0)):
        if not option.startswith("--"):
            raise ValueError(f"Unknown positional argument '{option}'.")
        if "." not in option:
            raise ValueError(f"Argument without category '{option}'. Please use --<category>.<option>")
        category, name = option[2:].split(".")
        # Check if the next option element is the value of the current option, or mimic store_true
        if len(options) > 0 and not options[0].startswith("--"):
            print(f"popped {options[0]}")
            value = options.pop(0)
        else:
            value = True
        if category not in parsed:
            parsed[category] = {}
        parsed[category][name] = value
    return parsed



def main(interface: "Decompiler"):
    """Main function for command line invocation."""
    args, reminder = parse_commandline()
    if args.verbose >= 3:
        configure_logging(level="DEBUG")
    elif args.verbose == 2:
        configure_logging(level="INFO")
    elif args.verbose == 1:
        configure_logging(level="WARNING")
    else:
        configure_logging(level="ERROR")

    # options = interface.create_options(switch_to_dict(reminder))
    print(args)
    options = Options.from_cli(args)
    print(options)
    print(reminder)
    assert False, "break here"
    decompiler = interface.from_path(args.binary, options)
    if args.outfile is None:
        output_stream = None
        color = args.color == Colorize.ALWAYS or (args.color != Colorize.NEVER and isatty(stdout.fileno()))
    else:
        output_stream = open(args.outfile, "w")
        color = False
    try:
        if args.all or not args.function:
            # decompile all functions.
            undecorated_code = decompiler.decompile_all(options)
            DecoratedCode.print_code(
                undecorated_code, output_stream, color, style=options.getstring("code-generator.style_cmd", fallback="paraiso-dark")
            )
        else:
            for function_name in args.function:
                task = decompiler.decompile(function_name, options)
                DecoratedCode.print_code(
                    task.code, output_stream, color, style=task.options.getstring("code-generator.style_cmd", fallback="paraiso-dark")
                )
    finally:
        if args.outfile is not None:
            output_stream.close()
