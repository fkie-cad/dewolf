"""Command line interface for the decompiler."""
from argparse import ArgumentParser
from enum import Enum
from os import isatty
from os.path import isfile
from sys import stdout

from decompiler.logger import configure_logging
from decompiler.util.decoration import DecoratedCode


class Colorize(Enum):
    """Enum specifying if output should be colorized."""

    ALWAYS = "always"
    NEVER = "never"
    AUTO = "auto"


def parse_commandline():
    """Parse the current command line options for the arguments required for the decompiler."""

    def _is_valid_decompile_target(path: str):
        """Check if the given path is a valid decompilation target."""
        if not isfile(path):
            raise ValueError(f"{path} is not a valid file for decompilation!")
        else:
            return path

    parser = ArgumentParser("Decompiler")
    parser.add_argument("binary", type=_is_valid_decompile_target, help="Binaryninja input binary file")
    parser.add_argument("function", nargs="*", help="The name or address of a function to decompiled")
    parser.add_argument("--verbose", "-v", dest="verbose", action="store_true", help="Utilize verbose logging")
    parser.add_argument("--color", type=Colorize, choices=list(Colorize), default=Colorize.AUTO)
    parser.add_argument("--output", "-o", dest="outfile", help="The file in which to place decompilation output")
    parser.add_argument("--all", "-a", dest="all", action="store_true", help="Decompile all functions in this binary")
    return parser.parse_args()


def main(interface: "Decompiler"):
    """Main function for command line invocation."""
    args = parse_commandline()
    if args.verbose:
        configure_logging(level="DEBUG")
    else:
        configure_logging(level="WARNING")

    options = interface.create_options()
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
