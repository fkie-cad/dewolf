"""Command line interface for the decompiler."""

from argparse import SUPPRESS, ArgumentParser
from enum import Enum
from os import isatty
from os.path import isfile
from sys import stdout

from decompiler.logger import configure_logging
from decompiler.util.decoration import DecoratedCode
from decompiler.util.options import Options

VERBOSITY_TO_LOG_LEVEL = {0: "ERROR", 1: "WARNING", 2: "INFO", 3: "DEBUG"}


class Colorize(str, Enum):
    """Enum specifying if output should be colorized. note: subclass str for json.dumps"""

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

    parser = ArgumentParser(description=__doc__, epilog="", argument_default=SUPPRESS, add_help=False)
    # register CLI-specific arguments
    parser.add_argument("binary", type=_is_valid_decompile_target, help="Binaryninja input binary file")
    parser.add_argument("function", nargs="*", help="The name or address of a function to decompiled", default=None)
    parser.add_argument("--help", "-h", action="help", help="Show this help message and exit")
    parser.add_argument(
        "--verbose", "-v", dest="verbose", action="count", help="Set logging verbosity, e.g., -vvv for DEBUG logging", default=0
    )
    parser.add_argument("--color", type=Colorize, choices=list(Colorize), default=Colorize.AUTO)
    parser.add_argument("--output", "-o", dest="outfile", help="The file in which to place decompilation output", default=None)
    parser.add_argument("--all", "-a", dest="all", action="store_true", help="Decompile all functions in this binary", default=False)
    parser.add_argument("--print-config", dest="print", action="store_true", help="Print current config and exit", default=False)
    parser.usage = parser.format_usage().lstrip("usage: ")  # Don't add expert args to usage
    Options.register_defaults_in_argument_parser(parser)  # register expert arguments
    return parser.parse_args()


def main(interface: "Decompiler"):
    """Main function for command line invocation."""
    args = parse_commandline()
    configure_logging(level=VERBOSITY_TO_LOG_LEVEL[min(3, args.verbose)])

    options = Options.from_cli(args)
    if args.print:
        print(options)
        return

    decompiler = interface.from_path(args.binary, options)
    if args.outfile is None:
        output_stream = None
        color = args.color == Colorize.ALWAYS or (args.color != Colorize.NEVER and isatty(stdout.fileno()))
    else:
        output_stream = open(args.outfile, "w", encoding="utf-8")
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
        if output_stream is not None:
            output_stream.close()
