#!/usr/bin/env python3
import argparse
import hashlib
import logging
import sqlite3
import subprocess
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterator, Union

# Add project root to path (script located in dewolf/decompiler/util/bugfinder/)
project_root = Path(__file__).resolve().parents[3]
sys.path.append(str(project_root))
from binaryninja import Function, core_version

# use binaryninja.load for BN 3.5 up
version_numbers = core_version().split(".")
major, minor = int(version_numbers[0]), int(version_numbers[1])
if major >= 3 and minor >= 5:
    from binaryninja import load
else:
    from binaryninja import BinaryViewType

    load = BinaryViewType.get_view_of_file

from decompile import Decompiler
from decompiler.frontend import BinaryninjaFrontend
from decompiler.logger import configure_logging

VERBOSITY_TO_LOG_LEVEL = {0: "ERROR", 1: "WARNING", 2: "INFO", 3: "DEBUG"}


def get_git_commit():
    """Return the first 8 chars of the current commit hash"""
    script_location = Path(__file__).parent
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=script_location, universal_newlines=True).strip()[:8]


def sha256sum(file_path: Union[str, Path]) -> str:
    # https://stackoverflow.com/questions/22058048/hashing-a-file-in-python
    h = hashlib.sha256()
    b = bytearray(128 * 1024)
    mv = memoryview(b)
    with open(file_path, "rb", buffering=0) as f:
        while n := f.readinto(mv):
            h.update(mv[:n])
    return h.hexdigest()


class DBConnector:
    SCHEMA = """CREATE TABLE IF NOT EXISTS dewolf (
        id INTEGER NOT NULL PRIMARY KEY,
        function_name TEXT,
        function_basic_block_count INTEGER,
        function_size INTEGER,
        function_arch TEXT,
        function_platform TEXT,
        sample_hash TEXT,
        sample_name TEXT,
        sample_total_function_count INTEGER,
        sample_decompilable_function_count INTEGER,
        dewolf_current_commit TEXT,
        binaryninja_version TEXT,
        dewolf_max_basic_blocks INTEGER,
        dewolf_exception TEXT,
        dewolf_traceback TEXT,
        dewolf_decompilation_time INTEGER,
        dewolf_undecorated_code TEXT,
        is_successful INTEGER,
        timestamp TEXT
        )
    """

    def __init__(self, db_conn: Union[str, Path]) -> None:
        self.file_path = Path(db_conn)
        logging.debug(f"[Bugfinder] connect DB {self.file_path}")
        self.con = sqlite3.connect(self.file_path)
        self._create_table()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        logging.debug("[Bugfinder] close DB")
        self.con.close()
        return True

    def _create_table(self):
        logging.debug("[Bugfinder] create database")
        self.con.execute(self.SCHEMA)
        self.con.commit()

    def add(self, record: Dict):
        columns = ", ".join(record.keys())
        named_placeholder = ":" + ", :".join(record.keys())
        stmt = f"INSERT INTO dewolf ({columns}) VALUES ({named_placeholder})"
        logging.debug(f"[Bugfinder] DB insert: {stmt}")
        self.con.execute(stmt, record)
        self.con.commit()

    @staticmethod
    def get_sample_info(sample: Path, function_count: int, decompilable_function_count: int) -> dict:
        """
        return dict of sample information
        """
        return {
            "sample_name": sample.name,
            "sample_hash": sha256sum(sample),
            "sample_total_function_count": function_count,
            "sample_decompilable_function_count": decompilable_function_count,
        }

    @staticmethod
    def get_dewolf_info(max_size: int) -> dict:
        """
        return dict of dewolf decompiler information
        """
        return {
            "dewolf_max_basic_blocks": max_size,
            "dewolf_current_commit": get_git_commit(),
            "binaryninja_version": core_version(),
        }

    @staticmethod
    def get_function_info(function: Function) -> dict:
        """
        return dict of decompiled function info
        """
        return {
            "function_name": function.name,
            "function_basic_block_count": len(function.basic_blocks),
            "function_size": function.highest_address - function.start,
            "function_arch": str(function.arch),
            "function_platform": str(function.platform),
            "timestamp": datetime.now(),
        }

    @staticmethod
    def get_successful_info(code: str, time: int) -> dict:
        return {
            "dewolf_decompilation_time": time,
            "dewolf_undecorated_code": code,
            "is_successful": 1,
        }

    @staticmethod
    def get_error_info(e: Exception) -> dict:
        return {
            "dewolf_exception": "".join(traceback.format_exception_only(e)),
            "dewolf_traceback": "".join(traceback.format_tb(e.__traceback__)),
            "is_successful": 0,
        }


class DecompilerReporter(Decompiler):
    """Class for generating decompilation reports"""

    REPORT_OPTIONS = {"pipeline.debug": True}

    def __init__(self, frontend: BinaryninjaFrontend):
        self._function_max_basic_blocks = 15
        super().__init__(frontend)

    @property
    def function_max_basic_blocks(self) -> int:
        """The function_max_basic_blocks property."""
        return self._function_max_basic_blocks

    @function_max_basic_blocks.setter
    def function_max_basic_blocks(self, value: int):
        """Set the basic block threshold above which the function will be skipped for decompilation"""
        self._function_max_basic_blocks = value

    def _bn_functions(self):
        """Iterate frontend function objects"""
        for function in self._frontend._bv:
            if len(function.basic_blocks) > self.function_max_basic_blocks:
                logging.info("[Bugfinder] skip function due to basic block count")
                continue
            if function.name in self._frontend.BLACKLIST:
                logging.info("[Bugfinder] skip function due to dewolf block list")
                continue
            yield function

    def iter_function_reports(self, sample) -> Iterator[dict]:
        """For a given sample yield reports of function decompilations"""
        options = self.create_options()
        options.update(self.REPORT_OPTIONS)
        logging.debug(f"[Bugfinder] dewolf options:\n{options}")
        dewolf_info = DBConnector.get_dewolf_info(self.function_max_basic_blocks)
        decompilable_function_count = sum(1 for _ in self._bn_functions())
        sample_info = DBConnector.get_sample_info(sample, len(self._frontend._bv.functions), decompilable_function_count)
        for function in self._bn_functions():
            logging.debug(f"[Bugfinder] decompiling {function.name}")
            function_info = DBConnector.get_function_info(function)
            try:
                time1 = time.time()
                result = self.decompile([function], task_options=options)
                time2 = time.time()
                decompilation_info = DBConnector.get_successful_info(result.code, int(time2 - time1))
            except Exception as e:
                decompilation_info = DBConnector.get_error_info(e)
            yield {**dewolf_info, **sample_info, **function_info, **decompilation_info}


def store_reports_from_sample(sample: Path, db_reports: DBConnector, max_size: int):
    """Store all reports from sample into database"""
    logging.info(f"processing {sample}")
    if not (binary_view := load(sample)):
        logging.warning(f"Could not get BinaryView '{sample}'")
        return
    try:
        decompiler = DecompilerReporter.from_raw(binary_view)
        decompiler.function_max_basic_blocks = max_size
        for report in decompiler.iter_function_reports(sample):
            db_reports.add(report)
    finally:
        # do not leak memory please
        binary_view.file.close()


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bug finding tool for dewolf decompiler")
    parser.add_argument("input", type=Path, help="Sample file, or folder containing samples")
    parser.add_argument("--sqlite-file", type=Path, help="Path to SQLite file", default="bugs.db")
    parser.add_argument(
        "-s",
        "--function-max-basic-block-size",
        type=int,
        dest="max_size",
        help="Maximum count of basic blocks for decompilation of function",
        default=15,
    )
    parser.add_argument(
        "--verbose", "-v", dest="verbose", action="count", help="Set logging verbosity, e.g., -vvv for DEBUG logging", default=0
    )
    return parser.parse_args()


def main(args: argparse.Namespace) -> int:
    """
    Open DB connection and iterate sample files if directory
    """
    configure_logging(level=VERBOSITY_TO_LOG_LEVEL[min(3, args.verbose)])
    with DBConnector(args.sqlite_file) as db_reports:
        if (corpus := args.input).is_dir():
            for sample in corpus.iterdir():
                store_reports_from_sample(sample, db_reports, max_size=args.max_size)
        elif (sample := args.input).is_file():
            store_reports_from_sample(sample, db_reports, max_size=args.max_size)
    return 0


if __name__ == "__main__":
    args = parse_arguments()
    sys.exit(main(args))
