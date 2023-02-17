#!/usr/bin/env python3
import argparse
import hashlib
import logging
import sqlite3
import subprocess
import sys
import time
import traceback
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Dict, Iterator, Union

# Add project root to path (script located in dewolf/decompiler/util/bugfinder/)
project_root = Path(__file__).resolve().parents[3]
sys.path.append(str(project_root))
from binaryninja import BinaryViewType, Function, core_version
from decompile import Decompiler
from decompiler.frontend import BinaryninjaFrontend
from decompiler.logger import configure_logging
from decompiler.util.options import Options

VERBOSITY_TO_LOG_LEVEL = {0: "ERROR", 1: "WARNING", 2: "INFO", 3: "DEBUG"}


def valid_dir(arg: str) -> Path:
    """Use in argparse to get valid directory"""
    file_path = Path(arg)
    if file_path.exists() and file_path.is_dir():
        return file_path
    raise argparse.ArgumentTypeError(f"not a directory: {arg}")


def get_git_commit():
    """Return current commit hash"""
    script_location = Path(__file__).parent
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=script_location, universal_newlines=True).strip()


def rename(dir_path: Path):
    """Rename all files in dir_path to their hash value. Skip direcotries and symlinks"""
    answer = input(f"CAUTION: This will rename all files contained in {dir_path}. Continue? ")
    if not answer.upper() in ["Y", "YES"]:
        print("aborted renaming of test files")
        return
    for f in dir_path.iterdir():
        if not f.is_file() or f.is_symlink():
            continue
        print(f"TODO: rename {f.name} to {sha256sum(f)}")


def sha256sum(file_path: Union[str, Path]) -> str:
    # https://stackoverflow.com/questions/22058048/hashing-a-file-in-python
    h = hashlib.sha256()
    b = bytearray(128 * 1024)
    mv = memoryview(b)
    with open(file_path, "rb", buffering=0) as f:
        while n := f.readinto(mv):
            h.update(mv[:n])
    return h.hexdigest()


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="deBug", description="Bug finding tool for dewolf decompiler")
    parser.add_argument("corpus", type=valid_dir, help="Folder containing test binaries")
    parser.add_argument("--rename", action="store_true", help="Rename each file in the corpus directory to its hash value")
    parser.add_argument(
        "--verbose", "-v", dest="verbose", action="count", help="Set logging verbosity, e.g., -vvv for DEBUG logging", default=0
    )
    return parser.parse_args()


@dataclass
class FunctionInfo:
    """Class for keeping track of function info"""

    function_name: str
    function_basic_block_count: int
    function_size: int
    function_arch: str
    function_platform: str

    @classmethod
    def from_function(cls, function: Function):
        return cls(
            function_name=function.name,
            function_basic_block_count=len(function.basic_blocks),
            function_size=function.highest_address - function.start,
            function_arch=str(function.arch),
            function_platform=str(function.platform),
        )


@dataclass
class DewolfInfo:
    """Class for keeping track of decompiler info"""

    sample_hash: str
    sample_name: str
    dewolf_options: str
    dewolf_current_commit: str
    binaryninja_version: str

    @classmethod
    def from_options_sample(cls, options: Union[Options, str], sample: Path):
        return cls(
            sample_name=sample.name,
            sample_hash=sha256sum(sample),
            dewolf_options=str(options),
            dewolf_current_commit=get_git_commit(),
            binaryninja_version=core_version() or "",
        )


@dataclass
class DecompilationResult:
    dewolf_exception: str
    dewolf_traceback: str
    dewolf_decompilation_time: int
    dewolf_undecorated_code: str
    is_successful: bool


@dataclass
class FunctionReport:
    """Class for keeping track of a single function report"""

    function_info: FunctionInfo
    dewolf_info: DewolfInfo
    decompilation_result: DecompilationResult

    def __str__(self) -> str:
        return f"{self.dewolf_info.sample_hash}, {self.function_info.function_name}, {self.decompilation_result.is_successful}"

    @classmethod
    def get_table_column_names(cls):
        sub_classes = fields(cls)
        cols = []
        for s in sub_classes:
            cols.extend([f.name for f in fields(s.type)])
        return ", ".join(cols)

    @classmethod
    def fields(cls):
        for subclass in fields(cls):
            for field in fields(subclass.type):
                yield field

    @property
    def record(self) -> Dict:
        record = {}
        for field in fields(self):
            record.update(asdict(getattr(self, field.name)))
        return record


class DBConnector:

    TABLE_NAME = "dewolf"

    def __init__(self, data_model=FunctionReport, db_file: Union[str, Path] = "bugs.db") -> None:
        self.file_path = Path(db_file)
        self.con = sqlite3.connect(self.file_path)
        self.cur = self.con.cursor()
        self.column_names = [f.name for f in data_model.fields()]
        self._create_table()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.con.close()
        return True

    def _create_table(self):
        stmt = f"CREATE TABLE IF NOT EXISTS {self.TABLE_NAME}({', '.join(self.column_names)})"
        self.con.execute(stmt)
        self.con.commit()

    def _is_columns_correct(self):
        cursor = self.con.execute(f"SELECT * FROM {self.TABLE_NAME}")
        col_names = [description[0] for description in cursor.description]
        cursor.close()
        return self.column_names == col_names

    def add(self, record: Dict):
        placeholder = ", ".join("?" for _ in self.column_names)
        stmt = f"INSERT INTO {self.TABLE_NAME} VALUES({placeholder})"
        self.con.execute(stmt, tuple(record[col] for col in self.column_names))
        self.con.commit()


class DecompilerReporter(Decompiler):
    """Class for generating decompilation reports"""

    REPORT_OPTIONS = {"pipeline": {"debug": True}}
    FUNCTION_MAX_BASIC_BLOCKS = 50

    def __init__(self, frontend: BinaryninjaFrontend):
        super().__init__(frontend)

    def _bn_functions(self):
        """Iterate frontend function objects"""
        for function in self._frontend._bv:
            if len(function.basic_blocks) > self.FUNCTION_MAX_BASIC_BLOCKS:
                logging.info("[Bugfinder] skip function due to basic block count")
                continue
            if function.name in self._frontend.BLACKLIST:
                logging.info("[Bugfinder] skip function due to dewolf block list")
                continue
            yield function

    def iter_function_reports(self, sample) -> Iterator[FunctionReport]:
        options = self.create_options(self.REPORT_OPTIONS)
        dewolf_info = DewolfInfo.from_options_sample(options, sample)
        for function in self._bn_functions():
            function_info = FunctionInfo.from_function(function)
            try:
                time1 = time.time()
                task_result = self.decompile(function, options)
                time2 = time.time()
                decompilation_result = DecompilationResult(
                    dewolf_exception="",
                    dewolf_traceback="",
                    dewolf_decompilation_time=int(time2 - time1),
                    dewolf_undecorated_code=task_result.code,
                    is_successful=True,
                )
            except Exception as e:
                # TODO https://docs.python.org/3/library/traceback.html
                # exc_type, exc_value, exc_traceback = sys.exc_info()
                decompilation_result = DecompilationResult(
                    dewolf_exception="".join(traceback.format_exception_only(e)),
                    dewolf_traceback="".join(traceback.format_tb(e.__traceback__)),
                    dewolf_decompilation_time=-1,
                    dewolf_undecorated_code="failed",
                    is_successful=False,
                )
            yield FunctionReport(function_info, dewolf_info, decompilation_result)


def create_and_store_reports(corpus: Path, db_reports: DBConnector):
    for sample in corpus.iterdir():
        logging.info(f"processing {sample}")
        if not sample.is_file() or sample.is_symlink():
            continue
        if not (binary_view := BinaryViewType.get_view_of_file(sample)):
            logging.warning(f"Could not get BinaryView '{sample}'")
            continue
        try:
            decompiler = DecompilerReporter.from_raw(binary_view)
            for report in decompiler.iter_function_reports(sample):
                db_reports.add(report.record)
        finally:
            # do not leak memory please
            binary_view.file.close()


def main(args: argparse.Namespace) -> int:
    configure_logging(level=VERBOSITY_TO_LOG_LEVEL[min(3, args.verbose)])
    if args.rename:
        rename(args.corpus)

    with DBConnector() as db_reports:
        create_and_store_reports(args.corpus, db_reports)
        pass
    return 0


if __name__ == "__main__":
    args = parse_arguments()
    sys.exit(main(args))
