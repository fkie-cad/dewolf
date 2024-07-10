import difflib
import itertools
import logging
import timeit
from pathlib import Path

import binaryninja
from decompile import Decompiler
from decompiler.frontend.binaryninja.frontend import BinaryninjaFrontend
from decompiler.pipeline.controlflowanalysis.restructuring_options import CbfNodeOrder
from decompiler.util.decoration import DecoratedCode
from functional import seq
from tqdm import tqdm
from tqdm.contrib.concurrent import process_map
from tqdm.contrib.logging import logging_redirect_tqdm

options_a = Decompiler.create_options()
# options_a.set("pipeline.debug", True)
options_a.set("pattern-independent-restructuring.cbf_node_order", CbfNodeOrder.NONE.value)
options_b = Decompiler.create_options()
# options_b.set("pipeline.debug", True)
options_b.set("pattern-independent-restructuring.cbf_node_order", CbfNodeOrder.SMALLEST_FIRST.value)
options_c = Decompiler.create_options()
# options_c.set("pipeline.debug", True)
options_c.set("pattern-independent-restructuring.cbf_node_order", CbfNodeOrder.BIGGEST_FIRST.value)

options = [options_a, options_b, options_c]


def process_binary(task: tuple[str, list[str]]) -> None:
    binary_name, function_names = task

    logging.getLogger().disabled = True
    binaryninja.disable_default_log()

    binaryninja.set_worker_thread_count(1)
    with logging_redirect_tqdm():
        # options for frontend are different to decompilation options...
        # print(f"creating frontend for {binary_name}")
        frontend = BinaryninjaFrontend.from_path(f"../tests/coreutils/binaries/{binary_name}", Decompiler.create_options())
        # print(f"created frontend {binary_name}")
        decompiler = Decompiler(frontend)

        for function_name in function_names:
            for index, option in enumerate(options):
                outputPath = Path("./output") / binary_name / function_name / str(index)
                if outputPath.exists():
                    continue

                start_time = timeit.default_timer()
                # print(f"decompiling {binary_name}::{function_name}")
                decompiler_task, code = decompiler.decompile(function_name, option)
                # print(f"decompiled {binary_name}::{function_name}")
                end_time = timeit.default_timer()

                decorated_code = DecoratedCode(code)
                decorated_code.reformat()

                outputPath.parent.mkdir(parents=True, exist_ok=True)
                outputPath.write_text(f"{decorated_code.code}\n{end_time - start_time}", encoding="UTF-8")

        # hack, because our api has no way of doing this
        frontend._bv.file.close()


def analyze(binary_name: str, function_names: list[str]) -> dict[str, int]:
    stats: dict[str, int] = {}

    for function_name in function_names:
        code_outputs = []

        for index in range(len(options)):
            outputPath = Path("./output") / binary_name / function_name / str(index)
            if outputPath.exists():
                code_outputs.append(outputPath.read_text(encoding="UTF-8"))

        try:
            max_diff = (seq(itertools.combinations(code_outputs, 2))
                        .map(lambda cases: seq(difflib.ndiff(cases[0].splitlines(keepends=True), cases[1].splitlines(keepends=True)))
                             .count(lambda li: not li.startswith(" ")))
                        .max())
            # print(max_diff)
        except ValueError:
            max_diff = 0

        stats[function_name] = max_diff

    return stats


if __name__ == "__main__":
    functions = (Path("../tests/coreutils/functions.txt")
                 .read_text(encoding="UTF-8")
                 .splitlines())
    tasks = (seq(functions)
             .map(lambda line: line.split(" "))
             .group_by_key()
             .to_list())

    with logging_redirect_tqdm():
        # process_map(process_binary, tasks, max_workers=16)

        stats: dict[str, dict[str, int]] = {}
        for bin_name, function_names in tqdm(tasks, desc="Analyze"):
            stats[bin_name] = analyze(bin_name, function_names)

    report = (
        seq(stats.items())
        .flat_map(lambda bi: seq(bi[1].items()).map(lambda fi: (f"{bi[0]}::{fi[0]}", fi[1])))
        .sorted(key=lambda i: i[1], reverse=True)
        .to_list()
    )

    seq(report).show()
    Path("./report").write_text("\n".join(map(lambda s: f"{s[0]}, {s[1]}", report)), encoding="UTF-8")
