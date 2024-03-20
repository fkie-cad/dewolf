import difflib
import itertools
from pathlib import Path

import binaryninja
from decompile import Decompiler
from decompiler.frontend.binaryninja.frontend import BinaryninjaFrontend
from decompiler.pipeline.ssa.outofssatranslation import SSAOptions
from decompiler.util.decoration import DecoratedCode
from functional import seq
from tqdm import tqdm
from tqdm.contrib.logging import logging_redirect_tqdm

options_a = Decompiler.create_options()
options_a.set("out-of-ssa-translation.mode", SSAOptions.lift_minimal.value)
options_b = Decompiler.create_options()
options_b.set("out-of-ssa-translation.mode", SSAOptions.conditional.value)

options = [options_a, options_b]


def process_binary(item: tuple[str, list[str]]) -> dict[str, int]:
    binaryninja.disable_default_log()
    binary_name, function_names = item

    with (logging_redirect_tqdm()):
        # options for frontend are different to decompilation options...
        frontend = BinaryninjaFrontend.from_path(f"../tests/coreutils/binaries/{binary_name}", Decompiler.create_options())
        decompiler = Decompiler(frontend)

        stats: dict[str, int] = {}

        for function_name in (fbar := tqdm(function_names, leave=False)):
            fbar.set_description(f"Decompiling function '{function_name}'")
        # for function_name in function_names:
            code_outputs = []
            for index, option in enumerate(options):
                decompiler_output = decompiler.decompile(function_name, option)

                decorated_code = DecoratedCode(decompiler_output.code)
                decorated_code.reformat()

                outputPath = Path("./output") / binary_name / function_name / str(index)
                outputPath.parent.mkdir(parents=True, exist_ok=True)
                outputPath.write_text(decorated_code.code, encoding="UTF-8")

                code_outputs.append(decorated_code.code)

            max_diff = (seq(itertools.combinations(code_outputs, 2))
                    .max_by(lambda cases: seq(difflib.ndiff(cases[0].splitlines(keepends=True), cases[0].splitlines(keepends=True)))
                            .count(lambda li: not li.startswith(" "))))

            stats[function_name] = max_diff

        return stats


if __name__ == "__main__":
    functions = Path("../tests/coreutils/functions.txt").read_text(encoding="UTF-8").splitlines()
    tasks = seq(functions).map(lambda line: line.split(" ")).group_by_key().to_list()

    stats: dict[str, dict[str, int]] = {}
    with logging_redirect_tqdm():
        for bin_name, function_names in tqdm(tasks):
            stats[bin_name] = process_binary((bin_name, function_names))
        # for task, bin_stats in zip(tasks, process_map(process_binary, tasks)):
        #     stats[task[0]] = bin_stats

    report = (
        seq(stats.items())
        .flat_map(lambda bi: seq(bi[1].items).map(lambda fi: (f"{bi[0]}::{fi[0]}", fi[1])))
        .sorted(key=lambda i: i[1])
        .to_list()
    )

    seq(report).show()
    Path("./report").write_text("\n".join(report), encoding="UTF-8")
