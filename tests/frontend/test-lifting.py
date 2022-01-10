import argparse
import os
import sys

current_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(current_dir)

import collections
import logging

from binaryninja import *
from decompiler.frontend.binaryninja.lifter import BinaryninjaLifter
from decompiler.logger import configure_logging

if __name__ == "__main__":
    configure_logging()
    binary = sys.argv[1]
    print(binary)

    bv = BinaryViewType.get_view_of_file(binary)
    bv.update_analysis_and_wait()

    not_lifted = collections.defaultdict(dict)
    lifter = BinaryninjaLifter()
    for f in bv.functions:
        logging.info(f.name)
        for i in f.medium_level_il.ssa_form.instructions:
            try:
                lifted = lifter.lift(i)

            except Exception as e:
                logging.info(f.name)
                logging.info(e.message)

                pass

    # with open('/tmp/unimplemented.json', 'w') as f:
    #
    #     json.dump(lifting_utils.unimplemented_map, f)

    # parser = parsing_dfa.GraphBuilder(lifter)
    # cfg = parser.cfg(f)
    # utils.flow_graph(cfg)
    # cpa = cp.LocalCopyPropagation(cfg)
    # cpa.perform()
    # dce = de.PrimitiveDeadCodeElimination(cfg)
    # dce.perform()
    #
    # utils.flow_graph(cfg)
