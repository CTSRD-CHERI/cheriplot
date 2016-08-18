#!/usr/bin/python

"""
This script produces a poiner provenance plot from a cheri trace file
"""

import argparse as ap
import sys
import logging
import cProfile

from cheri_trace_parser.cheri_provenance import PointerProvenancePlot

logger = logging.getLogger(__name__)

if __name__ == "__main__":
    parser = ap.ArgumentParser(description="Plot pointer provenance from cheri trace")
    parser.add_argument("trace", help="Path to trace file")
    parser.add_argument("-c", "--cache", help="Enable provenance tree caching",
                        action="store_true")
    parser.add_argument("-v", "--verbose", help="Show debug output",
                        action="store_true")
    parser.add_argument("--log", help="Set logfile path")
    parser.add_argument("--tree", help="Dump tree to logging and exit",
                        action="store_true")
    parser.add_argument("--profile",
                        help="Run in profiler (disable verbose output)",
                        action="store_true")

    args = parser.parse_args()

    if args.profile:
        args.verbose = False

    logging_args = {}
    if args.verbose:
        logging_args["level"] = logging.DEBUG
    else:
        logging_args["level"] = logging.INFO

    if args.log:
        logging_args["filename"] = args.log

    logging.basicConfig(**logging_args)

    plot = PointerProvenancePlot(args.trace)
    if args.cache:
        plot.set_caching(True)

    if args.tree:
        plot.build_tree()
        logger.debug(plot.tree)
    else:
        if args.profile:
            cProfile.run("plot.build_figure()")
        else:
            plot.show()

