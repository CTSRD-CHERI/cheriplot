#!/usr/bin/python

"""
Copyright 2016 Alfredo Mazzinghi

Copyright and related rights are licensed under the BERI Hardware-Software
License, Version 1.0 (the "License"); you may not use this file except
in compliance with the License.  You may obtain a copy of the License at:

http://www.beri-open-systems.org/legal/license-1-0.txt

Unless required by applicable law or agreed to in writing, software,
hardware and materials distributed under this License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
express or implied.  See the License for the specific language governing
permissions and limitations under the License.


This script produces a poiner provenance plot from a cheri trace file
"""

import argparse as ap
import sys
import logging
import cProfile
import pstats

from cheri_trace_parser.plot import (PointerDensityPlot,
                                     ContinuousPointerDensityPlot)

logger = logging.getLogger(__name__)

if __name__ == "__main__":
    parser = ap.ArgumentParser(description="Plot pointer density from cheri trace")
    parser.add_argument("trace", help="Path to trace file")
    parser.add_argument("-c", "--cache", help="Enable provenance tree caching",
                        action="store_true")
    parser.add_argument("-v", "--verbose", help="Show debug output",
                        action="store_true")
    parser.add_argument("-o", "--outfile", help="Save plot to file")
    parser.add_argument("--log", help="Set logfile path")
    parser.add_argument("--tree", help="Dump tree to logging and exit",
                        action="store_true")
    parser.add_argument("--profile",
                        help="Run in profiler (disable verbose output)",
                        action="store_true")
    parser.add_argument("plot_type", help="Valid choices are:"
                        "lt (pointers location vs time), "
                        "ln (pointers location vs number of pointers stored), "
                        "lpn (same as lp but with page granularity)")

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

    if args.plot_type == "lt":
        plot = PointerDensityPlot(args.trace)
    elif args.plot_type == "ln":
        plot = ContinuousPointerDensityPlot(args.trace)
    else:
        print("Invalid plot type")
        quit()
    
    if args.cache:
        plot.set_caching(True)

    try:
        if args.tree:
            if args.profile:
                cProfile.run("plot.build_tree()", "run_stats")
            else:
                plot.build_tree()
                logger.debug("Provenance tree:")
                logger.debug(plot.tree)
                # XXX inefficient, make tree.__str__ handle this
                # logger.debug("Tree size: %d" % len(plot.tree))
        else:
            if args.profile:
                cProfile.run("plot.build_figure()", "run_stats")
            elif args.outfile is None:
                plot.show()
            else:
                plot.save(args.outfile)
    finally:
        # print profiling results
        if args.profile:
            p = pstats.Stats("run_stats")
            p.strip_dirs()
            p.sort_stats("cumulative")
            p.print_stats()
