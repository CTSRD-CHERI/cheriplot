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


This script plots the out-of-bound pointer manipulations
"""

import argparse as ap
import sys
import logging
import cProfile
import pstats

from cheri_trace_parser.plot import CapOutOfBoundPlot

logger = logging.getLogger(__name__)

if __name__ == "__main__":
    parser = ap.ArgumentParser(description="Out of bound pointer manipulation from cheri trace")
    parser.add_argument("trace", help="Path to trace file")
    parser.add_argument("-c", "--cache", help="Enable caching of the parsed trace",
                        action="store_true")
    parser.add_argument("-v", "--verbose", help="Show debug output",
                        action="store_true")
    parser.add_argument("-o", "--outfile", help="Save plot to file")
    parser.add_argument("--log", help="Set logfile path")
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

    plot = CapOutOfBoundPlot(args.trace)
    
    if args.cache:
        plot.set_caching(True)

    try:
        if args.profile:
            cProfile.run("plot.show()", "run_stats")
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
