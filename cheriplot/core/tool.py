#-
# Copyright (c) 2016 Alfredo Mazzinghi
# All rights reserved.
#
# This software was developed by SRI International and the University of
# Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
# ("CTSRD"), as part of the DARPA CRASH research programme.
#
# @BERI_LICENSE_HEADER_START@
#
# Licensed to BERI Open Systems C.I.C. (BERI) under one or more contributor
# license agreements.  See the NOTICE file distributed with this work for
# additional information regarding copyright ownership.  BERI licenses this
# file to you under the BERI Hardware-Software License, Version 1.0 (the
# "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at:
#
#   http://www.beri-open-systems.org/legal/license-1-0.txt
#
# Unless required by applicable law or agreed to in writing, Work distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations under the License.
#
# @BERI_LICENSE_HEADER_END@
#

import sys
import os
import logging
import cProfile
import pstats

from argparse import ArgumentParser, RawTextHelpFormatter
from cheriplot.core.driver import NestingNamespace, TaskDriver, Option, Argument


def driver_tool(task, argv=None):
    parser = ArgumentParser(description=task.description,
                            formatter_class=RawTextHelpFormatter)
    task.make_config(parser)
    args = parser.parse_args(args=argv, namespace=NestingNamespace())
    task_inst = task(args)
    task_inst.run()


class BaseToolTaskDriver(TaskDriver):
    """
    Base taskdriver that handles logging configuration and profiling
    """
    verbose = Option(help="Show debug output")
    profile = Option(help="Enable profiling")
    logfile = Option(help="Log output file")

    def __init__(self, config):
        super().__init__(config)

        verbose = config.verbose and not config.profile
        logging_args = {
            "level": logging.DEBUG if verbose else logging.INFO,
            "filename": config.logfile
        }
        logging.basicConfig(**logging_args)

        # instrument the run method to do profiling
        if config.profile:
            def profiling_run(self_):
                try:
                    pr = cProfile.Profile()
                    pr.runcall(self.run)
                finally:
                    # print profiling results
                    pr.create_stats()
                    pr.print_stats(sort="cumulative")
                    # this is to print stats to file
                    # p = pstats.Stats(self._get_profiler_file())
                    # p.strip_dirs()
                    # p.sort_stats("cumulative")
                    # p.print_stats()
            self.run = profiling_run

    def _get_profiler_file(self):
        tool_name, _ = os.path.splitext(sys.argv[0])
        return "%s.cprof" % tool_name


class BaseTraceTaskDriver(BaseToolTaskDriver):
    """
    Base task driver that adds options to accept a
    trace file, output file and caching policy
    """
    trace = Argument(help="Path to cvtrace file")
    cache = Option(help="Enable caching of intermediary datasets")
    outfile = Option(help="Output file")
