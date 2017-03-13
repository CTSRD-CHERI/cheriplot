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
import shlex

from argparse import RawTextHelpFormatter
from cheriplot.core.driver import *


class BaseToolTaskDriver(TaskDriver):
    """Base taskdriver that handles logging configuration and profiling"""
    verbose = Option(help="Show debug output")
    profile = Option(help="Enable profiling")
    logfile = Option(help="Log output file")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        verbose = self.config.verbose and not self.config.profile
        logging_args = {
            "level": logging.DEBUG if verbose else logging.INFO,
            "filename": self.config.logfile
        }
        logging.basicConfig(**logging_args)

        # instrument the run method to do profiling
        if self.config.profile:
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


def run_driver_tool(task, argv=None):
    """
    Run a TaskDriver as a CLI tool

    :param task: the task driver
    :type task: :class:`TaskDriver`
    :param argv: argument list
    :type argv: iterable
    """
    parser = TaskDriverArgumentParser(description=task.description)
    task.make_config(parser)
    args = parser.parse_args(args=argv)
    task_inst = task(config=args)
    task_inst.run()


class InteractiveTool(TaskDriver):
    """
    Task driver that runs another task as both a CLI batch
    command or an interactive tool.
    Instad of subclassing this, it is suggested to use
    :func:`interactive_tool`.

    Note:
    This relies on subclasses to define the following attributes:
    task_class:
        the class of the wrapped task
    wrapped_conf:
        the configuration argument of the wrapped task
    interactive_conf_keys:
        list of configuration keys in the wrapped
        parser that are allowed in the interactive prompt
    """
    interactive = Option("-i", action="store_true",
                         help="Run interactively")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # the wrapped task is initialized in the subclass
        self.task = self.task_class(config=self.config.wrapped_conf)

        toolname = os.path.basename(sys.argv[0])
        self.prompt = "%s> " % os.path.splitext(toolname)[0]

    def _mainloop(self):
        parser = TaskDriverArgumentParser(description=self.task.description)
        sub = parser.add_subparsers()
        cmd = sub.add_parser(self.interactive_conf_key)
        self.task.make_config(cmd, keys=[self.interactive_conf_key])
        while True:
            try:
                cli_in = input(self.prompt)
                argv = shlex.split(cli_in)
                if len(argv) and argv[0] == "quit":
                    break
                config = parser.parse_args(argv)
                self.task.update_config(config)
                self.task.run()
            except (SystemExit, KeyboardInterrupt):
                print("")
                continue
            except EOFError:
                break

    def run(self):
        if self.config.interactive:
            self._mainloop()
        else:
            self.task.run()


def interactive_tool(key):
    """
    Decorator that creates an interactive loop driver that wraps the given task
    driver. This reserves the "quit" keyword from the possible argparse
    keywords available to the wrapped task driver.

    >>> @interactive_tool("interactive_arg")
    ... class MyTaskDriver(TaskDriver):
    ...     cli_option = Option()
    ...     interactive_arg = NestedConfig(InteractiveConfig)
    """
    def wrapper(wrapped_task):
        # dynamically build the interactive tool subclass
        # with the class attributes requred by InteractiveTool
        ns = {
            "task_class": wrapped_task,
            "wrapped_conf": NestedConfig(wrapped_task),
            "interactive_conf_key": key
        }
        driver_class = TaskDriverType("_interactive_tool",
                                      (InteractiveTool,), ns)
        return driver_class
    return wrapper


def any_int_validator(value):
    """
    Validata input parameter of argparse argument.
    Accept integers in base 10 and 16
    """
    try:
        n = int(value)
    except ValueError:
        # try hex
        n = int(value, 16)
    return n

def option_range_validator(value):
    """
    Validate input parameter of an argparse argument.
    Accept a range of values.
    Expects a string in the form "start-end".
    Returns the tuple (start, end).
    """
    parts = value.split("-")
    try:
        if len(parts) > 1:
            start, end = parts
        else:
            start = end = parts[0]
        start = any_int_validator(start) if start != "" else None
        end = any_int_validator(end) if end != "" else None
    except ValueError:
        raise ValueError("Invalid range %s, accepted formats are"\
                         "<start>-<end>, <start>-, -<end>, <start=end>" % value)
    return (start, end)
