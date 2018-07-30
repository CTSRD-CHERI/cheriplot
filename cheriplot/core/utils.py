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

import logging
import sys
import io
import cProfile
import pstats
import tracemalloc
import linecache
from threading import Thread, Lock, Event

from collections import defaultdict
from datetime import datetime, timedelta

from pyprof2calltree import visualize

logger = logging.getLogger(__name__)

class ProgressPrinter:
    """
    Print progress information based on the log-level
    """

    def __init__(self, end, desc="Progress", start=0, step=1,
                 level=logging.INFO):
        self.start = start
        """Start value of progress counter"""

        self.end = end
        """End value of progress counter"""

        self.desc = desc
        """Counter description"""

        self.progress = 0
        """Current % progress"""

        self.curr = 0
        """Current counter value"""

        self.step = step
        """Counter increment step"""

        self.level = level
        """Log level"""

    def advance(self, step=1, to=None):
        if logger.getEffectiveLevel() > self.level:
            return
        if to is not None:
            self.curr = to
        else:
            self.curr += step
        if self.end < 0:
            # wait until someone resets a consistent end
            return
        progress = int(self.curr * 100 / (self.end - self.start))
        if (progress != self.progress):
            self.progress = progress
            sys.stdout.write("\r%s [%d%%]" % (self.desc, progress))
            sys.stdout.flush()
            
    def finish(self):
        """
        Add newline to separate upcoming output
        """
        if logger.getEffectiveLevel() < self.level:
            return
        sys.stdout.write("\n\n")
        sys.stdout.flush()


class ProgressManager(Thread):
    """
    Extended version of progress reporting. This runs as a separate thread that
    prints out the internal progress count at given time intervals.
    """

    def __init__(self, desc, start, end, interval=2, level=logging.INFO):
        super().__init__()

        self._interval = interval
        """Reporting interval (seconds)"""

        self._lock = Lock()
        """Progress counter lock"""

        self._stop = Event()
        """Progress finish event"""
        self._stop.clear()

        self._desc = desc
        """Output description"""

        self._start = start
        """Start offset of the progress counter"""

        self._end = end
        """End offset of the progress counter"""

        self._progress = start
        """Current progress counter"""

        self._level = level
        """Log level"""

    def advance(self, step=1):
        if logger.getEffectiveLevel() > self._level:
            return
        with self._lock:
            self._progress += step

    def report(self):
        with self._lock:
            progress = int(self._progress * 100 / (self._end - self._start))
        sys.stdout.write("\r{} [{:d}%] ({:d}/{:d})".format(
            self._desc, progress, self._progress, self._end))
        sys.stdout.flush()

    def run(self):
        timeout = False
        while not timeout:
            timeout = self._stop.wait(self._interval)
            self.report()
        sys.stdout.write("\n")
        sys.stdout.flush()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, type, value, traceback):
        self._stop.set()


class ProgressTimer:
    """
    Context manager that wraps a statement and measures the run time.
    The message can be customised to show different information along
    with the timing.
    """

    def __init__(self, msg="", logger_inst=None):
        self.msg = msg
        self.logger = logger_inst or logger
        self.start = None

    def __enter__(self):
        self.start = datetime.now()
        self.logger.info("%s started at %s", self.msg,
                         self.start.isoformat(timespec="seconds"))

    def __exit__(self, type, value, traceback):
        end = datetime.now()
        self.logger.info("%s done at %s (time %s)", self.msg,
                         end.isoformat(timespec="seconds"), end - self.start)


class CumulativeTimer:
    """
    Helper context manager for profiling purposes.

    This keeps track of the cumulative time spent in a block of code.
    """

    timers = {}

    def __init__(self, name):
        """
        Each timer name returns a different shared-state cumulative timer
        based on the borg pattern.
        """
        try:
            state = self.timers[name]
            self.__dict__ = state
        except KeyError:
            self.name = name
            self.elapsed = timedelta()
            self.timers[name] = self.__dict__
        self.start = None

    def __enter__(self):
        self.start = datetime.now()

    def __exit__(self, type, value, traceback):
        self.elapsed += datetime.now() - self.start

    def report(self, logger):
        logger.debug("Cumulative timer probe %s elapsed %s", self.name, self.elapsed)


class LineMap:

    def __init__(self):
        self.filemap = defaultdict(0)

    def extend(self, diff):
        for stat in diff:
            file_line = str(stat.traceback)
            fname, lineno = file_line.split(":")
            self.filemap[(fname, lineno)] += 0

class Profiler:
    """
    Helper context manager that enables and disables profiling for portions of
    code.
    This can also be used as a decorator.

    The profiler can be left in the code to enable fine-grained profiling control
    without having to change the code. When profiling is disabled the
    profiler should have very low impact on performance.
    """

    _mem_profiling = 0
    """Count of memory profiling requests."""

    _profilers = {}

    @classmethod
    def list_probes(cls):
        return cls._profilers.keys()

    def __init__(self, name):
        """
        Each profiler name returns a different shared-state profiler
        based on the borg patter.
        This is done to easily enable profilers in all the system with
        minimal imports and globals usage.
        """
        try:
            self.__dict__ = self._profilers[name]
        except KeyError:
            self.name = name
            self._profiler = cProfile.Profile()
            self._mem_snapshot = None
            self._mem_diff_map = LineMap()
            self._profile_time = False
            self._profile_mem = False
            self._profilers[name] = self.__dict__

    def _mprof_enable(self):
        """Enable memory profiler."""
        if self._mem_profiling == 0:
            tracemalloc.start()
            self._mem_snapshot = tracemalloc.take_snapshot()
        self._mem_profiling += 1

    def _mprof_disable(self):
        """Disable memory profiler"""
        self._mem_profiling -= 1
        if self._mem_profiling == 0:
            end = tracemalloc.take_snapshot()
            tracemalloc.stop()
            self._mem_diff_map.extend(
                end.compare_to(self._mem_snapshot, "lineno"))

    def __enter__(self):
        if self._profile_time:
            self._profiler.enable()
        if self._profile_mem:
            self._mprof_enable()

    def __exit__(self, type, value, traceback):
        self._profiler.disable()
        self._mprof_disable()

    def __call__(self, target):
        # XXX TODO
        return target

    def enable_time(self):
        self._profile_time = True
        self._profile_mem = False

    def enable_mem(self):
        self._profile_time = False
        self._profile_mem = True

    def disable(self):
        self._profile_time = False
        self._profile_mem = False

    def report(self, logger):
        stream = io.StringIO()
        ps = pstats.Stats(self._profiler, stream=stream)
        ps.sort_stats("cumulative")
        logger.debug("Cumulative timer probe %s elapsed %s", self.name, self.elapsed)

    def show(self):
        visualize(self._profiler.getstats())
