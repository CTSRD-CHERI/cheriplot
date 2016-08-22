"""
Parser for cheri trace files based on the cheritrace library
"""

import os
import math
import numpy as np

from multiprocessing import RawValue, Process
from ctypes import py_object
from itertools import repeat

import pycheritrace as pct

class TraceParser:
    """
    Generic trace file parser abstraction to decouple the
    cheritrace-specific interface
    """

    def __init__(self, trace_path=None):
        self.path = trace_path
        self.trace = None

        if trace_path is not None:
            if not os.path.exists(trace_path):
                raise IOError("File not found %s" % trace_path)
            self.trace = pct.trace.open(trace_path)
            if self.trace is None:
                raise IOError("Can not open trace %s" % trace_path)

    def __len__(self):
        if self.trace:
            return self.trace.size()
        return 0


class ThreadedTraceParser:
    """
    Trace parser that scans a trace using multiple threads

    XXX: experimental
    """

    def __init__(self, path, parser, threads=2):
        self.trace = RawValue(py_object, None)
        """Trace in shared memory"""
        self.parser = parser
        """
        Callback that handles each trace block, this is run
        in separate processes
        """
        self.n_threads = threads
        """Number of subprocesses that are spawned"""
        self.path = path
        """Trace path"""

        if not os.path.exists(path):
            raise IOError("File not found %s" % path)
        self.trace = pct.trace.open(path)
        if self.trace is None:
            raise IOError("Can not open trace %s" % path)

    def __len__(self):
        if self.trace:
            return self.trace.size()
        return 0

    def parse(self, *args, **kwargs):
        start = kwargs.pop("start", 0)
        end = kwargs.pop("end", len(self))
        block_size = math.floor((end - start) / self.n_threads)
        start_indexes = np.arange(start, end - block_size + 1, block_size)
        end_indexes = np.arange(start + block_size, end + 1, block_size) - 1
        # the last process consumes any remaining entries left by the
        # rounding of block_size
        end_indexes[-1] = end

        procs = []
        for idx_start, idx_end in zip(start_indexes, end_indexes):
            print(idx_start, idx_end)
            p = Process(target=self.parser, args=(self.path, idx_start, idx_end))
            procs.append(p)

        for p in procs:
            p.start()
        for p in procs:
            p.join()
