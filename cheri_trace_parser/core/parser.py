"""
Parser for cheri trace files based on the cheritrace library
"""

import os

import pycheritrace.pycheritrace as pct

class TraceParser(object):
    """
    Generic trace file parser abstraction to decouple the
    cheritrace-specific interface
    Parse a cheri trace file into a pointer provenance tree
    """

    class py_callback(object):
        def __init__(self, cbk, context):
            self.cbk = cbk
            self.ctx = context

        def run(self, *args):
            return self.cbk(self.ctx, *args)

    class py_scanner(py_callback, pct.Scanner):
        def __init__(self, cbk, context=None):
            pct.Scanner.__init__(self)
            TraceParser.py_callback.__init__(self, cbk, context)

    class py_detail(py_callback, pct.DetailedScanner):
        def __init__(self, cbk, context=None):
            pct.DetailedScanner.__init__(self)
            TraceParser.py_callback.__init__(self, cbk, context)

    class py_filter(py_callback, pct.Filter):
        def __init__(self, cbk, context=None):
            pct.Filter.__init__(self)
            TraceParser.py_callback.__init__(self, cbk, context)

    def __init__(self, path=None):
        self.path = path
        self.trace = None

        if path is not None:
            if not os.path.exists(path):
                raise IOError("File not found %s" % path)
            self.trace = pct.trace.open(path)
            if self.trace is None:
                raise IOError("Can not open trace %s" % path)

    def __len__(self):
        if self.trace:
            return self.trace.size()
        return 0

    def scan(self, callback, *args, context=None):
        cbk = TraceParser.py_scanner(callback, context).__disown__()
        if len(args) == 0:
            self.trace.scan_trace(cbk)
        elif len(args) == 2 or len(args) == 3:
            self.trace.scan_trace(cbk, *args)
        else:
            raise NotImplementedError("Invalid scan() signature.")

    def scan_detail(self, callback, *args, context=None):
        start = args[0] if len(args) > 0 else 0
        end = args[1] if len(args) > 1 else self.trace.size()
        opt = args[2] if len(args) > 2 else 0
        cbk = TraceParser.py_detail(callback, context).__disown__()
        self.trace.scan_trace(cbk, start, end, opt)
    
    def filter_(self, callback, context=None):
        cbk = TraceParser.py_filter(callback, context).__disown__()
        filtered = self.trace.filter_trace(cbk)
        new_trace = TraceParser()
        new_trace.trace = filtered
        return new_trace
