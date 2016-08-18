"""
Parser for cheri trace files based on the cheritrace library
"""

import os

import pycheritrace as pct

class TraceParser(object):
    """
    Generic trace file parser abstraction to decouple the
    cheritrace-specific interface
    """
    
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
