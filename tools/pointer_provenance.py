#!/usr/bin/python

"""
This script produces a poiner provenance plot from a cheri trace file
"""

import argparse as ap
import sys

from cheri_trace_parser.cheri_provenance import *
from cheri_trace_parser.core.parser import TraceParser

def log(fmt, *args):
    print("[%s]" % sys.argv[0], fmt % args)

if __name__ == "__main__":
    parser = ap.ArgumentParser(description="Plot pointer provenance from cheri trace")
    parser.add_argument("trace", help="Path to trace file")

    args = parser.parse_args()

    traceparser = PointerProvenanceParser(args.trace)
    tree = ProvenanceTree()
    traceparser.parse(tree)
    errs = []
    tree.check_consistency(errs)
    if len(errs) > 0:
        log("Inconsistent provenance tree: %s", errs)
    print(tree)

