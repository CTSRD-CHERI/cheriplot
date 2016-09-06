"""
Plot density of pointers (capabilities) in memory
"""

import numpy as np
import logging
import sys

from matplotlib import pyplot as plt
from matplotlib import lines, transforms, axes

from itertools import repeat
from functools import reduce
from operator import attrgetter

from cheri_trace_parser.utils import ProgressPrinter
from cheri_trace_parser.core import AddressSpaceCanvas, RangeSet, Range
from cheri_trace_parser.provenance_tree import (
    PointerProvenanceParser, CachedProvenanceTree, CheriCapNode)

logger = logging.getLogger(__name__)


class PageBoundaryOmitStrategy:
    """
    Generate address ranges that are displayed as shortened in the
    address-space plot based on leaf capabilities found in the
    provenance tree.
    We only care about the pages that contain some pointers, ranges
    are kept in chunks of 4K depending on whether there is at least
    one capability pointer stored inside
    """

    def __init__(self):
        self.ranges = RangeSet()
        """List of ranges"""
        self.size_limit = 0
        """Minimum size to retain a range in the set"""

        self.ranges.append(Range(0, np.inf, Range.T_OMIT))

    def __iter__(self):
        return iter(self.ranges)

    def _inspect_range(self, node_range):
        """
        XXX: this is quite generic but seems to be useful across
        different omit-range detection mechanisms, may be be
        desirable to make a base class. For now leave it unchanged
        """
        overlap = self.ranges.match_overlap_range(node_range)
        logger.debug("Mark %s -> %s", node_range, self.ranges)
        for r in overlap:
            # 4 possible situations for range (R)
            # and node_range (NR):
            # i) NR completely contained in R
            # ii) R completely contained in NR
            # iii) NR crosses the start or iv) the end of R
            if (node_range.start >= r.start and node_range.end <= r.end):
                # (i) split R
                del self.ranges[self.ranges.index(r)]
                r_left = Range(r.start, node_range.start, Range.T_OMIT)
                r_right = Range(node_range.end, r.end, Range.T_OMIT)
                if r_left.size >= self.size_limit:
                    self.ranges.append(r_left)
                if r_right.size >= self.size_limit:
                    self.ranges.append(r_right)
            elif (node_range.start <= r.start and node_range.end >= r.end):
                # (ii) remove R
                del self.ranges[self.ranges.index(r)]
            elif node_range.start < r.start:
                # (iii) resize range
                r.start = node_range.end
                if r.size < self.size_limit:
                    del self.ranges[self.ranges.index(r)]
            elif node_range.end > r.end:
                # (iv) resize range
                r.end = node_range.start
                if r.size < self.size_limit:
                    del self.ranges[self.ranges.index(r)]
        logger.debug("New omit set %s", self.ranges)

    def inspect(self, node):
        """
        Inspect a CheriCapNode and update internal
        set of ranges

        Take the node address and round it to page boundary
        """
        for addr in node.address.values():
            page_addr = addr & ~(0xfff)
            page_bound = page_addr + 0x1000
            page_range = Range(page_addr, page_bound, Range.T_KEEP)
            self._inspect_range(page_range)

    def add_ranges(self, canvas):
        """
        Apply the ranges to an AddressSpaceCanvas
        """
        for r in self.ranges:
            canvas.omit(r.start, r.end)


class CapabilityDot:
    """
    Draw the memory address associated to a capability
    (where it is stored)
    """

    STACK_COLOR = "b"
    HEAP_COLOR = "r"
    CODE_COLOR = "g"

    def __init__(self, node, addr, time):
        self.node = node
        self.addr = addr
        self.time = time

    @property
    def start(self):
        return self.addr

    @property
    def end(self):
        return self.addr + 1

    @property
    def size(self):
        return 1

    @property
    def y_value(self):
        return self.time / 10**6

    def draw(self, start, end, ax):
        """
        Draw the interesting part of the element
        """
        ax.plot(start, self.y_value, "o", color="b")
        return 0

    def omit(self, start, end, ax):
        """
        Draw the pattern showing an omitted block
        of the element
        """
        return 0

    def __str__(self):
        return "<CapDot at:0x%x>" % (self.start,)

class PointerDensityPlot:

    def __init__(self, tracefile):
        self.tracefile = tracefile
        """Tracefile path"""
        self.parser = PointerProvenanceParser(tracefile)
        """Tracefile parser"""
        self.tree = None
        """Provenance tree"""
        self.omit_strategy = PageBoundaryOmitStrategy()
        """
        Strategy object that decides which parts of the AS
        are interesting
        """

        self._caching = False

    def _get_cache_file(self):
        return self.tracefile + ".cache"

    def set_caching(self, state):
        self._caching = state

    def build_tree(self):
        """
        Build the provenance tree
        """
        logger.debug("Generating provenance tree for %s", self.tracefile)
        self.tree = CachedProvenanceTree()
        if self._caching:
            fname = self._get_cache_file()
            try:
                self.tree.load(fname)
            except IOError:
                self.parser.parse(self.tree)
                self.tree.save(self._get_cache_file())
        else:
            self.parser.parse(self.tree)

        errs = []
        self.tree.check_consistency(errs)
        if len(errs) > 0:
            logger.warning("Inconsistent provenance tree: %s", errs)


    def plot(self, radix=None):
        """
        Create the provenance plot and return the figure

        radix: a root node to use instead of the full tree
        """

        if radix is None:
            tree = self.tree
        else:
            tree = radix
        tree_progress = ProgressPrinter(len(tree), desc="Adding nodes")
        fig = plt.figure()
        ax = fig.add_axes([0.05, 0.15, 0.9, 0.80,])

        canvas = AddressSpaceCanvas(ax)
        for child in tree:
            tree_progress.advance()
            self.omit_strategy.inspect(child)
            for t_store, addr in child.address.items():
                canvas.add_element(CapabilityDot(child, addr, t_store))
        tree_progress.finish()

        self.omit_strategy.add_ranges(canvas)
        canvas.draw()
        ax.invert_yaxis()
        return fig

    def build_figure(self):
        """
        Build the plot without showing it
        """
        if self.tree is None:
            self.build_tree()
        fig = self.plot()

    def show(self):
        """
        Show plot in a new window
        """
        self.build_figure()
        plt.show()
