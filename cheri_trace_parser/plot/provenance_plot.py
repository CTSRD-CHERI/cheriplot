"""
Plot representation of a CHERI pointer provenance tree
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

class CapabilityRange:

    def __init__(self, node):
        self.node = node

    @property
    def start(self):
        return self.node.base

    @property
    def end(self):
        return self.node.bound

    @property
    def size(self):
        return self.node.length

    @property
    def y_value(self):
        return self.node.t_alloc / 10**6

    def draw(self, start, end, ax):
        """
        Draw the interesting part of the element
        """
        logger.debug("Draw [0x%x, 0x%x] %d", start, end, self.node.t_alloc)
        line = lines.Line2D([start, end],
                            [self.y_value, self.y_value])
        ax.add_line(line)
        # add vertical separators
        line = lines.Line2D([start, start],
                            [self.y_value, 0],
                            linestyle="dotted",
                            color="black")
        ax.add_line(line)
        line = lines.Line2D([end, end],
                            [self.y_value, 0],
                            linestyle="dotted",
                            color="black")
        ax.add_line(line)

    def omit(self, start, end, ax):
        """
        Draw the pattern showing an omitted block
        of the element
        """
        logger.debug("Omit [0x%x, 0x%x] %d", start, end, self.node.t_alloc)
        line = lines.Line2D([start, end],
                            [self.y_value, self.y_value],
                            linestyle="dotted")
        ax.add_line(line)

    def __str__(self):
        return "<CapRange start:0x%x end:0x%x>" % (self.start, self.end)


class LeafCapOmitStrategy:
    """
    Generate address ranges that are displayed as shortened in the
    address-space plot based on leaf capabilities found in the
    provenance tree.
    We only care about zones where capabilities without children
    are allocated. If the allocations are spaced out more than
    a given number of pages, the space in between is omitted
    in the plot.
    """

    def __init__(self):
        self.ranges = RangeSet()
        """List of ranges"""
        self.size_limit = 2**12
        """Minimum distance between omit ranges"""
        self.split_size = 2 * self.size_limit
        """
        If single capability is larger than this,
        the space in the middle is omitted
        """

        # In the beginning there was nothing
        self.ranges.append(Range(0, np.inf, Range.T_OMIT))

    def __iter__(self):
        return iter(self.ranges)

    def _inspect_range(self, node_range):
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
        """
        if len(node) != 0:
            return
        if node.length > self.split_size:
            l_range = Range(node.base, node.base + self.size_limit,
                            Range.T_KEEP)
            r_range = Range(node.bound - self.size_limit, node.bound,
                            Range.T_KEEP)
            self._inspect_range(l_range)
            self._inspect_range(r_range)
        else:
            self._inspect_range(Range(node.base, node.bound, Range.T_KEEP))

    def add_ranges(self, canvas):
        """
        Apply the ranges to an AddressSpaceCanvas
        """
        for r in self.ranges:
            canvas.omit(r.start, r.end)


class PointerProvenancePlot:

    def __init__(self, tracefile):
        self.tracefile = tracefile
        """Tracefile path"""
        self.parser = PointerProvenanceParser(tracefile)
        """Tracefile parser"""
        self.tree = None
        """Provenance tree"""
        self.omit_strategy = LeafCapOmitStrategy()
        """
        Strategy object that decides which parts of the AS
        are interesting
        """

        self._caching = False

    def _get_cache_file(self):
        return self.tracefile + ".cache"

    def _get_plot_file(self):
        return self.tracefile + ".png"

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

        logger.debug("Total nodes %d", len(self.tree))
        def remove_nodes(node):
            """
            remove null capabilities
            remove operations in kernel mode
            """
            if (node.offset >= 0xFFFFFFFF0000000 or
                (node.length == 0 and node.base == 0)):
                # XXX should we only check the length?
                node.selfremove()
        self.tree.visit(remove_nodes)
        logger.debug("Filtered kernel nodes, remaining %d", len(self.tree))

        def merge_setbounds(node):
            """
            merge cfromptr -> csetbounds subtrees
            """
            if (node.parent.origin == CheriCapNode.C_FROMPTR and
                node.origin == CheriCapNode.C_SETBOUNDS and
                len(node.parent.children) == 1):
                # the child must be unique to avoid complex logic
                # when merging, it may be desirable to do so with
                # more complex traces
                node.origin = CheriCapNode.C_PTR_SETBOUNDS
                grandpa = node.parent.parent
                node.parent.selfremove()
                grandpa.append(node)
        self.tree.visit(merge_setbounds)

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
        ax = fig.add_axes([0.05, 0.1, 0.9, 0.85,])

        canvas = AddressSpaceCanvas(ax)
        # XXX may want to do this in parallel or reduce the
        # time spent in the omit strategy?
        for child in tree:
            tree_progress.advance()
            self.omit_strategy.inspect(child)
            canvas.add_element(CapabilityRange(child))
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

    def show_multiple(self):
        """
        Show multiple plots, one for each root of the "tree"
        """
        if self.tree is None:
            self.build_tree()

        for node in self.tree.children:
            fig = self.plot(node)
            plt.show()
