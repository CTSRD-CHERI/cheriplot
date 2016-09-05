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

class CapabilityDot:
    """
    Draw the memory address associated to a capability
    (where it is stored)
    """

    def __init__(self, addr, time):
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
        self.omit_strategy = None #LeafCapOmitStrategy()
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
        # XXX may want to do this in parallel or reduce the
        # time spent in the omit strategy?
        for child in tree:
            tree_progress.advance()
            # self.omit_strategy.inspect(child)
            for t_store, addr in child.address.items():
                canvas.add_element(CapabilityDot(addr, t_store))
        tree_progress.finish()

        # self.omit_strategy.add_ranges(canvas)
        canvas.draw()
        ax.invert_yaxis()
        logger.debug(ax.patches)
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
