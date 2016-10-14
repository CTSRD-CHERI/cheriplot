"""
Same as the pointer density plot but show the amount of allocations
vs address-space in a continuous way. The single allocation is not
given in terms of single dot but is cumulative over the address that
it occupies.
"""

import numpy as np
import logging
from matplotlib import pyplot as plt

from cheri_trace_parser.utils import ProgressPrinter
from cheri_trace_parser.core import AddressSpaceCanvas, RangeSet, Range, AddressSpaceAxes
from cheri_trace_parser.provenance_tree import (
    PointerProvenanceParser, CachedProvenanceTree, CheriCapNode)

logger = logging.getLogger(__name__)

class ContinuousPointerDensityPlot:

    def __init__(self, tracefile):
        self.tracefile = tracefile
        """Tracefile path"""
        self.parser = PointerProvenanceParser(tracefile)
        """Tracefile parser"""
        self.tree = None
        """Provenance tree"""

        # XXX we may want to do this later
        # self.omit_strategy = PageBoundaryOmitStrategy()
        # """
        # Strategy object that decides which parts of the AS
        # are interesting
        # """

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
                logger.debug("No cached tree found %s", fname)
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
        Create density plot

        radix: a root node to use instead of the full tree
        """
        tree_size = len(self.tree)
        # (addr, num_allocations)
        addresses = {}
        page_use = {}
        page_size = 2**12
        
        # address reuse metric
        # num_allocations vs address
        # linearly and in 4k chunks
        tree_progress = ProgressPrinter(len(self.tree), desc="Fetching addresses")
        for child in self.tree:
            for time, addr in child.address.items():                
                try:                
                    addresses[addr] += 1
                except KeyError:
                    addresses[addr] = 1
                page_addr = addr & (~0xfff)
                try:
                    page_use[page_addr] += 1
                except KeyError:
                    page_use[page_addr] = 1
            tree_progress.advance()
        tree_progress.finish()

        # time vs address
        # address working set over time

        fig = plt.figure(figsize=(15,10)) # 25,20
        ax = fig.add_axes([0.05, 0.15, 0.9, 0.80,], projection="custom_addrspace")
        ax.set_ylabel("Number of pointers stored")
        ax.set_xlabel("Virtual address")
        ax.set_yscale("log")
        # ax.set_ylim(0, )
        data = np.array(sorted(page_use.items(), key=lambda i: i[0]))
        # ignore empty address-space chunks
        prev_addr = data[0]
        omit_ranges = []
        first_tick = data[0][0]
        ticks = [first_tick]
        labels = ["0x%x" % int(first_tick)]
        for addr in data:
            logger.debug("DATA 0x%x (%d)", int(addr[0]), addr[0])
            if addr[0] - prev_addr[0] > 2**12:
                omit_ranges.append([prev_addr[0] + page_size, addr[0]])
                ticks.append(addr[0])
                labels.append("0x%x" % int(addr[0]))
            prev_addr = addr
        ax.set_omit_ranges(omit_ranges)
        # ax.set_xticks(ticks)
        # ax.set_xticklabels(labels, rotation="vertical")
        ax.set_xlim(first_tick - page_size, data[-1][0] + page_size)
        ax.vlines(data[:,0], [1]*len(data[:,0]), data[:,1], color="b")
        
        # fig.savefig(self._get_plot_file())
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
