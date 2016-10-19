"""
Plot representation of a CHERI pointer provenance tree
"""

import numpy as np
import logging

from matplotlib import pyplot as plt
from matplotlib import lines, collections, transforms

from cheri_trace_parser.utils import ProgressPrinter
from cheri_trace_parser.core import RangeSet, Range
from cheri_trace_parser.provenance_tree import (
    PointerProvenanceParser, CachedProvenanceTree, CheriCapNode)

logger = logging.getLogger(__name__)

class LeafCapPatchGenerator:
    """
    The patch generator build the matplotlib patches for each
    capability node and generates the ranges of address-space in
    which we are not interested.


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
        """List of uninteresting ranges of address-space"""
        self.size_limit = 2**12
        """Minimum distance between omitted address-space ranges"""
        self.split_size = 2 * self.size_limit
        """
        Capability length threshold to trigger the omission of
        the middle portion of the capability range.
        """
        self._omit_collection = np.empty((1,2,2))
        """Collection of elements in omit ranges"""
        self._keep_collection = np.empty((1,2,2))
        """Collection of elements in keep ranges"""
        self._bbox = transforms.Bbox.from_bounds(0, 0, 0, 0)
        """Bounding box of the artists in the collections"""
        self.y_unit = 10**-6
        """
        Unit on the y-axis 
        XXX may set it in the axis unit?
        """
        
        # omit everything if there is nothing to show
        self.ranges.append(Range(0, np.inf, Range.T_OMIT))

    def __iter__(self):
        return iter(self.ranges)

    def _update_regions(self, node_range):
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

    def _build_patch(self, node_range, **kwargs):
        """
        Build patch for the given range and type and add it
        to the patch collection for drawing
        """
        y = kwargs["y"]
        line = [[(node_range.start, y), (node_range.end, y)]]
        if node_range.rtype == Range.T_KEEP:
            self._keep_collection = np.append(self._keep_collection, line, axis=0)
        elif node_range.rtype == Range.T_OMIT:
            self._omit_collection = np.append(self._omit_collection, line, axis=0)
        else:
            raise ValueError("Invalid range type %s" % node_range.rtype)

    def inspect(self, node):
        """
        Inspect a CheriCapNode and update internal
        set of ranges
        """
        if len(node) != 0:
            # not a leaf in the provenance tree
            return
        
        node_y = node.t_alloc * self.y_unit
        node_box = transforms.Bbox.from_extents(node.base, node_y,
                                                node.bound, node_y)
        self._bbox = transforms.Bbox.union([self._bbox, node_box])
        if node.length > self.split_size:
            l_range = Range(node.base, node.base + self.size_limit,
                            Range.T_KEEP)
            r_range = Range(node.bound - self.size_limit, node.bound,
                            Range.T_KEEP)
            omit_range = Range(node.base + self.size_limit,
                               node.bound - self.size_limit,
                               Range.T_OMIT)
            self._update_regions(l_range)
            self._update_regions(r_range)
            self._build_patch(l_range, y=node_y)
            self._build_patch(r_range, y=node_y)
            self._build_patch(omit_range, y=node_y)
        else:
            keep_range = Range(node.base, node.bound, Range.T_KEEP)
            self._update_regions(keep_range)
            self._build_patch(keep_range, y=node_y)
            

    def get_omit_ranges(self):
        """
        Return an array of address ranges that do not contain
        interesting data evaluated by :meth:inspect
        """
        return [[r.start, r.end] for r in self.ranges]

    def get_patches(self):
        """
        Return a list of patches to draw for the data
        evaluated by :meth:inspect
        """
        omit_patch = collections.LineCollection(self._omit_collection,
                                                linestyle="dotted")
        keep_patch = collections.LineCollection(self._keep_collection,
                                                linestyle="solid")
        logger.debug("omit segments %s", omit_patch.get_segments())
        logger.debug("keep segments %s", keep_patch.get_segments())
        return [omit_patch, keep_patch]

    def get_bbox(self):
        """
        Return the bounding box of the data produced
        """
        return self._bbox


class PointerProvenancePlot:
    """
    XXX: the logic for tree caching/generation should go elsewhere,
    there should be only plotting stuff here
    """

    def __init__(self, tracefile):
        self.tracefile = tracefile
        """Tracefile path"""
        self.parser = PointerProvenanceParser(tracefile)
        """Tracefile parser"""
        self.tree = None
        """Provenance tree"""
        self.omit_strategy = LeafCapPatchGenerator()
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

        num_nodes = len(self.tree)
        logger.debug("Total nodes %d", num_nodes)
        progress = ProgressPrinter(num_nodes, desc="Remove kernel nodes")
        def remove_nodes(node):
            """
            remove null capabilities
            remove operations in kernel mode
            """
            if (node.offset >= 0xFFFFFFFF0000000 or
                (node.length == 0 and node.base == 0)):
                # XXX should we only check the length?
                node.selfremove()
            progress.advance()
        self.tree.visit(remove_nodes)
        progress.finish()
        
        num_nodes = len(self.tree)
        logger.debug("Filtered kernel nodes, remaining %d", num_nodes)
        progress = ProgressPrinter(num_nodes, desc="Merge (cfromptr + csetbounds) sequences")
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
            progress.advance()
        self.tree.visit(merge_setbounds)
        progress.finish()

    def plot(self, radix=None):
        """
        Create the provenance plot and return the figure

        radix: a root node to use instead of the full tree
        """

        if radix is None:
            tree = self.tree
        else:
            tree = radix
        fig = plt.figure(figsize=(15,10))
        ax = fig.add_axes([0.05, 0.15, 0.9, 0.80,],
                          projection="custom_addrspace")

        # XXX may want to do this in parallel or reduce the
        # time spent in the omit strategy?
        tree_progress = ProgressPrinter(len(tree), desc="Adding nodes")
        for child in tree:
            self.omit_strategy.inspect(child)
            tree_progress.advance()
        tree_progress.finish()

        for collection in self.omit_strategy.get_patches():
            ax.add_collection(collection)
        ax.set_omit_ranges(self.omit_strategy.get_omit_ranges())

        view_box = self.omit_strategy.get_bbox()
        logger.debug("X limits: (%d, %d)", view_box.xmin, view_box.xmax)
        ax.set_xlim(view_box.xmin, view_box.xmax)
        logger.debug("Y limits: (%d, %d)", view_box.ymin, view_box.ymax)
        ax.set_ylim(view_box.ymin, view_box.ymax * 1.02)
        ax.invert_yaxis()

        logger.debug("Plot build completed")
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
