"""
Plot representation of a CHERI pointer provenance tree
"""
import numpy as np
import logging

from matplotlib import pyplot as plt
from matplotlib import lines, patches

from itertools import repeat
from functools import reduce
from operator import attrgetter

from .parser import PointerProvenanceParser
from .cheri_provenance import CachedProvenanceTree

logger = logging.getLogger(__name__)

class PointerProvenancePlot:

    class Chunk:

        def __init__(self, node):
            self.node = node
            """Leaf node that originated this chunk"""
            self.lines = []
            """Line2D instances representing data in this chunk"""

        def __iter__(self):
            parent = self.node.parent
            while parent is not None:
                yield parent
                parent = parent.parent

        @property
        def start(self):
            # XXX TO DO chunk extension
            return self.node.base

        @property
        def end(self):
            # XXX TO DO chunk extension
            return self.node.bound

        @property
        def size(self):
            return self.end - self.start

        def make_lines(self, x_offset, x_gap):
            """
            Prepare all the lines in the chunk and return the space
            in the X axis taken by the chunk, including separation space
            """
            chunk_x = x_offset + x_gap
            chunk_y = PointerProvenancePlot.scale_time(self.node.t_alloc)
            line = lines.Line2D([chunk_x, chunk_x + self.size],
                                [chunk_y, chunk_y])
            logger.debug("Draw chunk line: from [%d, %d] to [%d, %d]" %
                         (chunk_x, chunk_y, chunk_x + self.size, chunk_y))
            self.lines.append(line)
            # add vertical separators
            line = lines.Line2D([chunk_x, chunk_x],
                                [chunk_y, 0],
                                linestyle="dotted",
                                color="black")
            self.lines.append(line)
            line = lines.Line2D([chunk_x + self.size, chunk_x + self.size],
                                [chunk_y, 0],
                                linestyle="dotted",
                                color="black")
            self.lines.append(line)
            # add lines for parent nodes
            for parent in self:
                chunk_y = PointerProvenancePlot.scale_time(parent.t_alloc)
                line = lines.Line2D([chunk_x, chunk_x + self.size],
                                    [chunk_y, chunk_y])
                logger.debug("Draw parent line: from [%d, %d] to [%d, %d]" %
                             (chunk_x, chunk_y, chunk_x + self.size, chunk_y))
                self.lines.append(line)
                # add dotted continuation line for the parent if parent
                # is not starting exactly at the same point as the chunk
                if parent.base < self.node.base:
                    gap_line = lines.Line2D([x_offset, chunk_x],
                                            [chunk_y, chunk_y],
                                            linestyle="dotted")
                    self.lines.append(gap_line)
            return self.size + x_gap

        def make_xtick(self, x_offset, x_gap):
            xtick = x_offset + x_gap
            xlabel = "0x%x" % self.start
            return (xtick, xlabel)

    class LargeChunk(Chunk):

        def __init__(self, *args):
            super(PointerProvenancePlot.LargeChunk, self).__init__(*args)

        @property
        def size(self):
            return 0 # XXX TO DO
            
        def make_lines(self, x_offset, x_gap):
            return 0
        
        def make_xtick(self, x_offset, x_gap):
            return (None, None)

    @staticmethod
    def scale_time(time):
        """
        Change time scale
        """
        return time / 10**6

    def __init__(self, tracefile):
        self.tracefile = tracefile
        """Tracefile path"""
        self.parser = PointerProvenanceParser(tracefile)
        """Tracefile parser"""
        self.tree = None
        """Provenance tree"""

        self.large_chunk_size = 4 * 2**12
        """Large chunk detection threshold 4 pages"""
        self._caching = False

    def _get_cache_file(self):
        return self.tracefile + ".cache"

    def set_caching(self, state):
        self._caching = state

    def build_tree(self):
        """
        Build the provenance tree
        """
        logger.debug("Generating provenance tree for %s" % self.tracefile)
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
            logger.warning("Inconsistent provenance tree: %s" % errs)

    def get_chunks(self):
        """
        Split nodes in chunks of address-space to remove
        uninteresting parts of the address-space.
        Return a list of chunks, the maximum time found to
        set the Y scale and the xticks and labels 
        (this is to avoid walking the tree multiple times).

        Initially all leaves in the tree are chunks. The chunk
        boundaries are extended to the parent capability bonudaries
        if the parent leaf-space / blank-space ratio is higher than
        a threshold (this is to make the plot more readable).
        Finally capability start and end are inserted in chunks
        so that they show up when plotting.
        The chunk list is returned.

        Large chunks are also split in two smaller start and end chunks
        so that they do not take all the space. The large chunk 
        threshold can be tuned.

        XXXAM: this seems a space-partitioning problem
        are kd-trees an option?
        """
        logger.debug("Isolate interesting chunks of Address Space")
        # get leaves
        chunks = []
        time_max = 0
        for child in self.tree:
            if child.t_alloc > time_max:
                time_max = child.t_alloc
            if len(child) == 0:
                if child.length > self.large_chunk_size:
                    chunk = PointerProvenancePlot.LargeChunk(child)
                else:
                    chunk = PointerProvenancePlot.Chunk(child)
                logger.debug("Found chunk start:0x%x end:0x%x (%s)" %
                             (chunk.start, chunk.end, chunk.__class__.__name__))
                chunks.append(chunk)
        # expand/merge chunks (XXX TO DO)

        # sort chunks and make xticks
        chunks = sorted(chunks, key=attrgetter("start"))
        return {"chunks": chunks,
                "time_max": time_max}

    def plot(self):
        """
        Create the provenance plot and return the figure
        """
        fig = plt.figure()
        ax = fig.add_axes([0.05, 0.1, 0.85, 0.85,])

        chunk_info = self.get_chunks()
        chunks = chunk_info["chunks"]
        time_max = chunk_info["time_max"]

        # generate lines for each chunk
        # first we need to extract the total size of the chunks to
        # determine the scale of the X axis.
        chunk_space = reduce(lambda sz,chk: sz + chk.size, chunks, 0)
        # inter-chunk-space is dynamically computed as 30% of the 
        # average chunk size, this value is arbitrary.
        # XXX: it may be desirable to make this xx% tunable
        avg_chunk_size = chunk_space / len(chunks)
        inter_chunk_space = avg_chunk_size * 30 / 100

        xticks = [0]
        xlabels = ["0x0"]
        x_previous_chunks = 0
        for idx,chunk in enumerate(chunks):
            size = chunk.make_lines(x_previous_chunks, inter_chunk_space)
            xtick, xlabel = chunk.make_xtick(x_previous_chunks, inter_chunk_space)
            if xtick is not None:
                xticks.append(xtick)
                xlabels.append(xlabel)
            x_previous_chunks += size
            

        # X goes from 0 to chunk_space + inter_chunk_space
        x_size = x_previous_chunks
        y_size = self.scale_time(time_max)
        
        # double check in case something goes wrong
        # XXX not sure if the check is actually correct (the plot looks fine)
        # expected_x_size = chunk_space + inter_chunk_space * (len(chunks) - 1)
        # if (x_previous_chunks != expected_x_size):
        #     logger.warning("Unexpected computed plot X size, "\
        #                    "found %d, expected %d" %
        #                    (x_size, expected_x_size))
        logger.debug("Provenance plot X size: total: %d, "\
                     "inter-chunk-space: %d, chunk-space: %d" %
                     (x_size, inter_chunk_space, chunk_space))
        ax.set_xlim(0, x_size)
        # allow for a 1% margin in the y direction to make things
        # more readable
        delta_y = y_size / 100
        ax.set_ylim(-delta_y, y_size + delta_y)
        # set xticks and labels
        ax.set_xticks(xticks)
        ax.set_xticklabels(xlabels, rotation="vertical")
            
        # render chunks
        for idx,chunk in enumerate(chunks):
            for line in chunk.lines:
                ax.add_line(line)
        
        return fig

    def show(self):
        """
        Show plot in a new window
        """
        if self.tree is None:
            self.build_tree()
        fig = self.plot()
        plt.show()
        
        
