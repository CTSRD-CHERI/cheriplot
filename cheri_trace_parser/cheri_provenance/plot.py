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

    def _make_lines(self, x_offset, x_gap):
        """
        Prepare all the lines in the chunk and return the space
        in the X axis taken by the chunk.
        The x_gap is the size of a separation space between chunks,
        this is given in case the chunk need to create multiple blocks
        that are separated. It is not used in the simple case as the gap
        is handled by ChunkGap
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
            # # add dotted continuation line for the parent if parent
            # # is not starting exactly at the same point as the chunk
            # if parent.base < self.node.base:
            #     gap_line = lines.Line2D([x_offset, chunk_x],
            #                             [chunk_y, chunk_y],
            #                             linestyle="dotted")
            #     self.lines.append(gap_line)
        return self.size + x_gap

    def make_lines(self, x_offset, x_gap):
        """
        Prepare all the lines in the chunk and return the space
        in the X axis taken by the chunk.
        The x_gap is the size of a separation space between chunks,
        this is given in case the chunk need to create multiple blocks
        that are separated. It is not used in the simple case as the gap
        is handled by ChunkGap
        """
        chunk_x = x_offset
        chunk_y = PointerProvenancePlot.scale_time(self.node.t_alloc)
        line = lines.Line2D([chunk_x, chunk_x + self.size],
                            [chunk_y, chunk_y])
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
            self.lines.append(line)
        logger.debug("Draw %d lines for chunk [0x%x, 0x%x] as [%d, %d]" %
                     (len(self.lines), self.start, self.end,
                      chunk_x, chunk_x + self.size))
        return self.size

    def make_xtick(self, x_offset, x_gap):
        """
        Generate the plot xtick and associated label
        for this chunk
        """
        xtick = x_offset + x_gap
        xlabel = "0x%x" % self.start
        return (xtick, xlabel)

    def add_subchunk(self, chunk):
        logger.debug("Creating merged chunk [%x, %x] + [%x, %x]" %
                     (self.start, self.end, chunk.start, chunk.end))
        return ChunkGroup([self, chunk])

    def __str__(self):
        return "<Chunk start:0x%x end:0x%x>" % (self.start, self.end)


class LargeChunk(Chunk):

    def __init__(self, *args):
        super(LargeChunk, self).__init__(*args)

    @property
    def size(self):
        return 0 # XXX TO DO

    def make_lines(self, x_offset, x_gap):
        return 0

    def make_xtick(self, x_offset, x_gap):
        return (None, None)

    def __str__(self):
        return "<LargeChunk start:0x%x end:0x%x>" % (self.start, self.end)


class ChunkGroup(Chunk):

    def __init__(self, chunks):
        super(ChunkGroup, self).__init__(None)
        self.sub_chunks = chunks

    def __iter__(self):
        for cnk in self.sub_chunks:
            for parent in cnk:
                yield parent

    @property
    def start(self):
        base = np.inf
        for cnk in self.sub_chunks:
            if cnk.start < base:
                base = cnk.start
        return base

    @property
    def end(self):
        end = 0
        for cnk in self.sub_chunks:
            if cnk.end > end:
                end = cnk.end
        return end

    @property
    def size(self):
        logger.debug("group size %d %s" % (self.end - self.start, self.sub_chunks[0]))
        return self.end - self.start

    def make_lines(self, x_offset, x_gap):
        """
        Make lines for a chunk group

        The first chunk is generated normally, as we still need to
        account for the gap between this chunk and the previous one.
        Other chunks are rendered relative to the start of the first
        chunk (in order of start address), in this case the gap is the
        distance (delta address) between the first chunk and the
        one being rendered.

        XXX the notion of gap may be quite confusing, how about using
        only the offset and add the gap in another layer?
        (e.g. decorator pattern)
        """
        total_size = 0
        curr_x_offset = x_offset
        sub_chunks = sorted(self.sub_chunks, key=attrgetter("start"))
        first_chunk = sub_chunks[0]
        for cnk in sub_chunks:
            curr_x_offset += cnk.start - first_chunk.start
            logger.debug("curr_x_offset %d", curr_x_offset)
            total_size += cnk.make_lines(curr_x_offset, x_gap)
        # merge lines
        map(lambda cnk: self.lines.extend(cnk.lines), self.sub_chunks)
        return curr_x_offset - x_offset

    def add_subchunk(self, chunk):
        self.sub_chunks.append(chunk)
        logger.debug("Add to merged chunk [%x, %x] + [%x, %x]" %
                     (self.start, self.end, chunk.start, chunk.end))
        return self

    def __str__(self):
        return "<ChunkGroup start:0x%x end:0x%x>" % (self.start, self.end)


class ChunkGap(Chunk):
    """
    Decorator that adds a gap before the wrapped chunk
    Parent capabilities are shown in the gap as dotted lines
    """

    def __init__(self, chunk):
        super(ChunkGap, self).__init__(None)
        self.wrapped = chunk
        self.lines = self.wrapped.lines

    def __iter__(self):
        for item in self.wrapped:
            yield item

    @property
    def start(self):
        return self.wrapped.start

    @property
    def end(self):
        return self.wrapped.end

    @property
    def size(self):
        return self.wrapped.size

    def make_lines(self, x_offset, x_gap):
        """
        Prepare the lines and adds an inter-chunk separation
        space. Capabilities that overflow the wrapped chunk boundaries
        are represented as dotted lines in the gap space.
        """
        chunk_x = x_offset + x_gap
        size = self.wrapped.make_lines(chunk_x, x_gap)
        # add lines for parent nodes
        for parent in self.wrapped:
            # add dotted continuation line for the parent if parent
            # is not starting exactly at the same point as the chunk
            if parent.base < self.wrapped.start:
                chunk_y = PointerProvenancePlot.scale_time(parent.t_alloc)
                gap_line = lines.Line2D([x_offset, chunk_x],
                                        [chunk_y, chunk_y],
                                        linestyle="dotted")
                self.lines.append(gap_line)
        return size + x_gap

    def make_xtick(self, *args):
        return self.wrapped.make_xtick(*args)

    def add_subchunk(self, *args):
        return ChunkGap(self.wrapped.add_subchunk(*args))

    def __str__(self):
        return "<ChunkGap %s>" % str(self.wrapped)


class PointerProvenancePlot:

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
        Return a list of chunks and the maximum time found to
        set the Y scale (this is to avoid walking the tree multiple
        times).

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
        # get leaves merging chunks referring to duplicate leaves
        chunks = {}
        time_max = 0
        for child in self.tree:
            if child.t_alloc > time_max:
                time_max = child.t_alloc
            if len(child) == 0:
                if child.length > self.large_chunk_size:
                    chunk = LargeChunk(child)
                    logger.warning("LargeChunk not implemented")
                    continue
                else:
                    chunk = Chunk(child)
                logger.debug("Found chunk %s" % chunk)
                # At this point we need to find if there is a chunk that
                # already contains or partially contains the address
                # range of the current chunk, if so a Group is created
                # or the current chunk is appended to an existing Group.
                # There are 3 situations to handle:
                # i) duplicates: same start and end, match by start and
                #  add to group.
                # ii) non-exact overlap: happens when two capabilities
                # share a portion of the address space but they are not
                # parent-child, the overlap may or may not be complete.
                # The Group can handle that but they have to be detected.
                # iii) overlap with large chunks: ?

                if not chunk.start in chunks:
                    chunk = ChunkGap(chunk)
                    chunks[chunk.start] = chunk
                elif chunks[chunk.start].end == chunk.end:
                    # see(i)
                    chunks[chunk.start] = chunks[chunk.start].add_subchunk(chunk)
                else:
                    # XXX TO DO (ii) and (iii) unsupported
                    logger.error("UNSUPPORTED CHUNK MERGE")
                    logger.warning("Skipping chunk")
                    # raise NotImplementedError("Unsupported chunk merge")
                logger.debug("Processed chunk %s" % chunks[chunk.start])

        chunks = sorted(chunks.values(), key=attrgetter("start"))
        # XXX chunks at this point must be non-overlapping,
        # it may be worth adding an assertion for this?
        
        # XXX we should really show also duplicates that are not leaves
        # this is somewhat the same problem of detecting non-leaf nodes
        # that cover a part of the address space without being parents of
        # any of the nodes in there (e.g. root->[10, 50] and root->[20, 30]
        # see (ii) above.
        
        return {"chunks": chunks,
                "time_max": time_max}

    def plot(self):
        """
        Create the provenance plot and return the figure
        """
        fig = plt.figure()
        ax = fig.add_axes([0.05, 0.1, 0.9, 0.85,])

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
        
        
