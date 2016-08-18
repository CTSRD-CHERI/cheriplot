"""
Plot representation of a CHERI pointer provenance tree
"""
import numpy as np
import logging

from matplotlib import pyplot as plt
from matplotlib import lines, transforms, axes

from itertools import repeat
from functools import reduce
from operator import attrgetter

from .parser import PointerProvenanceParser
from .cheri_provenance import CachedProvenanceTree

logger = logging.getLogger(__name__)

class AddressSpaceAxes(axes.Axes):
    """
    XXX TO DO move the AddressSpaceCanvas here
    This should be moved to a separate module as it is a reusable
    Axes class for various plots involving considerations on
    address-spaces
    """
    pass

class AddressSpaceShrinkTransform(transforms.Transform):
    """
    Non-affine transform that shrinks a selected segment
    of the address-space

    When we have the omit range list we have a complete map
    of which parts of the address-space we are not interested in.

    The size of the shrunk segment (hole) is computed as a function of 
    n_omit_ranges and its X coordinate is computed from the
    cumulative X of the previous (known) segments and holes.

    XXX this needs to be done for xticks as well
    """

    def __init__(self, range_list, *args, **kwargs):
        super(AddressSpaceShrinkTransform, self).__init__(*args, **kwargs)
        self.target_ranges = range_list
        self._inverse = False

        keep = [r for r in self.target_ranges if r.rtype == Range.T_KEEP]
        size = reduce(lambda acc,r: acc + r.size
                      if r.size < np.inf else acc, keep, 0)
        self.omit_width = size / len(keep) * 20 / 100
        """Width of an omitted range"""

        self.has_inverse = True
        self.is_separable = False
        self.input_dims = 2
        self.output_dims = 2

    def get_x_offset(self, range_in):
        """
        Get the data X coordinate based on the omit/keep ranges
        before the current range
        """
        x_offset = 0
        # XXX may use a B-tree of precomputed offsets to speed up
        for r in self.target_ranges:
            if range_in in r:
                if r.rtype == Range.T_KEEP:
                    x_offset += range_in.start - r.start
                    x_len = range_in.size
                else:
                    if (range_in.start == r.start and range_in.size == 0):
                        # if not really overlapping
                        # the length is 0, otherwise points such as
                        # (x,x) with x exactly equal to the start of
                        # the omit range and the end of the previous
                        # keep range are shifted by omit_width when they
                        # should not
                        x_len = 0
                    else:
                        x_len = self.omit_width
                break
            else:
                if r.rtype == Range.T_KEEP:
                    x_offset += r.size
                else:
                    # T_OMIT
                    x_offset += self.omit_width
        return x_offset, x_len

    def get_x_offset_inv(self, range_in):
        """
        Inverse of get_x_offset

        Find the address range corresponding to the plot range
        given by scanning all the target ranges
        """
        return range_in.start, 0
    """
    DISABLED WHY??
        x_offset = 0
        for r in self.target_ranges:
            if r.rtype == Range.T_KEEP:
                next_offset = x_offset + r.size
            else:
                # T_OMIT
                next_offset = x_offset + self.omit_width                
            if range_in in Range(0, next_offset):
                # the plot offset correspond to something is the
                # current range (r)
                # XXX note: this is not accurate as there is no way of
                # knowing the exact x coordinate once something is
                # collapsed in an omit range.
                # This is exact only when the size of omitted ranges
                # match exactly the part of capabilities they contain
                # e.g. there is no capability that ends halfway in an
                # omit range.
                # We don't care about this in the inverse for now.
                return r.start, r.size
            x_offset = next_offset
        return x_offset, 0
    """

    def transform_x(self, datain_range):
        """
        Handle the X axis transformation
        """
        if self._inverse:
            x_offset, x_len = self.get_x_offset_inv(datain_range)
        else:
            x_offset, x_len = self.get_x_offset(datain_range)
        # logger.debug("{%s} %s %s %f" % ("OMIT" if datain_range.rtype == Range.T_OMIT else "KEEP",
        #                                 self.target_ranges,
        #                                 datain_range,
        #                                 x_offset))
        return x_offset, x_len

    def transform_non_affine(self, datain):
        """
        The transform modifies only the X-axis, Y-axis is identity
        """
        if datain.shape == (2,2):
            datain_range = Range(int(datain[0,0]), int(datain[1,0]))
            x_offset, x_len = self.transform_x(datain_range)
            return np.array([[x_offset, datain[0,1]],
                             [x_offset + x_len, datain[1,1]]])
        elif datain.shape == (1,2):
            # single points are handles as lines of length 0
            datain_range = Range(int(datain[0,0]), int(datain[0,0]))
            x_offset, x_len = self.transform_x(datain_range)
            return np.array([[x_offset, datain[0,1]]])
        else:
            logger.debug("skipping %s" % (datain.shape,))
            return datain

    def inverted(self):
        asst = AddressSpaceShrinkTransform(self.target_ranges)
        asst._inverse = not self._inverse
        return asst

class Range:

    T_OMIT = 0
    T_KEEP = 1
    T_UNKN = -1

    def __init__(self, start, end, rtype=-1):
        self.start = start
        self.end = end
        self.rtype = rtype
        """The type is used to distinguish omit and keep ranges"""

    @property
    def size(self):
        return self.end - self.start

    def __str__(self):
        return "<Range [%x, %x]>" % (self.start, self.end)

    def __repr__(self):
        return str(self)

    def __add__(self, other):
        return Range(min(self.start, other.start), max(self.end, other.end))

    def __contains__(self, target):
        """
        target can be a Range or a single address
        """
        try:
            return self.start <= target.end and target.start < self.end
        except:
            return self.start <= addr and addr < self.end

    def __str__(self):
        start = "0x%x" if type(self.start) == int else "%s"
        end = "0x%x" if type(self.end) == int else "%s"
        if self.rtype == self.T_OMIT:
            rtype = "OMIT"
        elif self.rtype == self.T_KEEP:
            rtype = "KEEP"
        else:
            rtype = "UNK"
        fmt = "<Range s:" + start + " e:" + end + " t:%s>"
        return fmt % (self.start, self.end, rtype)


class RangeSet(list):

    def __init__(self, *args):
        super(RangeSet, self).__init__(*args)

    def match_overlap(self, addr):
        """
        Return the list of ranges containing addr
        """
        range_ = Range(addr, addr)
        return self.match_overlap_range(ranges, range_)

    def match_overlap_range(self, target):
        """
        Return the list of ranges overlapping target
        XXX one of the boundaries should not have <= or >=
        otherwise we count that twice for adjacent ranges.
        By convention range intervals are left-closed e.g.
        [start, end)
        """
        overlaps = [r for r in self if (r.start <= target.end and
                                        r.end > target.start)]
        return RangeSet(overlaps)

    def first_overlap_range(self, target):
        """
        Return the first range in the set that overlaps target
        """
        for r in self:
            if (r.start <= target.end and r.end > target.start):
                return r
        return None

class AddressSpaceCanvas:
    """
    Abstract representation of the address space where to draw

    Elements are added to the canvas that handles the partial
    rendering of the address range with gaps where the uninteresting
    parts are.
    The class never exposes actual plot coordinates, so the interface
    consistently use memory addresses for the X axis and whatever
    elements implement for the Y axis.
    """

    DEFAULT_OMIT = 0
    """Default mode: omit all non-included addresses"""
    DEFAULT_INCLUDE = 1
    """Default mode: include all non-omitted addresses"""

    def __init__(self, axes):
        self.ax = axes
        self.omit_filters = RangeSet()
        """List of address ranges that are omitted"""
        self.include_filters = RangeSet()
        """List of address ranges that are included"""
        self.mode = AddressSpaceCanvas.DEFAULT_INCLUDE
        """
        Control what to do with address ranges that are not in 
        the omit or include list
        """
        self.elements = RangeSet()
        """List of elements in the canvas, ordered by start address"""

    def add_element(self, element):
        self.elements.append(element)
        self.elements.sort(key=attrgetter("start"))

    def __iter__(self):
        for elem in self.elements:
            yield elem

    def get_elements_at(self, addr):
        return self.elements.match_overlap(addr)

    def get_elements_in(self, addr_start, addr_end):
        return self.elements.match_overlap_range(
            Range(addr_start, addr_end))

    def _filter(self, target_list, other_list, target_range):
        """Generic omit or include"""
        if len(other_list.match_overlap_range(target_range)):
            raise ValueError("Range %s is present in another filter" %
                             target_range)

        existing_range = target_list.match_overlap_range(target_range)
        assert len(existing_range) < 2, "Too many overlapping ranges"
        try:
            target_range = existing_range[0] + target_range
        except IndexError:
            pass
        finally:
            target_list.append(target_range)
        # XXX may want to sort ranges
    
    def omit(self, addr_start, addr_end):
        """
        Add range to the omit list, if not on the include list
        Use when canvas is in DEFAULT_KEEP mode
        """
        omit_range = Range(addr_start, addr_end)
        self._filter(self.omit_filters, self.include_filters, omit_range)

    def keep(self, addr_start, addr_end):
        """
        Add range to the keep list, if not on the omit list
        Use when canvas is in DEFAULT_OMIT mode
        """
        incl_range = Range(addr_start, addr_end)
        self._filter(self.include_filters, self.omit_filters, incl_range)

    def set_default_mode(self, mode):
        if (mode != self.DEFAULT_OMIT and
            mode != self.DEFAULT_INCLUDE):
            raise ValueError("Invalid mode %d" % mode)
        self.mode = mode

    def map_omit(self, map_range):
        """
        Map the omit and include lists on the given range.
        The range is split in omit regions and include regions,
        the omit regions are the ones to be shrunk in the plot
        while the include regions are rendered normally.

        Return a 2-tuple as (keep-list, omit-list) XXX we now return a single list, the type is encoded in the ranges
        """
        if self.mode == AddressSpaceCanvas.DEFAULT_INCLUDE:
            logger.debug("Map omit regions on %s" % (map_range))
            regions = self.omit_filters.match_overlap_range(map_range)
            # type of mapped regions
            rtype = Range.T_OMIT
            # type of complement regions
            c_rtype = Range.T_KEEP
        else:
            logger.debug("Map include regions on %s" % (map_range))
            regions = self.include_filters.match_overlap_range(map_range)
            # type of mapped regions
            rtype = Range.T_KEEP
            # type of complement regions
            c_rtype = Range.T_OMIT

        regions.sort(key=attrgetter("start"))
        logger.debug("Found %d regions for %s: %s" % (len(regions), map_range, regions))
        mapped = []
        complement = []
        start = None
        for r in regions:
            # r.start can not be after target.end so the
            # mapped range start always in the target boundaries
            # same applies for the r.end and target.end
            start = max(map_range.start, r.start)
            end = min(map_range.end, r.end)
            m_range = Range(start, end, rtype)
            # logger.debug("m_range %s" % m_range)
            # regions are assumed to be sorted by start address
            c_start = mapped[-1].end if len(mapped) else map_range.start
            c_end = start
            c_range = Range(c_start, c_end, c_rtype)
            # logger.debug("c_range %s" % c_range)
            if m_range.size > 0:
                mapped.append(m_range)
            if c_range.size > 0:
                complement.append(c_range)
        # add last block to complement if necessary
        c_start = mapped[-1].end if len(mapped) else map_range.start
        c_end = map_range.end
        c_range = Range(c_start, c_end, c_rtype)
        if c_range.size > 0:
            complement.append(c_range)

        logger.debug("Mapped: %s" % mapped)
        logger.debug("Complement: %s" % complement)

        ranges = RangeSet(mapped + complement)
        # XXX may keep the lists separated to avoid the need to sort
        ranges.sort(key=attrgetter("start"))
        return ranges

    def draw(self):
        y_max = 0
        x_max = 0
        x_ticks = []
        x_labels = []
        
        all_ranges = self.map_omit(Range(0, np.inf))
        transAS = AddressSpaceShrinkTransform(all_ranges)        
        self.ax.transData = transAS + self.ax.transData
        
        for e in self.elements:
            # keep, omit = self.map_omit(e)
            regions = self.map_omit(e)
            logger.debug("Draw %s" % e)
            for r in regions:
                if r.rtype == Range.T_KEEP:
                    e.draw(r.start, r.end, self.ax)
                else:
                    e.omit(r.start, r.end, self.ax)
            y_max = max(y_max, e.y_value)
            x_max = max(x_max, e.node.bound)
        # set axis labels and ticks
        # XXX move transform logic to overridden set_xticks
        # XXX see TickLocator to see if it can be used insted
        # of calling the transAS directly
        for r in all_ranges:
            if r.rtype == Range.T_KEEP:
                x_tick_point = transAS.transform((r.start, 0))
                x_ticks.append(x_tick_point[0])
                x_labels.append("0x%x" % r.start)
        x_tick_point = transAS.transform((x_max, 0))
        x_ticks.append(x_tick_point[0] + transAS.omit_width)
        x_labels.append("0x%x" % x_max)
        self.ax.set_xticks(x_ticks)
        self.ax.set_xticklabels(x_labels, rotation="vertical")
        self.ax.set_ylim(-y_max / 100, y_max)


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
        logger.debug("Draw [0x%x, 0x%x] %d" % (start, end, self.node.t_alloc))
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
        logger.debug("Omit [0x%x, 0x%x] %d" % (start, end, self.node.t_alloc))
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
        logger.debug("Mark %s -> %s" % (node_range, self.ranges))
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
        logger.debug("New omit set %s" % self.ranges)
    
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

    def plot(self):
        """
        Create the provenance plot and return the figure
        """
        fig = plt.figure()
        ax = fig.add_axes([0.05, 0.1, 0.9, 0.85,])

        canvas = AddressSpaceCanvas(ax)
        for child in self.tree:
            self.omit_strategy.inspect(child)
            canvas.add_element(CapabilityRange(child))
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

    
