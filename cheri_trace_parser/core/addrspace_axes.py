import numpy as np
import logging
import sys

from matplotlib import pyplot as plt
from matplotlib import lines, transforms, axes

from itertools import repeat
from functools import reduce
from operator import attrgetter

from cheri_trace_parser.utils import ProgressPrinter

logger = logging.getLogger(__name__)

# class AddressSpaceAxes(axes.Axes):
#     """
#     XXX TO DO move the AddressSpaceCanvas here as it the
#     way matplotlib works
#     Axes class for various plots involving considerations on
#     address-spaces
#     """
#     pass

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
            logger.debug("skipping %s", datain.shape)
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
            logger.debug("Map omit regions on %s", map_range)
            regions = self.omit_filters.match_overlap_range(map_range)
            # type of mapped regions
            rtype = Range.T_OMIT
            # type of complement regions
            c_rtype = Range.T_KEEP
        else:
            logger.debug("Map include regions on %s", map_range)
            regions = self.include_filters.match_overlap_range(map_range)
            # type of mapped regions
            rtype = Range.T_KEEP
            # type of complement regions
            c_rtype = Range.T_OMIT

        regions.sort(key=attrgetter("start"))
        logger.debug("Found %d regions for %s: %s", len(regions), map_range, regions)
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
            # logger.debug("m_range %s", m_range)
            # regions are assumed to be sorted by start address
            c_start = mapped[-1].end if len(mapped) else map_range.start
            c_end = start
            c_range = Range(c_start, c_end, c_rtype)
            # logger.debug("c_range %s", c_range)
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

        logger.debug("Mapped: %s", mapped)
        logger.debug("Complement: %s", complement)

        ranges = RangeSet(mapped + complement)
        # XXX may keep the lists separated to avoid the need to sort
        ranges.sort(key=attrgetter("start"))
        return ranges

    def draw(self):
        y_max = 0
        x_max = 0
        x_ticks = []
        x_labels = []
        draw_progress = ProgressPrinter(len(self.elements), desc="Draw nodes")
        self.elements.sort(key=attrgetter("start"))

        all_ranges = self.map_omit(Range(0, np.inf))
        transAS = AddressSpaceShrinkTransform(all_ranges)
        self.ax.transData = transAS + self.ax.transData

        for e in self.elements:
            draw_progress.advance()
            # keep, omit = self.map_omit(e)
            regions = self.map_omit(e)
            logger.debug("Draw %s", e)
            for r in regions:
                if r.rtype == Range.T_KEEP:
                    e.draw(r.start, r.end, self.ax)
                else:
                    e.omit(r.start, r.end, self.ax)
            y_max = max(y_max, e.y_value)
            x_max = max(x_max, e.end)
        draw_progress.finish()
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
        self.ax.set_xlim(x_ticks[0], x_ticks[-1])
