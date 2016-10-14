import numpy as np
import logging
import sys

from matplotlib import pyplot as plt
from matplotlib import transforms, axes, scale, axis
from matplotlib.projections import register_projection
from matplotlib.cbook import iterable
from matplotlib.ticker import Formatter, FixedLocator, Locator

from itertools import repeat
from functools import reduce
from operator import attrgetter

from cheri_trace_parser.utils import ProgressPrinter

logger = logging.getLogger(__name__)

class AddressSpaceCollapseTransform(transforms.Transform):
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

    def __init__(self, *args, **kwargs):
        super(AddressSpaceCollapseTransform, self).__init__(*args, **kwargs)
        self.target_ranges = RangeSet()
        """List of ranges to keep and omit"""
        
        self.omit_scale = 1
        """Scale factor of the omitted address ranges"""

        self.target_ranges.append(Range(0, np.inf, Range.T_KEEP))
        self._inverse = False

        self.has_inverse = False # pyplot seems not to care
        self.is_separable = True
        self.input_dims = 2
        self.output_dims = 2

    def update_range(self, range_list):
        """
        Update parameters depending on the omit ranges
        """
        self.target_ranges = range_list

        keep = [r for r in self.target_ranges if r.rtype == Range.T_KEEP]
        omit = [r for r in self.target_ranges if r.rtype == Range.T_OMIT]
        # total size of the KEEP ranges
        keep_size = reduce(lambda acc,r: acc + r.size
                           if r.size < np.inf else acc, keep, 0)
        omit_size = reduce(lambda acc,r: acc + r.size
                           if r.size < np.inf else acc, omit, 0)
        # we want the omitted ranges to take up 5% of the keep ranges
        # in size
        # scale = <percent_of_keep_size_to_take> * sum(keep) / sum(omit)
        self.omit_scale = 0.05 * keep_size / omit_size

    def get_x(self, x):
        """
        Get the data X coordinate based on the omit/keep ranges
        """
        x_offset = 0
        for r in self.target_ranges:
            if x in r:
                if r.rtype == Range.T_KEEP:
                    x_offset += x - r.start
                break
            else:
                # r.end < x because target_ranges are sorted
                if r.rtype == Range.T_KEEP:
                    x_offset += r.size
                else:
                    # T_OMIT
                    x_offset += r.size * self.omit_scale # self.omit_width
        return x_offset


    def get_x_inv(self, x):
        """
        Inverse of get_x

        Find the address range corresponding to the plot range
        given by scanning all the target ranges
        """
        x_inverse = 0
        x_current = 0
        for r in self.target_ranges:
            if r.rtype == Range.T_KEEP:                
                if x > x_current + r.size:
                    x_current += r.size
                    x_inverse += r.size
                else:
                    x_inverse += x - x_current
                    break
            else:
                scaled_size = r.size * self.omit_scale
                if x > x_current + scaled_size:
                    x_current += scaled_size
                    x_inverse += r.size
                else:
                    x_inverse += (x - x_current) / self.omit_scale
                    break
        return x_inverse

    def transform_x(self, x):
        """
        Handle the X axis transformation
        """
        if self._inverse:
            return self.get_x_inv(x)
        else:
            return self.get_x(x)
    
    def transform_non_affine(self, datain):
        """
        The transform modifies only the X-axis, Y-axis is identity
        
        datain is a numpy array of size Nx2
        return a numpy array of size Nx2
        """
        _prev = np.array(datain)
        dataout = np.array(datain)
        for point in dataout:
            point[0] = self.transform_x(point[0])
        return dataout

    def inverted(self):
        trans = AddressSpaceCollapseTransform(self.target_ranges)
        trans._inverse = not self._inverse
        return trans


class AddressSpaceScale(scale.ScaleBase):
    """
    Non-uniform scale that shrinks parts of the address space in which
    we are not interested in
    """

    name = "scale_addrspace"

    max_address = 0xFFFFFFFFFFFFFFFF

    class HexFormatter(Formatter):
        def __call__(self, x, pos=None):
            return "0x%x" % int(x)


    class AddressSpaceTickLocator(Locator):
        def __init__(self, scale):
            self.scale = scale
        
        def __call__(self):
            vmin, vmax = self.axis.get_view_interval()
            return self.tick_values(vmin, vmax)

        def tick_values(self, vmin, vmax):
            """
            Return the location of the ticks using the
            scale transform to convert from data ticks to
            ticks in the scaled axis coordinates
            """
            trans = self.scale.transform
            ranges = trans.target_ranges
            values = []
            for r in ranges:
                if r.rtype == Range.T_KEEP:
                    values.append(r.start)
            return values


    def __init__(self, axis, **kwargs):
        super(AddressSpaceScale, self).__init__()
        self.transform = AddressSpaceCollapseTransform()

    def get_transform(self):
        return self.transform

    def set_default_locators_and_formatters(self, axis):
        axis.set_major_locator(self.AddressSpaceTickLocator(self))
        axis.set_major_formatter(self.HexFormatter())
        axis.set_minor_formatter(self.HexFormatter())

    def limit_range_for_scale(self, vmin, vmax, minpos):
        """
        Just return the linear limit, the trasformation of the scale
        will be applied later on when setting the viewLimit on the
        axis Spine.
        """
        return max(vmin, 0), min(vmax, self.max_address)


scale.register_scale(AddressSpaceScale)


class AddressSpaceXAxis(axis.XAxis):
    """
    Custom XAxis with 
    """
    
    def _get_tick(self, **kwargs):
        """
        Force labels to be vertical
        """
        tick = super(AddressSpaceXAxis, self)._get_tick(**kwargs)
        prop = {"rotation": "vertical"}
        tick.label1.update(prop)
        tick.label2.update(prop)
        return tick

    def _get_pixel_distance_along_axis(self, where, perturb):
        """
        Like the polar plot it is not meaningful
        """
        return 0.0

    
class AddressSpaceAxes(axes.Axes):
    """
    Axes class for various plots involving considerations on
    address-spaces
    """

    name = "custom_addrspace"

    DEFAULT_OMIT = 0
    """Default mode: omit all non-included addresses"""
    DEFAULT_INCLUDE = 1
    """Default mode: include all non-omitted addresses"""

    def __init__(self, *args, **kwargs):
        self.omit_filters = RangeSet()
        self.include_filters = RangeSet()
        self.mode = AddressSpaceAxes.DEFAULT_INCLUDE
        self.transAS = None
        kwargs["xscale"] = "scale_addrspace"
        super(AddressSpaceAxes, self).__init__(*args, **kwargs)

    def _init_axis(self):
        """
        We need a custom XAxis because there is currently no way
        of setting the tick label direction to vertical from the
        Scale class
        """
        self.xaxis = AddressSpaceXAxis(self)
        self.spines['bottom'].register_axis(self.xaxis)
        self.spines['top'].register_axis(self.xaxis)
        self.yaxis = axis.YAxis(self)
        self.spines['left'].register_axis(self.yaxis)
        self.spines['right'].register_axis(self.yaxis)
        self._update_transScale()

    def _set_lim_and_transforms(self):
        """
        Override transform initialization
        """
        
        # axis coords to display coords
        self.transAxes = transforms.BboxTransformTo(self.bbox)
        
        # X and Y axis scaling
        self.transScale = transforms.TransformWrapper(
            transforms.IdentityTransform())
        # transform from given Bbox to unit Bbox
        # the given transformedBbox is updated every time the
        # viewLim changes or the transScale changes
        self.transLimits = transforms.BboxTransformFrom(
            transforms.TransformedBbox(self.viewLim, self.transScale))

        # address space non-uniform X scaling
        # self.transAS = AddressSpaceCollapseTransform()

        # data to display coordinates
        self.transData = self.transScale + (
            self.transLimits + self.transAxes)
        # self.transData = self.transAS + self.transScale + (
        #     self.transLimits + self.transAxes)

        # blended transforms for xaxis and yaxis
        self._xaxis_transform = transforms.blended_transform_factory(
            self.transData, self.transAxes)
        self._yaxis_transform = transforms.blended_transform_factory(
            self.transAxes, self.transData)

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

    def _map_omit(self, map_range):
        """
        Map the omit and include lists on the given range.
        The range is split in omit regions and include regions,
        the omit regions are the ones to be shrunk in the plot
        while the include regions are rendered normally.

        Return a RangeSet containing the ranges to keep and omit that overlap
        the input range
        """
        if self.mode == AddressSpaceAxes.DEFAULT_INCLUDE:
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

    def set_omit_ranges(self, ranges):
        """
        Configure the set of addresses (x-axis values) that
        are omitted from the plot. These are collapsed to
        a small separation space between chunks of address-space
        that are displayed normally.

        Accept an Nx2 array in the form [[r_start, r_end], ...]
        """
        for r in ranges:
            self._filter(self.omit_filters, self.include_filters,
                         Range(r[0], r[1], Range.T_OMIT))
        all_ranges = self._map_omit(Range(0, np.inf))
        self.xaxis.get_transform().update_range(all_ranges)

    def set_xticks(self, ticks, **kwargs):
        logger.debug("set xticks %s", ticks)
        return super(AddressSpaceAxes, self).set_xticks(ticks, **kwargs)

    def set_xlim(self, *args, **kwargs):
        logger.debug("set xlimit %s %s", args, kwargs)
        return super(AddressSpaceAxes, self).set_xlim(*args, **kwargs)
        
    ## interactive panning and zoom

    def can_zoom(self):
        # XXX unsupported yet
        return False

    def can_pan(self):
        # XXX unsupported yet
        return False

    # def start_pan(self, x, y, button):
    #     pass

    # def end_pan(self):
    #     pass

    # def drag_pan(self, button, key, x, y):
    #     pass

register_projection(AddressSpaceAxes)

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
        if len(keep) > 0:
            self.omit_width = size / len(keep) * 20 / 100
            """Width of an omitted range"""

        self.has_inverse = True
        self.is_separable = False
        self.input_dims = 2
        self.output_dims = 2

    def update_range(self, range_list):
        self.target_ranges = range_list
        keep = [r for r in self.target_ranges if r.rtype == Range.T_KEEP]
        size = reduce(lambda acc,r: acc + r.size
                      if r.size < np.inf else acc, keep, 0)
        self.omit_width = size / len(keep) * 20 / 100

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
            return self.start <= target and target < self.end

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
