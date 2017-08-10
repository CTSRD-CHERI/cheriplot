#-
# Copyright (c) 2016 Alfredo Mazzinghi
# All rights reserved.
#
# This software was developed by SRI International and the University of
# Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
# ("CTSRD"), as part of the DARPA CRASH research programme.
#
# @BERI_LICENSE_HEADER_START@
#
# Licensed to BERI Open Systems C.I.C. (BERI) under one or more contributor
# license agreements.  See the NOTICE file distributed with this work for
# additional information regarding copyright ownership.  BERI licenses this
# file to you under the BERI Hardware-Software License, Version 1.0 (the
# "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at:
#
#   http://www.beri-open-systems.org/legal/license-1-0.txt
#
# Unless required by applicable law or agreed to in writing, Work distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations under the License.
#
# @BERI_LICENSE_HEADER_END@
#

import numpy as np
import logging
import sys

from matplotlib import pyplot as plt
from matplotlib import transforms, axes, scale, axis, lines
from matplotlib.projections import register_projection
from matplotlib.ticker import Formatter, Locator

from operator import attrgetter, itemgetter
from sortedcontainers import SortedDict, SortedListWithKey

from cheriplot.core.plot.label_manager import LabelManager

logger = logging.getLogger(__name__)

class AddressSpaceCollapseTransform(transforms.Transform):
    """
    Transform that shrinks selected segments of the address-space

    Given a list of address ranges in which we are not interested,
    the trasform applies a linear scale to the address-space regions
    marked as Range.T_KEEP, a different scale is applied to Range.T_OMIT
    regions so that these occupy 5% of the total size of the
    Range.T_KEEP regions.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._target_ranges = []
        """
        Unsorted list of target ranges, possibly with duplicates or
        overlapping ranges.
        """

        self._intervals = None
        """
        Numpy array that holds intervals [start,end,type].
        The type is 0 for omit ranges and 1 for keep ranges.
        """

        self._precomputed_offsets = None
        """
        SortedDict that caches the transformed X corresponding to the
        start of each interval
        """

        self.omit_scale = 1
        """Scale factor of the omitted address ranges"""

        self._inverse = False
        """Is this transform performing the direct or inverse operation"""

        self.has_inverse = False # pyplot seems not to care
        self.is_separable = True
        self.input_dims = 2
        self.output_dims = 2

    def set_ranges(self, ranges):
        """
        The ranges here represent the parts of the address space we
        want to show.

        :param ranges: list of intervals in the form [(start, end), ...]
        :type ranges: list of 2-tuples
        """
        logger.debug("Set collapse ranges (%d)", len(ranges))
        self._target_ranges = ranges
        self._precomputed_offsets = None
        self._intervals = None

    def get_ranges(self):
        """See :meth:`set_ranges`."""
        return self._target_ranges

    def _merge(self, intervals):
        """
        Given a set of intervals [(start, end), ...] merge the overlapping
        intervals.
        This is O(n*log(n)) but if all goes well is only done once for every
        plot.
        """
        merged = SortedListWithKey(intervals, key=lambda k: (k[0], k[1]))
        out = []
        if len(merged) == 0:
            return out
        curr = merged[0]
        idx = 1
        while idx < len(merged):
            to_merge = merged[idx]
            if to_merge[0] > curr[1]:
                # we are done with to_merge
                out.append(curr)
                curr = to_merge
            else:
                curr = (curr[0], to_merge[1])
            end_idx = merged.bisect((curr[1], np.inf))
            idx = end_idx
            if end_idx == len(merged):
                end_idx -= 1
            if merged[end_idx][0] <= curr[1]:
                end = max(curr[1], merged[end_idx][1])
            else:
                end = max(curr[1], merged[end_idx - 1][1])
            curr = (curr[0], end)
        out.append(curr)
        logger.debug("Merge collapse ranges (remaining %d)", len(out))
        return out

    def _gen_omit_scale(self, intervals, keep_idx, omit_idx):
        """
        Generate the scale used to collapse omit ranges.
        The scale is computed so that the omitted ranges take up 5% of the
        total size of the keep ranges.
        """
        keep_size = np.sum(intervals[keep_idx,1] - intervals[keep_idx,0])
        # the last omit interval always goes to Inf
        omit_size = np.sum(intervals[omit_idx[:-1],1] - intervals[omit_idx[:-1],0])
        if omit_size != 0:
            # we want the omitted ranges to take up 5% of the keep ranges
            # in size
            # scale = <percent_of_keep_size_to_take> * sum(keep) / sum(omit)
            self.omit_scale = 0.05 * keep_size / omit_size
        logger.debug("Omit scale 5%%: total-keep:%d total-omit:%d scale:%s",
                     keep_size, omit_size, self.omit_scale)

    def _range_len(self, start, end, step):
        return (end - start -1) // step + 1

    def _gen_intervals(self):
        """
        Generate the non-overlapping intervals to display in the
        axis.
        The intervals generated cover the whole axis without holes.
        """
        logger.debug("Generate collapse intervals")
        # merge ranges O(n*log(n)) and sort them
        merged_intervals = self._merge(self._target_ranges)
        if len(merged_intervals) == 0:
            self._intervals = np.zeros((0,3))
            return
        # if the first interval starts from 0, the starting
        # interval is a KEEP interval
        is_start_keep = merged_intervals[0][0] == 0
        holes = len(merged_intervals)
        if not is_start_keep:
            holes += 1
        # generate condition arrays for the piecewise function boundaries
        # cond: [start, end, type]
        n_intervals = len(merged_intervals) + holes
        if is_start_keep:
            # first interval is keep
            keep = range(0,n_intervals, 2)
            omit = range(1,n_intervals, 2)
        else:
            # first interval is omit
            keep = range(1,n_intervals, 2)
            if (self._range_len(1, n_intervals, 2) !=
                self._range_len(0, n_intervals, 2)):
                omit = range(0,n_intervals - 1, 2)
            else:
                omit = range(0,n_intervals, 2)
        intervals = np.zeros((n_intervals,3))
        intervals[keep,2] = 1
        intervals[keep,0:2] = merged_intervals
        intervals[omit,0] = intervals[keep,1]
        intervals[omit[:-1],1] = intervals[keep[1:],0]
        # fixup last omit interval end
        intervals[-1,1] = np.inf
        self._gen_omit_scale(intervals, keep, omit)
        self._intervals = intervals

    def _precompute_offsets(self):
        """
        Precompute the transformed X base values for the start of each
        interval on the axis. The base addresses are used to look up
        the closest interval start when transforming.
        """
        self._gen_intervals()
        logger.debug("Precompute collapse range offsets")
        # reset previous offsets
        self._precomputed_offsets = SortedDict()
        x_collapsed = 0
        for r in self._intervals:
            r_scale = 1 if r[2] else self.omit_scale
            self._precomputed_offsets[r[0]] = (x_collapsed, r_scale)
            x_collapsed += (r[1] - r[0]) * r_scale

    def get_x(self, x_dataspace):
        """
        Get the transformed X coordinate.
        This is just a lookup in the precomputed offsets and some calculations,
        should be O(log(n)) in the number of intervals (which is expected to be
        at most in the order of 10**3~10**4)
        """
        if self._precomputed_offsets == None:
            self._precompute_offsets()

        if x_dataspace < 0 or len(self._precomputed_offsets) == 0:
            return x_dataspace
        base_idx = self._precomputed_offsets.bisect_left(x_dataspace)
        if (len(self._precomputed_offsets) == base_idx or
            self._precomputed_offsets.iloc[base_idx] > x_dataspace):
            key = self._precomputed_offsets.iloc[base_idx - 1]
        else:
            key = x_dataspace
        x_collapsed, x_scale = self._precomputed_offsets[key]
        return x_collapsed + (x_dataspace - key) * x_scale

    def get_x_inv(self, x):
        """
        Inverse of get_x

        Find the address range corresponding to the plot range
        given by scanning all the target ranges
        XXX: this may be made faster by using a reverse form of
        the precomputed offsets but there is no need for
        such an effort because the inverse transform is not
        invoked as much.
        """
        if self._precomputed_offsets == None:
            self._precompute_offsets()
        x_inverse = 0
        x_current = 0
        for r in self._intervals:
            r_size = r[1] - r[0]
            if r[2] == 1:
                # range is type KEEP
                if x > x_current + r_size:
                    x_current += r_size
                    x_inverse += r_size
                else:
                    x_inverse += x - x_current
                    break
            elif r[2] == 0:
                scaled_size = r_size * self.omit_scale
                if x > x_current + scaled_size:
                    x_current += scaled_size
                    x_inverse += r_size
                else:
                    x_inverse += (x - x_current) / self.omit_scale
                    break
            else:
                logger.error("The range %s must have a valid type", r)
                raise ValueError("Unexpected range in transform %s", r)
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
        trans = AddressSpaceCollapseTransform()
        trans._target_ranges = self._target_ranges
        trans._intervals = self._intervals
        trans._precomputed_offsets = self._precomputed_offsets
        trans.omit_scale = self.omit_scale
        trans._inverse = not self._inverse
        return trans


class HexFormatter(Formatter):
    """
    Formatter that generates an hex representation
    for the value.
    """
    def __call__(self, x, pos=None):
        return "0x%x" % int(x)


class AddressSpaceTickLocator(Locator):
    """
    Locator that generates the default tick
    values from the ASCollapseTransform intevals
    """
    
    def __init__(self, scale):
        self.scale = scale
        """The address space scale"""

    def __call__(self):
        vmin, vmax = self.axis.get_view_interval()
        return self.tick_values(vmin, vmax)

    def tick_values(self, vmin, vmax):
        """
        Return the location of the ticks using the
        scale transform to convert from data ticks to
        ticks in the scaled axis coordinates
        """
        trans = self.scale.get_transform()
        values = []
        for r in trans._intervals:
            if r[2] == 1:
                # keep interval
                if len(values) > 0:
                    prev = trans.transform((values[-1], 0))[0]
                    curr = trans.transform((r[0], 0))[0]
                    # XXX 2**12 is an empiric value we should use
                    # the bounding box of the label but there is no
                    # easy way to get it from here
                    if curr - prev < 2**12:
                        # skip tick if they end up too close
                        continue
                values.append(r[0])
        return values


class AddressSpaceScale(scale.ScaleBase):
    """
    Non-uniform scale that applies a different scaling function
    to parts of the address space marked as "not interesting"
    (:attr:`Range.T_OMIT`)
    """
    name = "scale_addrspace"
    max_address = 0xFFFFFFFFFFFFFFFF

    def __init__(self, axis, **kwargs):
        super(AddressSpaceScale, self).__init__()
        self.transform = AddressSpaceCollapseTransform()

    def get_transform(self):
        return self.transform

    def set_default_locators_and_formatters(self, axis):
        axis.set_major_locator(AddressSpaceTickLocator(self))
        axis.set_major_formatter(HexFormatter())
        axis.set_minor_formatter(HexFormatter())

    def limit_range_for_scale(self, vmin, vmax, minpos):
        """
        Just return the linear limit, the trasformation of the scale
        will be applied later on when setting the viewLimit on the
        axis Spine.
        """
        return max(vmin, 0), min(vmax, self.max_address)

scale.register_scale(AddressSpaceScale)


class AddressSpaceXTick(axis.XTick):

    def _get_ticklabel_line(self):
        axis_trans = self.axes.get_xaxis_transform(which="tick1")
        text_trans = self._get_text1_transform()[0]
        tick_position = axis_trans.transform((self.tick1line.get_xdata()[0],
                                              self.tick1line.get_ydata()[0]))
        label_position = text_trans.transform(self.label1.get_position())
        x = (tick_position[0], label_position[0])
        y = (tick_position[1], label_position[1])
        line = lines.Line2D(x, y, linestyle="solid", color="black")
        return line

    # @allow_rasterization
    def draw(self, renderer):
        super(AddressSpaceXTick, self).draw(renderer)

        line = self._get_ticklabel_line()
        line.draw(renderer)


class AddressSpaceXAxis(axis.XAxis):
    """
    Custom XAxis for the AddressSpace projection
    """

    def _get_tick(self, major):
        """
        Force labels to be vertical
        """
        if major:
            tick_kw = self._major_tick_kw
        else:
            tick_kw = self._minor_tick_kw
        tick = AddressSpaceXTick(self.axes, 0, '', major=major, **tick_kw)
        prop = {"rotation": "vertical"}
        tick.label1.update(prop)
        tick.label2.update(prop)
        return tick

    def _update_ticks(self, renderer):
        ticks = super(AddressSpaceXAxis, self)._update_ticks(renderer)
        mgr = LabelManager(direction="h")
        mgr.add_labels([t.label1 for t in ticks])
        mgr.update_label_position(renderer)
        return ticks

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

    def __init__(self, *args, **kwargs):
        self._status_message = ""
        kwargs["xscale"] = "scale_addrspace"
        super(AddressSpaceAxes, self).__init__(*args, **kwargs)
        self.fmt_xdata = self._fmt_xdata

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
        """Override transform initialization."""

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

        # data to display coordinates
        self.transData = self.transScale + (
            self.transLimits + self.transAxes)

        # blended transforms for xaxis and yaxis
        self._xaxis_transform = transforms.blended_transform_factory(
            self.transData, self.transAxes)
        self._yaxis_transform = transforms.blended_transform_factory(
            self.transAxes, self.transData)

    def get_addr_ranges(self):
        return self.xaxis.get_transform().get_ranges()

    def set_addr_ranges(self, ranges):
        self.xaxis.get_transform().set_ranges(ranges)

    def set_status_message(self, message):
        """
        Set the status message to show in the status bar along with
        the (x,y) coordinates of the mouse
        """
        self._status_message = message

    def _fmt_xdata(self, x):
        """Override the formatting of the x-axis data in the statusbar."""
        try:
            return "0x%x" % int(x)
        except ValueError:
            return "???"

    def format_coord(self, x, y):
        """
        Add the status message to the status bar format string
        """
        xy_fmt = super().format_coord(x, y)
        return "%s %s" % (xy_fmt, self._status_message)

register_projection(AddressSpaceAxes)
