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

import logging
import numpy as np

from matplotlib.transforms import Bbox

# from cheriplot.core.plot import Range

logger = logging.getLogger(__name__)


class PatchBuilder:
    """
    The patch generator build the matplotlib patches for each
    dataset item
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.style = None

    def set_style(self, style):
        """
        Set the style configuration to use

        :param style: dict of style parameters specified in the plot builder
        :type style: dict
        """
        self.style = style

    def inspect(self, data):
        """
        Inspect a data item and update internal
        set of patches.

        This is intended to be overridden by subclasses.

        :param data: a item of the dataset to be processed
        :type data: object
        """
        return

    def get_patches(self, axes):
        """
        Add the patches from the patch builder to the given axes.
        This is intended to be overridden by subclasses.

        :param axes: matplotlib axes
        :type axes: matplotlib.axes.Axes
        """
        return

    def get_bbox(self):
        """
        Return the bounding box of the data produced, this is useful
        to get the limits in the X and Y of the data.

        :return: a bounding box containing all the artists returned by
        :meth:`get_patches`
        :rtype: :class:`matplotlib.transforms.Bbox`
        """
        return Bbox.from_bounds(0, 0, 0, 0)

    def get_legend(self):
        """
        Generate legend handles for the patches produced.

        :return: a list of legend handles
        :rtype: list
        """
        return []

    def get_xticks(self):
        """
        Generate the X axis ticks.

        :return: list of tick X coordinates in data space
        """
        return []

    def get_xlabels(self):
        """
        Generate the X axis labels.

        :return: list of string labels on the X axis or None if
        the default labels are to be used
        """
        return None

    def get_yticks(self):
        """
        Generate the Y axis ticks.

        :return: list of tick Y coordinates in data space
        """
        return []

    def get_ylabels(self):
        """
        Generate the Y axis labels.

        :return: list of string labels on the Y axis or None if
        the default labels are to be used
        """
        return None

    def __str__(self):
        return self.__class__.__name__


class ASAxesPatchBuilder(PatchBuilder):
    """
    This is a PatchBuilders used in ASAxesPlotBuilders
    that need to register a set of address ranges that the
    axes transform should expand.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ranges = set()
        """
        Set of interesting ranges of address-space.
        We use a set to remove duplicates early.
        """

    def _add_range(self, start, end, size_limit=2**12):
        """
        Add a range that we care about

        :param data: a item of the dataset to be processed
        :type data: object
        """
        if (end - start > 2 * size_limit):
            self.ranges.add((start, start + size_limit))
            self.ranges.add((end - size_limit, end))
        else:
            self.ranges.add((start, end))

    def get_patches(self, axes):
        """
        Add the omit range to an instance of AddressSpaceAxes.

        :param axes: axes where the ranges are added
        :type axes: :class:`cheriplot.core.plot.AddressSpaceAxes`
        """
        super().get_patches(axes)
        existing_ranges = axes.get_addr_ranges()
        existing_ranges.extend(self.ranges)
        axes.set_addr_ranges(existing_ranges)


class PickablePatchBuilder:
    """
    Patch builder mixin with additional support for picking
    the objects from the canvas.
    """

    def __init__(self, figure, **kwargs):
        super().__init__(**kwargs)
        self._figure = figure
        """The figure used to register the event handler."""

        self._figure.canvas.mpl_connect("button_release_event", self.on_click)

    def on_click(self, event):
        """
        Handle the click event on the canvas to check which object is being
        selected.
        We do not use the matplotlib "pick_event" because for collections it
        scans the whole collection to find the artist, we may want to do it
        faster (but can still call the picker on the collection patches).
        Also matplotlib does not allow to bind external data
        (e.g. the graph node) to the object so we would have to do
        that here anyway.

        This is intended to be overridden by subclasses.
        """
        return
