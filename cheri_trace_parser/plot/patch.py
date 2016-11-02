"""
Copyright 2016 Alfredo Mazzinghi

Copyright and related rights are licensed under the BERI Hardware-Software
License, Version 1.0 (the "License"); you may not use this file except
in compliance with the License.  You may obtain a copy of the License at:

http://www.beri-open-systems.org/legal/license-1-0.txt

Unless required by applicable law or agreed to in writing, software,
hardware and materials distributed under this License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
express or implied.  See the License for the specific language governing
permissions and limitations under the License.
"""

import logging
import numpy as np

from matplotlib import transforms

from cheri_trace_parser.core import RangeSet, Range

logger = logging.getLogger(__name__)

class PatchBuilder:
    """
    The patch generator build the matplotlib patches for each
    dataset item and generates the ranges of address-space in
    which we are not interested
    """

    def __init__(self):
        self.ranges = RangeSet()
        """List of uninteresting ranges of address-space"""
        
        self.size_limit = 2**12
        """Minimum distance between omitted address-space ranges"""
        
        self._bbox = transforms.Bbox.from_bounds(0, 0, 0, 0)
        """Bounding box of the artists in the collections"""
        
        # omit everything if there is nothing to show
        self.ranges.append(Range(0, np.inf, Range.T_OMIT))

    def __iter__(self):
        """
        Allow convenient iteration over the ranges in the builder
        """
        return iter(self.ranges)

    def _update_regions(self, node_range):
        """
        Handle the insertion of a new address range to :attr:`ranges`
        by merging overlapping or contiguous ranges.
        The behaviour is modified by :attr:`size_limit`

        :param node_range: Range specifying the new region
        :type node_range: :class:`cheri_trace_parser.core.Range`
        """
        overlap = self.ranges.match_overlap_range(node_range)
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

    def inspect(self, data):
        """
        Inspect a data item and update internal
        set of ranges

        This is intended to be overridden by subclasses

        :param data: a item of the dataset to be processed
        :type data: object
        """
        return

    def get_omit_ranges(self):
        """
        Return an array of address ranges that do not contain
        interesting data evaluated by :meth:`inspect`

        This is intended to be overridden by subclasses

        :return: a list of (start, end) pairs defining each address
        range that should be considered uninteresting
        :rtype: iterable with shape Nx2
        """
        return [[r.start, r.end] for r in self.ranges]

    def get_patches(self):
        """
        Return a list of patches to draw for the data
        evaluated by :meth:`inspect`

        This is intended to be overridden by subclasses

        :return: a list of matplotlib artists that will be added to
        the Axes
        :rtype: iterable of :class:`matplotlib.artist.Artist`
        """
        return []

    def get_bbox(self):
        """
        Return the bounding box of the data produced, this is useful
        to get the limits in the X and Y of the data

        :return: a bounding box containing all the artists returned by
        :meth:`get_patches`
        :rtype: :class:`matplotlib.transforms.Bbox`
        """
        return self._bbox
