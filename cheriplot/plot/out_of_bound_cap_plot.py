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

import numpy as np
import logging
import pickle

from matplotlib import pyplot as plt
from matplotlib.collections import LineCollection, PathCollection
from matplotlib.markers import MarkerStyle
from matplotlib.transforms import Bbox, IdentityTransform
from matplotlib.colors import colorConverter

from ..utils import ProgressPrinter
from ..core import RangeSet, Range, CallbackTraceParser
from ..plot import Plot, PatchBuilder

logger = logging.getLogger(__name__)


class OutOfBoundParser(CallbackTraceParser):
    """
    Scan the trace and record all pointer operations that bring the
    capability offset out-of-bounds
    """

    def scan_cap_arith(self, inst, entry, regs, last_regs, idx):
        register = inst.cd.value
        # check if we went out of bound
        offset = register.base + register.offset
        bound = register.base + register.length
        if (offset > bound or offset < register.base):
            data_entry = np.array([entry.cycles, register.base, bound, offset])
            logger.debug("[%d] Found out-of-bound capability"\
                         " base: 0x%x, len: 0x%x, off: 0x%x",
                         idx, register.base, register.length, register.offset)
            self.dataset.append(data_entry)
        return False


class OutOfBoundPlotPatchBuilder(PatchBuilder):
    """
    Generate patches for the out-of-bound plot.
    Each capability that is left with an out-of-bounds offset is
    rendered as 3 patches:
    - a solid line indicating the range
    - a dot indicating the offset
    - a dotted line connecting the dot to the range to make
    it more clear which offset belongs to which capability
    """

    def __init__(self):
        super(OutOfBoundPlotPatchBuilder, self).__init__()

        self.split_size = 2 * self.size_limit
        """
        Capability length threshold to trigger the omission of
        the middle portion of the capability range.
        """

        self._cap_ranges = []
        """
        List of line coordinates for ranges of capabilities that 
        have violated the bounds. This is used to build a 
        :class:`matplotlib.collections.LineCollection`
        """

        self._oob_links = []
        """
        List of line coordinates for the dotted lines connecting
        the capability range and the offset dot
        """
        
        self._oob_offsets = []
        """
        List of coordinates for the dots representing the out-of-bound
        offsets
        """

        # clear the bbox, we are creating it from scratches
        self._bbox = None

    def inspect(self, data):
        """
        The data item for an out-of-bound capability is expected to 
        be in the form [cycles, base, length, offset]
        """
        logger.debug("Inspect data point %s", data)
        cycles, base, bound, offset = data
        cap_range = ((base, cycles), (bound, cycles))
        oob_offset = (offset, cycles)
        if offset < base:
            oob_link = ((offset, cycles), (base, cycles))
        else:
            # offset > base + length because we are certain that
            # it is out of bounds
            oob_link = ((bound, cycles), (offset, cycles))
        self._cap_ranges.append(cap_range)
        self._oob_links.append(oob_link)
        self._oob_offsets.append(oob_offset)
        
        # update bounding box
        range_bbox = Bbox(cap_range)
        link_bbox = Bbox(oob_link)
        offset_bbox = Bbox([oob_offset, oob_offset])
        if self._bbox:
            self._bbox = Bbox.union([self._bbox, range_bbox,
                                     link_bbox, offset_bbox])
        else:
            self._bbox = Bbox.union([range_bbox, link_bbox, offset_bbox])

        # update ranges
        logger.debug("View %s", self._bbox)
        self._update_regions(Range(self._bbox.xmin, self._bbox.xmax,
                                   Range.T_KEEP))

    def get_patches(self, ax):
        ranges = LineCollection(self._cap_ranges,
                                linestyle="solid")
        links = LineCollection(self._oob_links,
                               linestyle="dotted",
                               colors=colorConverter.to_rgba_array("#808080"))

        color = colorConverter.to_rgba_array("#DC143C")
        scales = np.array((20,))
        marker_obj = MarkerStyle("o")
        path = marker_obj.get_path().transformed(
            marker_obj.get_transform())

        offsets = PathCollection(
            (path,), scales,
            facecolors=color,
            offsets=self._oob_offsets,
            transOffset=ax.transData)
        offsets.set_transform(IdentityTransform())
        
        return [ranges, links, offsets]


class CapOutOfBoundPlot(Plot):
    """
    Plot the time, range and offset of out-of-bound capability 
    manipulations
    """

    def __init__(self, tracefile):
        super(CapOutOfBoundPlot, self).__init__(tracefile)

        self.patch_builder = OutOfBoundPlotPatchBuilder()
        """Strategy object that builds the plot components"""

    def _get_cache_file(self):
        return self.tracefile + "_oob.cache"

    def build_dataset(self):
        if self._caching:
            fname = self._get_cache_file()
            try:
                with open(fname, "rb") as fd:
                    self.dataset = pickle.load(fd)
                    logger.info("Using cached dataset %s", fname)
            except IOError:
                self.parser.parse()
                with open(fname, "wb") as fd:
                    pickle.dump(self.dataset, fd, pickle.HIGHEST_PROTOCOL)
                logger.info("Saving cached dataset %s", fname)
        else:
            self.parser.parse()

        # inject fake item for testing
        # self.dataset.append([100, 0x30000, 0x40000, 0x41000])
        # self.dataset.append([125, 0x6000, 0x20000, 0x24000])
        # self.dataset.append([130, 0x10000, 0x12000, 0x8000])
        # self.dataset.append([150, 0x3000, 0x5000, 0x6000])
        self.dataset = np.array(self.dataset)

    def init_parser(self):
        return OutOfBoundParser(self.dataset, self.tracefile)

    def init_dataset(self):
        return []

    def plot(self):
        """
        Create the time, range and offset of out-of-bound
        capability manipulations
        """
        progress = ProgressPrinter(len(self.dataset), desc="Generating plot")
        fig = plt.figure(figsize=(15,10))
        ax = fig.add_axes([0.05, 0.15, 0.9, 0.8,],
                          projection="custom_addrspace")
        ax.set_ylabel("Time (cycles)")
        ax.set_xlabel("Virtual Address")
        ax.set_title("Distribution of out-of-bounds capability computations")
        for item in self.dataset:
            progress.advance()
            self.patch_builder.inspect(item)
        progress.finish()

        for collection in self.patch_builder.get_patches(ax):
            ax.add_collection(collection)
        ax.set_omit_ranges(self.patch_builder.get_omit_ranges())
        
        view_box = self.patch_builder.get_bbox()
        xmin = view_box.xmin * 0.98
        xmax = view_box.xmax * 1.02
        ymin = view_box.ymin * 0.98
        ymax = view_box.ymax * 1.02
        logger.debug("X limits: (%d, %d)", xmin, xmax)
        ax.set_xlim(xmin, xmax)
        logger.debug("Y limits: (%d, %d)", ymin, ymax)
        ax.set_ylim(ymin, ymax)
        ax.invert_yaxis()
        
        return fig
