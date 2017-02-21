#-
# Copyright (c) 2016-2017 Alfredo Mazzinghi
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

from collections import defaultdict

from matplotlib import pyplot as plt

from cheriplot.utils import ProgressPrinter
from cheriplot.core.vmmap import VMMap
from cheriplot.core.provenance import CheriCapPerm
from cheriplot.core.addrspace_axes import Range

from cheriplot.plot.patch import OmitRangeSetBuilder
from cheriplot.plot.provenance.vmmap import VMMapPatchBuilder
from cheriplot.plot.provenance.provenance_plot import PointerProvenancePlot

logger = logging.getLogger(__name__)

class PointOmitBuilder(OmitRangeSetBuilder):
    """
    The omit builder generates the ranges of address-space in
    which we are not interested.

    XXX: move this to plot.patch because most of the code is duplicated
    """

    def __init__(self):
        super().__init__()

        self.split_size = 2 * self.size_limit
        """
        Capability length threshold to trigger the omission of
        the middle portion of the capability range.
        """

    def inspect(self, point):
        """
        Build a 64-byte range around each point that is not omitted
        """
        point_range = Range(point - 2**5, point + 2**5,
                            Range.T_KEEP)
        self._update_regions(point_range)

    def inspect_range(self, node_range):
        if node_range.size > self.split_size:
            l_range = Range(node_range.start,
                            node_range.start + self.size_limit,
                            Range.T_KEEP)
            r_range = Range(node_range.end - self.size_limit,
                            node_range.end,
                            Range.T_KEEP)
            self._update_regions(l_range)
            self._update_regions(r_range)
        else:
            node_range.rtype = Range.T_KEEP
            node_range = Range(node_range.start, node_range.end, Range.T_KEEP)
            self._update_regions(node_range)


class ExecCapLoadStoreScatterPlot(PointerProvenancePlot):
    """
    Show in the address space axes the locations where
    executable capabilities are stored and loaded
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.vmmap = None
        """VMMap object representing the process memory map"""

        self.store_addr_map = {}
        """Map access_time->access_address for the capabilities to plot"""

        self.n_points = 0
        """Number of points in the store_addr_map"""

        self.vmmap_patch_builder = VMMapPatchBuilder(self.ax)
        """Helper object that builds patches to display VM map regions."""

        self.range_builder = PointOmitBuilder()

    def init_axes(self):
        """
        Build the figure and axes for the plot
        """
        fig = plt.figure(figsize=(15,10))
        ax = fig.add_axes([0.05, 0.15, 0.9, 0.80,],
                          projection="custom_addrspace")
        return (fig, ax)

    def set_vmmap(self, mapfile):
        """
        Use tha CSV file for the memory mapping, later we will
        switch to a dynamic vmmap extracted from the trace.
        """
        self.vmmap = VMMap(mapfile)

    def build_dataset(self):
        """
        For each capability with exec permissions, merge its
        store map to a common dictionary.
        The common dictionary is then used for the plot.
        """
        super().build_dataset()
        progress = ProgressPrinter(self.dataset.num_vertices(),
                                   desc="Extract executable cap memory locations")
        for node in self.dataset.vertices():
            node_data = self.dataset.vp.data[node]
            if node_data.cap.has_perm(CheriCapPerm.EXEC):
                for addr in node_data.address.values():
                    self.range_builder.inspect(addr)
                self.store_addr_map.update(node_data.address)
            progress.advance()
        progress.finish()

    def plot(self):
        """
        Build the scatter plot from the provenance graph.
        """

        # get all the points in a numpy array
        addrs = np.fromiter(iter(self.store_addr_map.values()), dtype=float)
        cycles = np.fromiter(iter(self.store_addr_map.keys()), dtype=float)
        points = np.vstack([addrs, cycles]).transpose()
        self.ax.plot(points[:,0], points[:,1], 'o', markersize=2)

        if self.vmmap:
            for vme in self.vmmap:
                self.vmmap_patch_builder.inspect(vme)
                self.range_builder.inspect_range(Range(vme.start, vme.end))
            for collection in self.vmmap_patch_builder.get_patches():
                self.ax.add_collection(collection)
            for label in self.vmmap_patch_builder.get_annotations():
                self.ax.add_artist(label)

            # manually set xticks based on the vmmap
            start_ticks = [vme.start for vme in self.vmmap]
            end_ticks = [vme.end for vme in self.vmmap]
            ticks = sorted(set(start_ticks + end_ticks))
            self.ax.set_xticks(ticks)

        self.ax.set_omit_ranges(self.range_builder.get_omit_ranges())
