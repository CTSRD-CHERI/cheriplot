#-
# Copyright (c) 2017 Alfredo Mazzinghi
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

from itertools import chain

from matplotlib import pyplot as plt
from matplotlib import text

from cheriplot.utils import ProgressPrinter
from cheriplot.core.addrspace_axes import Range
from cheriplot.core.label_manager import LabelManager
from cheriplot.core.vmmap import VMMap
from cheriplot.plot.provenance.provenance_plot import PointerProvenancePlot

logger = logging.getLogger(__name__)

class CapSizeHistogramPlot(PointerProvenancePlot):
    """
    Vertical bar plot showing a bar for each mapped region of
    memory in the executable.
    Each vertical bar is subdivided in bins showing the amount
    of capabilities of size X referencing something in that mapped region.
    The vertical bars have fixed height, representing the 100% of the pointers
    in that region, the size of the bins is therefore the percentage of pointers
    to that region of size X.

    Variants:
    - remove roots, only keep globals (cfromptr)
    """

    def __init__(self, *args, **kwargs):
        super(CapSizeHistogramPlot, self).__init__(*args, **kwargs)

        self.vmmap = None
        """VMMap object representing the process memory map."""

        self.norm_histograms = []
        """List of normalized histograms for each vmmap entry."""

        self.abs_histograms = []
        """List of histograms for each vmmap entry."""

        self.n_bins = [0, 10, 20, 21, 22, 23, 64]
        """Bin edges for capability size, notice that the size is log2."""

        self.label_managers = []
        """Manage vertical labels for each vertical column"""

        self.colormap = [plt.cm.Dark2(i) for i in
                         np.linspace(0, 0.9, len(self.n_bins))]
        """Set of colors to use."""

    def init_axes(self):
        """
        Build the figure and axes for the plot
        """
        fig = plt.figure(figsize=(16,12))
        ax = fig.add_axes([0.05, 0.15, 0.9, 0.80,])
        return (fig, ax)

    def set_vmmap(self, mapfile):
        """
        Use tha CSV file for the memory mapping, later we will
        switch to a dynamic vmmap extracted from the trace.
        """
        self.vmmap = VMMap(mapfile)

    def on_draw(self, evt):
        """
        Adjust labels at the side of the bars so they do not overlap.
        """
        for mgr in self.label_managers:
            mgr.update_label_position(evt.renderer)

    def plot(self):
        """
        Make the vertical bar plot based on the processed dataset
        """
        histogram_data = np.array(self.norm_histograms)

        bottom = np.zeros(len(self.norm_histograms))
        positions = range(1, 2*len(self.norm_histograms) + 1, 2)
        # init label managers and legend list
        legend_handles = []
        legend_labels = []
        for entry in self.vmmap:
            self.label_managers.append(LabelManager(direction="vertical"))
            # self.label_managers[-1].constraint = (0, np.inf)

        for bin_idx, bin_limit in enumerate(self.n_bins[1:]):
            # color = np.random.rand(3,1)
            color = self.colormap[bin_idx]
            bar_slices = self.ax.bar(positions, histogram_data[:,bin_idx],
                                     bottom=bottom, color=color)
            abs_hist_iter = zip(bar_slices.patches, self.abs_histograms)
            for bar_idx, (bar, abs_hist) in enumerate(abs_hist_iter):
                # write the absolute count count at the left of each bar
                text_x = bar.get_x() - bar.get_width() / 2
                text_y = bar.get_y() + bar.get_height() / 2
                txt = self.ax.text(text_x, text_y, " %d " % abs_hist[bin_idx],
                                   ha="center", va="center",
                                   rotation="vertical")
                self.label_managers[bar_idx].labels.append(txt)
            legend_handles.append(bar_slices[0])
            legend_labels.append("Size: 2^%d" % bin_limit)
            bottom = bottom + histogram_data[:,bin_idx]

        # place vmmap label for each bar
        ticklabels = []
        for idx, entry in enumerate(self.vmmap):
            path = str(entry.path).split("/")[-1] if str(entry.path) else ""
            # remove suffix extension part
            path = path[0:path.find(".")]
            label = "%s (%s)" % (path, entry.perms)
            ticklabels.append(label)
        self.ax.set_xticks(np.array(positions) + 0.5)
        self.ax.set_xticklabels(ticklabels, rotation="vertical")
        self.ax.set_xlim(0, positions[-1] + 1)
        self.ax.set_ylim(0, 1.5)
        self.ax.legend(legend_handles, legend_labels)
        self.ax.set_xlabel("Mapped memory region")

        self.fig.canvas.mpl_connect("draw_event", self.on_draw)

        logger.debug("Plot build completed")
        plt.savefig(self._get_plot_file())


class CapSizeCreationPlot(CapSizeHistogramPlot):
    """
    Histogram plot that takes into account capabilities at creation time.
    The address space is split in chunks according to the VM map of the
    process. For each chunk, the set of capabilities that can be
    dereferenced in the chunk is computed. Note that the same capability may
    be counted in multiple chunks if it spans multiple VM map entries (eg DDC)
    From each set an histogram is generated and the bin count is used to produce
    the bar chart.
    """

    def build_dataset(self):
        """Process the provenance graph to extract histogram data."""
        super(CapSizeCreationPlot, self).build_dataset()

        # indexes in the vmmap and in the norm_histograms are
        # the same.
        vm_ranges = [Range(v.start, v.end) for v in self.vmmap]

        histogram_input = [[] for _ in range(len(vm_ranges))]

        progress = ProgressPrinter(self.dataset.num_vertices(),
                                   desc="Sorting capability references")
        logger.debug("Vm ranges %s", vm_ranges)
        for node in self.dataset.vertices():
            data = self.dataset.vp.data[node]

            for idx, r in enumerate(vm_ranges):
                if Range(data.cap.base, data.cap.bound) in r:
                    histogram_input[idx].append(data.cap.length)
            progress.advance()
        progress.finish()

        for data in histogram_input:
            logger.debug("hist entry len %d", len(data))
            data = np.array(data) + 1
            data = np.log2(data)
            h, b = np.histogram(data, bins=self.n_bins)
            # append normalized histogram to the list
            self.abs_histograms.append(h)
            self.norm_histograms.append(h / np.sum(h))

    def plot(self):
        self.ax.set_ylabel("Percentage of dereferenceable capabilities by size")
        return super().plot()


class CapSizeDerefPlot(CapSizeHistogramPlot):
    """
    Histogram plot that takes into account capabilities at dereference time.
    The address space is split in the same was as in
    :class:`CapSizeCreationPlot` but the each capability is assigned to
    a memory-mapped region based on its offset when it is dereferenced.
    Note that there is an amount of overcounting due to locations that
    are heavily accessed.
    """

    def build_dataset(self):
        """Process the provenance graph to extract histogram data."""
        super(CapSizeDerefPlot, self).build_dataset()

        # indexes in the vmmap and in the norm_histograms are
        # the same.
        vm_ranges = [Range(v.start, v.end) for v in self.vmmap]

        histogram_input = [[] for _ in range(len(vm_ranges))]

        progress = ProgressPrinter(self.dataset.num_vertices(),
                                   desc="Sorting capability references")
        for node in self.dataset.vertices():
            data = self.dataset.vp.data[node]
            # iterate over every dereference of the node
            for addr in chain(data.deref["load"], data.deref["store"]):
                # check in which vm-entry the address is
                for idx, r in enumerate(vm_ranges):
                    if addr in r:
                        histogram_input[idx].append(data.cap.length)
            progress.advance()
        progress.finish()

        for data in histogram_input:
            data = np.array(data) + 1
            data = np.log2(data)
            h, b = np.histogram(data, bins=self.n_bins)
            total_addrs = np.sum(h)
            self.abs_histograms.append(h)
            if total_addrs == 0:
                # no dereferences in this region
                self.norm_histograms.append(h)
            else:
                # append normalized histogram to the list
                self.norm_histograms.append(h / total_addrs)

    def plot(self):
        self.ax.set_ylabel("Percentage of dereferenced capabilities by size")
        return super().plot()


class CapSizeCallPlot(CapSizeHistogramPlot):
    """
    Histogram plot that takes into account capabilities that are called.
    Same as :class:`CapSizeCreationPlot` but the capabilities are
    taken at call-time.
    """

    def build_dataset(self):
        """Process the provenance graph to extract histogram data."""
        super(CapSizeCallPlot, self).build_dataset()

        # indexes in the vmmap and in the norm_histograms are
        # the same.
        vm_ranges = [Range(v.start, v.end) for v in self.vmmap]

        histogram_input = [[] for _ in range(len(vm_ranges))]

        progress = ProgressPrinter(self.dataset.num_vertices(),
                                   desc="Sorting capability references")
        for node in self.dataset.vertices():
            data = self.dataset.vp.data[node]
            # iterate over every dereference of the node
            for addr in data.deref["call"]:
                # check in which vm-entry the address is
                for idx, r in enumerate(vm_ranges):
                    if addr in r:
                        histogram_input[idx].append(data.cap.length)
            progress.advance()
        progress.finish()

        for data in histogram_input:
            data = np.array(data) + 1
            data = np.log2(data)
            h, b = np.histogram(data, bins=self.n_bins)
            total_addrs = np.sum(h)
            self.abs_histograms.append(h)
            if total_addrs == 0:
                # no dereferences in this region
                self.norm_histograms.append(h)
            else:
                # append normalized histogram to the list
                self.norm_histograms.append(h / total_addrs)
