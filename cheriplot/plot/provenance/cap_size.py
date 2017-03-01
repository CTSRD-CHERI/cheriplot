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
import pandas as pd
import logging
import os

from itertools import chain

from matplotlib import pyplot as plt
from matplotlib import text
from matplotlib import patches

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

        self.n_bins = [0, 10, 20, 21, 22, 23, 64]
        """Bin edges for capability size, notice that the size is log2."""

        self.norm_histogram = pd.DataFrame(columns=self.n_bins[1:])
        """List of normalized histograms for each vmmap entry."""

        self.abs_histogram = pd.DataFrame(columns=self.n_bins[1:])
        """List of histograms for each vmmap entry."""

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

    def build_legend(self, handles):
        self.ax.legend(handles=handles, bbox_to_anchor=(0, 1.02, 1, 0.102),
                       loc=3, ncol=9, mode="expand", borderaxespad=0)

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
        Make the vertical bar plot using the histogram data
        """
        step = 2
        positions = range(1, step*self.norm_histogram.shape[0] + 1, step)
        # init label managers and legend list
        for row in range(self.norm_histogram.shape[0]):
            self.label_managers.append(LabelManager(direction="vertical"))
            # self.label_managers[-1].constraint = (0, np.inf)

        legend_handles = []
        bin_start = 0
        # skip the first column that holds the vmmap entry for the row
        # labels are set to "2^<bin_stat_size>-2^<bin_end_size>"
        for idx,bin_limit in enumerate(self.norm_histogram.columns):
            label = "2^%d-2^%d" % (bin_start, bin_limit)
            bin_start = bin_limit
            handle = patches.Patch(color=self.colormap[idx], label=label)
            legend_handles.append(handle)
        self.build_legend(legend_handles)

        self.ax.set_xticks(np.array(positions))
        ticklabels = []
        for entry in self.norm_histogram.index:
            if entry.path:
                label_name = os.path.basename(entry.path)
            else:
                label_name = "0x%x" % entry.start
            ticklabel = "(%s) %s" % (entry.perms, label_name)
            ticklabels.append(ticklabel)
        self.ax.set_xticklabels(ticklabels, rotation="vertical")
        self.ax.set_yticks([0, 1])
        self.ax.set_yticklabels(["0", "100"])
        self.ax.set_xlim(0, positions[-1] + 1)
        self.ax.set_ylim(0, 1.1)
        self.ax.set_xlabel("Mapped memory region")

        # build the bars in the plot
        bottom = np.zeros(self.norm_histogram.shape[0])
        for bin_idx, bin_limit in enumerate(self.norm_histogram.columns):
            color = self.colormap[bin_idx]
            bar_slices = self.ax.bar(positions, self.norm_histogram[bin_limit],
                                     bottom=bottom, color=color)
            bottom = bottom + self.norm_histogram[bin_limit]
            # create text labels
            for bar_idx,hist_idx in enumerate(self.norm_histogram.index):
                bar = bar_slices[bar_idx]
                abs_bin = self.abs_histogram.at[hist_idx, bin_limit]
                # write the absolute count count at the left of each bar
                text_x = bar.get_x() - bar.get_width() / 2
                text_y = bar.get_y() + bar.get_height() / 2
                txt = self.ax.text(text_x, text_y, " %d " % abs_bin,
                                   ha="center", va="center",
                                   rotation="horizontal")
                self.label_managers[bar_idx].labels.append(txt)

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
        vm_entries = list(self.vmmap)
        vm_ranges = [Range(v.start, v.end) for v in self.vmmap]
        hist_data = [[] for _ in range(len(vm_entries))]

        progress = ProgressPrinter(self.dataset.num_vertices(),
                                   desc="Sorting capability references")
        logger.debug("Vm ranges %s", vm_ranges)
        for node in self.dataset.vertices():
            data = self.dataset.vp.data[node]
            for idx, r in enumerate(vm_ranges):
                if Range(data.cap.base, data.cap.bound) in r:
                    hist_data[idx].append(data.cap.length)
            progress.advance()
        progress.finish()

        for vm_entry,data in zip(vm_entries, hist_data):
            logger.debug("hist entry len %d", len(data))
            if len(data) == 0:
                continue
            # the bin size is logarithmic
            data = np.log2(data)
            h, b = np.histogram(data, bins=self.n_bins)
            # append histograms to the dataframe
            # self.hist_sources.append(vm_entry)
            # new_index = len(self.abs_histogram.index)
            self.abs_histogram.loc[vm_entry] = h
            self.norm_histogram.loc[vm_entry] = h / np.sum(h)

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
        vm_entries = list(self.vmmap)
        vm_ranges = [Range(v.start, v.end) for v in self.vmmap]
        hist_data = [[] for _ in range(len(vm_ranges))]

        progress = ProgressPrinter(self.dataset.num_vertices(),
                                   desc="Sorting capability references")
        for node in self.dataset.vertices():
            data = self.dataset.vp.data[node]
            # iterate over every dereference of the node
            for addr in chain(data.deref["load"], data.deref["store"]):
                # check in which vm-entry the address is
                for idx, r in enumerate(vm_ranges):
                    if addr in r:
                        hist_data[idx].append(data.cap.length)
                        break
            progress.advance()
        progress.finish()

        for vm_entry,data in zip(vm_entries, hist_data):
            if len(data) == 0:
                continue
            # the bin size is logarithmic
            data = np.log2(data)
            h, b = np.histogram(data, bins=self.n_bins)
            # append histogram to the dataframes
            # self.hist_sources.append(vm_entry)
            # new_index = len(self.abs_histogram.index)
            self.abs_histogram.loc[vm_entry] = h
            self.norm_histogram.loc[vm_entry] = h / np.sum(h)

    def plot(self):
        self.ax.set_ylabel("Percentage of dereferenced capabilities by size")
        return super().plot()
