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

import numpy as np
import pandas as pd
import logging
import os

from scipy import stats
from matplotlib import pyplot as plt
from matplotlib.patches import Patch
from matplotlib.lines import Line2D
from matplotlib.transforms import Bbox
from matplotlib.font_manager import FontProperties

from cheriplot.core import (
    ProgressTimer, ProgressPrinter, ExternalLegendTopPlotBuilder,
    BasePlotBuilder, PatchBuilder, LabelManager, AutoText, TaskDriver,
    Option, Argument)
from cheriplot.provenance.parser import PointerProvenanceParser
from cheriplot.provenance.transforms import *
from cheriplot.provenance.plot import VMMapPlotDriver

logger = logging.getLogger(__name__)

class CapSizeHistogram:
    """
    Base class for the histogram data structure building strategy
    """

    def __init__(self, provenance_graph, vmmap):
        self.graph = provenance_graph
        """The provenance graph"""

        self.vmmap = vmmap
        """VMMap object representing the process memory map."""

        self.n_bins = [0, 10, 20, 21, 22, 23, 64]
        """Bin edges for capability size, notice that the size is log2."""

        self.norm_histogram = pd.DataFrame(columns=self.n_bins[1:])
        """List of normalized histograms for each vmmap entry."""

        self.abs_histogram = pd.DataFrame(columns=self.n_bins[1:])
        """List of histograms for each vmmap entry."""

        self._build_histogram()

    def _build_histogram(self):
        hist_data = self._build_histogram_input()
        for vm_entry, data in zip(self.vmmap, hist_data):
            if len(data) == 0:
                continue
            # the bin size is logarithmic
            data = np.log2(data)
            h, b = np.histogram(data, bins=self.n_bins)
            # append histogram to the dataframes
            self.abs_histogram.loc[vm_entry] = h
            self.norm_histogram.loc[vm_entry] = h / np.sum(h)

    def _build_histogram_input(self):
        """
        Build the input data structure containing a list of data to use
        for the histogram for each entry in the vmmap entry.
        """
        return None


class CapSizeDerefHistogram(CapSizeHistogram):
    """
    Histogram that takes into account capabilities at dereference time.
    The address space is split in the same was as in
    :class:`CapSizeCreationPlot` but the each capability is assigned to
    a memory-mapped region based on its offset when it is dereferenced.
    Note that there is an amount of overcounting due to locations that
    are heavily accessed.
    """

    def _build_histogram_input(self):
        # indexes in the vmmap and in the norm_histograms are
        # the same.
        vm_entries = list(self.vmmap)
        # hist_data = [[] for _ in range(len(vm_entries))]
        hist_data = np.empty(len(vm_entries), dtype=object)
        hist_data[:] = [[] for _ in range(len(vm_entries))]

        progress = ProgressPrinter(self.graph.num_vertices(),
                                   desc="Sorting capability references")
        # the loop checks, for each vertex in the graph, where it is
        # dereferenced and adds the dereferenced capability size to every
        # histogram-input-data relative to the VM map entry where the
        # capability is dereferenced
        limits = np.array([(e.start, e.end) for e in vm_entries])
        for node in self.graph.vertices():
            data = self.graph.vp.data[node]
            addr = np.array(data.deref["addr"])
            hist_idx = map(
                lambda lim: np.logical_and(addr >= lim[0], addr <= lim[1]),
                limits)
            for idx, match in enumerate(hist_idx):
                hist_data[idx].extend([data.cap.length] * len(addr[match]))
            progress.advance()
        progress.finish()
        return hist_data


class CapSizeBoundHistogram(CapSizeHistogram):
    """
    Histogram that takes into account capabilities at creation time.
    The address space is split in chunks according to the VM map of the
    process. For each chunk, the set of capabilities that can be
    dereferenced in the chunk is computed. Note that the same capability may
    be counted in multiple chunks if it spans multiple VM map entries (eg DDC)
    From each set an histogram is generated and the bin count is used to produce
    the bar chart.
    """

    def _build_histogram_input(self):
        # indexes in the vmmap and in the norm_histograms are
        # the same.
        vm_entries = list(self.vmmap)
        hist_data = np.empty(len(vm_entries), dtype=object)
        hist_data[:] = [[] for _ in range(len(vm_entries))]
        progress = ProgressPrinter(self.graph.num_vertices(),
                                   desc="Sorting capability references")
        # the loop checks, for each vertex in the graph, whether the
        # capability can be dereferenced in a VM map entry,
        # if so it adds the capability size to the histogram-input-data
        # relative to the VM map entry.
        limits = np.array([(e.start, e.end) for e in vm_entries])
        for node in self.graph.vertices():
            data = self.graph.vp.data[node]
            match = np.logical_and(data.cap.base <= limits[:,1],
                                   data.cap.bound >= limits[:,0])
            for in_data in hist_data[match]:
                in_data.append(data.cap.length)
            progress.advance()
        progress.finish()
        return hist_data


class HistogramPatchBuilder(PatchBuilder):
    """
    Process an histogram to produce the bar plot
    """

    def __init__(self, figure, **kwargs):
        super().__init__(**kwargs)

        self.fig = figure

        self.label_managers = []
        """Manage vertical labels for each vertical column"""

        self.colormap = []
        """Set of colors to use."""

        self.hist = None
        """Histogram model"""

    def inspect(self, hist):
        """Prepare the data for plotting on the axes."""
        assert self.hist == None, \
            "This patch builder can process only a single histogram"
        self.hist = hist
        self.colormap = [plt.cm.Dark2(i) for i in
                         np.linspace(0, 0.9, len(hist.n_bins))]

    def _get_positions(self):
        """X locations of the histogram bars."""
        step = 2
        return range(1, step * self.hist.norm_histogram.shape[0] + 1, step)

    def get_legend(self):
        legend_handles = []
        bin_start = 0
        # skip the first column that holds the vmmap entry for the row
        # labels are set to "2^<bin_stat_size>-2^<bin_end_size>"
        for idx,bin_limit in enumerate(self.hist.norm_histogram.columns):
            label = "2^%d-2^%d" % (bin_start, bin_limit)
            bin_start = bin_limit
            handle = Patch(color=self.colormap[idx], label=label)
            legend_handles.append(handle)
        return legend_handles

    def get_bbox(self):
        positions = list(self._get_positions())
        return Bbox.from_extents(0, 0, positions[-1] + 1, 1.1)

    def get_xticks(self):
        return self._get_positions()

    def get_xlabels(self):
        ticklabels = []
        for entry in self.hist.norm_histogram.index:
            if entry.path:
                label_name = os.path.basename(entry.path)
            else:
                label_name = "0x%x" % entry.start
            ticklabel = "(%s) %s" % (entry.perms, label_name)
            ticklabels.append(ticklabel)
        return ticklabels

    def get_yticks(self):
        return [0, 1]

    def get_ylabels(self):
        return ["0", "100"]

    def get_patches(self, axes):
        norm_hist = self.hist.norm_histogram
        abs_hist = self.hist.abs_histogram
        step = 2
        positions = range(1, step * norm_hist.shape[0] + 1, step)
        # init label managers and legend list
        for row in range(norm_hist.shape[0]):
            mgr = LabelManager(direction="vertical")
            mgr.set_limits(0, np.inf)
            self.label_managers.append(mgr)
        # build the bars in the plot
        bottom = np.zeros(norm_hist.shape[0])
        for bin_idx, bin_limit in enumerate(norm_hist.columns):
            color = self.colormap[bin_idx]
            bar_slices = axes.bar(positions, norm_hist[bin_limit],
                                     bottom=bottom, color=color)
            bottom = bottom + norm_hist[bin_limit]
            # create text labels
            for bar_idx,hist_idx in enumerate(norm_hist.index):
                bar = bar_slices[bar_idx]
                abs_bin = abs_hist.at[hist_idx, bin_limit]
                # write the absolute count count at the left of each bar
                text_x = bar.get_x() - bar.get_width() / 2
                text_y = bar.get_y() + bar.get_height() / 2
                txt = AutoText(text_x, text_y, " %d " % abs_bin,
                               ha="center", va="center",
                               rotation="horizontal",
                               label_manager=self.label_managers[bar_idx])
                axes.add_artist(txt)


class PtrSizePlotDriver(VMMapPlotDriver, ExternalLegendTopPlotBuilder):

    histogram_builder_class = None

    def _get_xlabels_kwargs(self):
        kw = super()._get_xlabels_kwargs()
        kw["rotation"] = "vertical"
        return kw

    def run(self):
        self._vmmap_parser.parse()
        vmmap = self._vmmap_parser.get_model()
        hist = self.histogram_builder_class(self._provenance_graph, vmmap)
        self.register_patch_builder([hist], HistogramPatchBuilder(self.fig))
        self.process(out_file=self.config.outfile)


class PtrSizeDerefDriver(PtrSizePlotDriver):

    title = "Capability dereference size by memory region"
    x_label = ""
    y_label = ""
    histogram_builder_class = CapSizeDerefHistogram


class PtrSizeBoundDriver(PtrSizePlotDriver):

    title = "Capability bound size by memory region"
    x_label = ""
    y_label = ""
    histogram_builder_class = CapSizeBoundHistogram


class PtrBoundCdf:
    """
    Model of the CDF that the PatchBuilder can draw
    """

    def __init__(self, pgm):
        self.graph = pgm.graph
        """The provenance graph."""

        self.size_cdf = None
        """2xn numpy array containing [sizes, frequency]"""

        self.name = pgm.name
        """The CDF name"""

        self._build_cdf()

    def _build_cdf(self):
        ptr_sizes = []
        with ProgressTimer("Build CDF"):
            for v in self.graph.vertices():
                vdata = self.graph.vp.data[v]
                ptr_sizes.append(vdata.cap.length)
            size_freq = stats.itemfreq(ptr_sizes)
            logger.debug(size_freq)
            size_pdf = size_freq[:,1] / len(ptr_sizes)
            y = np.concatenate(([0, 0], np.cumsum(size_pdf)))
            x = np.concatenate(([0, size_freq[0,0]], size_freq[:,0]))
            self.size_cdf = np.column_stack((x,y))


class CdfPatchBuilder(PatchBuilder):
    """
    Plot a Cumulative Distribution Function of the number of
    instantiations of capability pointer vs. the capability
    lengths.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.cdf = []
        """Set of cdf to draw"""

        self.colormap = None
        """Colors to use for the lines"""

        self._bbox = Bbox.from_extents(1, 0, 0, 1)
        """Bbox of the plot"""

    def inspect(self, cdf):
        self.cdf.append(cdf)
        self._bbox.x1 = max(self._bbox.xmax, max(cdf.size_cdf[:,0]))

    def get_patches(self, axes):
        self.colormap = [plt.cm.Dark2(i) for i in
                         np.linspace(0, 0.9, len(self.cdf))]
        for cdf, color in zip(self.cdf, self.colormap):
            axes.plot(cdf.size_cdf[:,0], cdf.size_cdf[:,1], color=color)

    def get_legend(self):
        handles = []
        for cdf, color in zip(self.cdf, self.colormap):
            handle = Line2D([], [], color=color,
                            label=cdf.name)
            handles.append(handle)
        return handles

    def get_bbox(self):
        return self._bbox


class PtrSizeCdfDriver(TaskDriver, BasePlotBuilder):

    title = "CDF of the size of capabilities created"
    x_label = "Size"
    y_label = "Proportion of the total number of capabilities"

    extra_traces = Argument(help="Additional traces", nargs="*")
    outfile = Option(help="Output file", default=None)
    publish = Option(help="Adjust plot for publication", action="store_true")

    def _get_savefig_kwargs(self):
        kw = super()._get_figure_kwargs()
        kw["dpi"] = 300
        return kw

    def _get_axes_rect(self):
        if self.config.publish:
            return [0.1, 0.15, 0.85, 0.8]
        return super()._get_axes_rect()

    def _get_legend_kwargs(self):
        kw = super()._get_legend_kwargs()
        kw["loc"] = "lower right"
        return kw

    def __init__(self, pgm, **kwargs):
        super().__init__(**kwargs)
        self.pgm = pgm
        if self.config.publish:
            self._style["font"] = FontProperties(size=25)

    def make_plot(self):
        super().make_plot()
        self.ax.set_xscale("log", basex=2)

    def run(self):
        extra_pgm = []
        for path in self.config.extra_traces:
            parser = PointerProvenanceParser(cache=True, trace_path=path)
            parser.parse()
            pgm = parser.get_model()
            flat_transform(pgm, [MaskNullAndKernelVertices(pgm)])
            flat_transform(pgm, [MergeCFromPtr(pgm)])
            flat_transform(pgm, [MaskCFromPtr(pgm)])
            extra_pgm.append(pgm)
        datasets = [PtrBoundCdf(pgm) for pgm in extra_pgm]
        datasets += [PtrBoundCdf(self.pgm)]
        self.register_patch_builder(datasets, CdfPatchBuilder())
        self.process(out_file=self.config.outfile)
