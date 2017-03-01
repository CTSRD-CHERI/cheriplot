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
import pandas as pd
import logging
import os

from matplotlib import pyplot as plt
from matplotlib import lines
from scipy import stats

from cheriplot.utils import ProgressPrinter
from cheriplot.plot.provenance.provenance_plot import PointerProvenancePlot

logger = logging.getLogger(__name__)

class PointerSizeCdfPlot(PointerProvenancePlot):
    """
    Plot a Cumulative Distribution Function of the number of
    instantiations of capability pointer vs. the capability
    lengths.
    """

    def __init__(self, trace, *args, **kwargs):
        self.ax = kwargs.pop("axes", None)
        self.fig = kwargs.pop("fig", None)
        super().__init__(trace, *args, **kwargs)

        self.ptr_sizes = []

    def init_axes(self):
        if self.ax and self.fig:
            return (self.fig, self.ax)
        else:
            fig = plt.figure(figsize=(15,10))
            ax = fig.add_axes([0.05, 0.15, 0.9, 0.80,])
            return (fig, ax)

    def build_dataset(self):
        super().build_dataset()
        logger.info("Fetching cap lengths...")
        for v in self.dataset.vertices():
            vdata = self.dataset.vp.data[v]
            self.ptr_sizes.append(vdata.cap.length)
        logger.info("Done")

    def plot(self):
        """
        Plot a CDF number-of-pointers vs size of pointers
        """
        self.ax.set_ylabel("Proportion of total capability pointers")
        self.ax.set_xlabel("Capability size (bytes)")
        self.ax.set_title("CDF of the size of capability pointers")
        self.ax.set_xscale("log", basex=2)

        # since the plot is normalized on the y there is
        # no problem on the scale
        size_freq = stats.itemfreq(self.ptr_sizes)
        logger.debug(size_freq)
        size_pdf = size_freq[:,1] / len(self.ptr_sizes)
        y = np.concatenate(([0, 0], np.cumsum(size_pdf)))
        x = np.concatenate(([0, size_freq[0,0]], size_freq[:,0]))
        plot_lines = self.ax.plot(x, y)

        prev_legend = self.ax.get_legend()
        legend_handles = prev_legend.get_lines() if prev_legend else []
        label = os.path.basename(self.tracefile)
        label,_ = os.path.splitext(label)
        handle = lines.Line2D([], [], color=plot_lines[0].get_color(),
                              label=label)
        legend_handles.append(handle)
        self.ax.legend(handles=legend_handles, loc="lower right")

        plt.savefig(self._get_plot_file())


class MultiPointerSizeCdfPlot:

    def __init__(self, traces, *args, **kwargs):
        self.traces = traces
        self.plots = []
        # first plot created manually
        plot = PointerSizeCdfPlot(traces[0], *args, **kwargs)
        fig = plot.fig
        ax = plot.ax
        self.plots.append(plot)
        for trace in traces[1:]:
            plot = PointerSizeCdfPlot(trace, *args, axes=ax, fig=fig, **kwargs)
            self.plots.append(plot)

    def plot(self):
        for subplot in self.plots:
            subplot.build_dataset()
            subplot.plot()

    def show(self):
        self.plot()
        plt.show()
