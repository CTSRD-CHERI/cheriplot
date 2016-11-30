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
from matplotlib import pyplot as plt

from cheriplot.utils import ProgressPrinter

from cheriplot.plot.provenance.provenance_plot import PointerProvenancePlot

logger = logging.getLogger(__name__)


class PointerDensityPlot(PointerProvenancePlot):
    """
    Show the amount of allocations vs address-space with page granularity. 
    The single allocation is not given in terms of single dot but 
    is cumulative over the address that it occupies.
    """

    def __init__(self, tracefile, cache=False):
        super(PointerDensityPlot, self).__init__(tracefile, cache)

    def _get_plot_file(self):
        return self.tracefile + ".pgf"

    def plot(self):
        graph_size = self.dataset.num_vertices()
        # (addr, num_allocations)
        addresses = {}
        page_use = {}
        page_size = 2**12
        
        # address reuse metric
        # num_allocations vs address
        # linearly and in 4k chunks
        tree_progress = ProgressPrinter(graph_size, desc="Fetching addresses")
        for node in self.dataset.vertices():
            data = self.dataset.vp.data[node]
            for time, addr in data.address.items():                
                try:                
                    addresses[addr] += 1
                except KeyError:
                    addresses[addr] = 1
                page_addr = addr & (~0xfff)
                try:
                    page_use[page_addr] += 1
                except KeyError:
                    page_use[page_addr] = 1
            tree_progress.advance()
        tree_progress.finish()

        # time vs address
        # address working set over time

        fig = plt.figure(figsize=(15,10))
        ax = fig.add_axes([0.05, 0.15, 0.9, 0.80,], projection="custom_addrspace")
        ax.set_ylabel("Number of pointers stored")
        ax.set_xlabel("Virtual address")
        ax.set_yscale("log")
        # ax.set_ylim(0, )
        data = np.array(sorted(page_use.items(), key=lambda i: i[0]))
        # ignore empty address-space chunks
        prev_addr = data[0]
        omit_ranges = []
        first_tick = data[0][0]
        ticks = [first_tick]
        labels = ["0x%x" % int(first_tick)]
        for addr in data:
            logger.debug("DATA 0x%x (%d)", int(addr[0]), addr[0])
            if addr[0] - prev_addr[0] > 2**12:
                omit_ranges.append([prev_addr[0] + page_size, addr[0]])
                ticks.append(addr[0])
                labels.append("0x%x" % int(addr[0]))
            prev_addr = addr
        ax.set_omit_ranges(omit_ranges)
        # ax.set_xticks(ticks)
        # ax.set_xticklabels(labels, rotation="vertical")
        ax.set_xlim(first_tick - page_size, data[-1][0] + page_size)
        ax.vlines(data[:,0], [1]*len(data[:,0]), data[:,1], color="b")
        
        fig.savefig(self._get_plot_file())
        return fig
