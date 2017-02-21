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

from matplotlib import pyplot as plt
from graph_tool.all import *

from cheriplot.plot.plot_base import Plot
from cheriplot.dbg import CallGraphTraceParser
from cheriplot.graph.call_graph import CallGraphAddSymbols

logger = logging.getLogger(__name__)

class CallGraphPlot(Plot):
    """
    Plot the call graph of a trace from a specified point backwards.
    This does not follow the conventions of other plots as I am planning
    a refactoring ro the plot drivers
    """
    
    def __init__(self, trace, *args, **kwargs):
        super().__init__(trace, *args, **kwargs)

        self.bt_start = None
        self.bt_end = None
        self.bt_depth = None

        self.sym_files = []
        self.sym_vmmap = None

    def _get_cache_file(self):
        return self.tracefile + ".cache"

    def _get_plot_file(self):
        if self.plot_file:
            return self.plot_file
        classname = self.__class__.__name__.lower()
        return "%s_%s.svg" % (self.tracefile, classname)

    def init_axes(self):
        plt.switch_backend("cairo")
        fig = plt.figure(figsize=(15,10))
        ax = fig.add_axes([0.05, 0.15, 0.9, 0.80,])
        return (fig, ax)

    def build_dataset(self):
        super().build_dataset()

        self.parser = CallGraphTraceParser(self.tracefile, self.caching,
                                           depth=self.bt_depth)
        self.parser.parse(self.bt_start, self.bt_end)
        add_symbols = CallGraphAddSymbols(self.parser.cgm, self.sym_files,
                                          self.sym_vmmap)
        self.parser.cgm.bfs_transform(add_symbols)

    def plot(self):
        graph = self.parser.cgm.graph
        # layout = arf_layout(graph, max_iter=0, d=5)
        layout = sfdp_layout(graph)
        pen_width = prop_to_size(self.parser.cgm.backtrace, mi=0.5, ma=5)
        label = graph.new_vertex_property("string")
        map_property_values(graph.vp.addr, label, lambda addr: "0x%x" % addr)

        self.ax.set_axis_off()

        graph_draw(graph, pos=layout, mplfig=self.ax, vertex_shape="circle",
                   vertex_text=label,
                   vertex_text_position=-1,
                   edge_pen_width=pen_width,
                   output=self._get_plot_file())
        logger.debug("Plot saved to %s", self._get_plot_file())
        plt.savefig(self._get_plot_file())
        plt.show()
