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

from cheriplot.core import ConfigurableComponent, Option
from cheriplot.callgraph import CallGraphAddSymbols

logger = logging.getLogger(__name__)

class CallGraphPlot(ConfigurableComponent):
    """Handle plotting of a call graph using graph-tool layouts"""

    outfile = Option(
        "-o",
        help="Save plot to file, see matplotlib for supported formats "
        "(svg, png, pgf...)",
        required=True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.fig, self.ax = self.init_axes()

    def init_axes(self):
        plt.switch_backend("cairo")
        fig = plt.figure(figsize=(15,10))
        ax = fig.add_axes([0.05, 0.15, 0.9, 0.80,])
        return (fig, ax)

    def plot(self, cgm):
        """
        Plot the call graph

        :param cgm: The call graph model to plot
        :type cgm: :class:`cheriplot.callgraph.model.CallGraphManager`
        """
        graph = cgm.graph
        # layout = arf_layout(graph, max_iter=0, d=5)
        layout = sfdp_layout(graph)
        pen_width = prop_to_size(cgm.backtrace, mi=0.5, ma=5)
        label = graph.new_vertex_property("string")
        map_property_values(graph.vp.addr, label, lambda addr: "0x%x" % addr)

        self.ax.set_axis_off()

        graph_draw(graph, pos=layout, mplfig=self.ax, vertex_shape="circle",
                   vertex_text=label,
                   vertex_text_position=-1,
                   edge_pen_width=pen_width)
        plt.savefig(self.config.outfile)
        print("Written file %s" % self.config.outfile)
