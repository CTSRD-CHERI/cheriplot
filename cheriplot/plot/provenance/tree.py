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

from graph_tool.all import *

from matplotlib import pyplot as plt

from cheriplot.plot.provenance.provenance_plot import PointerProvenancePlot

logger = logging.getLogger(__name__)

class PointerTreePlot(PointerProvenancePlot):
    """
    Plot the pointer tree
    """

    def plot(self):

        layout = sfdp_layout(self.dataset)
        # also arf_layout? not sure how easy is to draw a tree with multiple roots
        # if we want to see features there

        node_sizes = np.empty(self.dataset.num_vertices())
        for idx, v in enumerate(self.dataset.vertices()):
            data = self.dataset.vp.data[v]
            node_sizes[idx] = data.length
        # normalize in the range min_size, max_size
        min_size = 5
        max_size = 50
        node_min = np.min(node_sizes) or 1
        node_max = np.max(node_sizes)
        b = (node_min * max_size - min_size * node_max) / (node_min - node_max)
        a = (min_size - b) / node_min
        node_sizes = a * node_sizes + b

        
        
        # nx.draw_networkx_nodes(self.dataset, pos,
        #                        node_size=100,
        #                        node_color="lightblue")
        # nx.draw_networkx_edges(self.dataset, pos)

        # labels = {}
        # for node in self.dataset.nodes():
        #     labels[node] = "0x%x" % node.length
        # nx.draw_networkx_labels(self.dataset, pos, labels, font_size=5)

        plt.axis("off")
        plt.savefig(self._get_plot_file())
