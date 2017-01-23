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

import logging
import pickle

from graph_tool.all import Graph, load_graph

from cheriplot.utils import ProgressPrinter
from cheriplot.core.provenance import CheriNodeOrigin
from cheriplot.plot.plot_base import Plot

from cheriplot.plot.provenance.parser import PointerProvenanceParser

logger = logging.getLogger(__name__)

class PointerProvenancePlot(Plot):
    """
    Base class for plots using the pointer provenance graph.
    """

    def __init__(self, *args, **kwargs):
        super(PointerProvenancePlot, self).__init__(*args, **kwargs)

        self._cached_dataset_valid = False
        """Tells whether we need to rebuild the dataset when caching."""

    def init_parser(self, dataset, tracefile):
        return PointerProvenanceParser(dataset, tracefile)

    def init_dataset(self):
        logger.debug("Init provenance graph for %s", self.tracefile)
        self.dataset = Graph(directed=True)
        vdata = self.dataset.new_vertex_property("object")
        self.dataset.vp["data"] = vdata
        return self.dataset

    def _get_cache_file(self):
        return self.tracefile + "_provenance_plot.gt"

    def build_dataset(self):
        """
        Build the provenance tree
        """
        if self.caching:
            try:
                self.dataset = load_graph(self._get_cache_file())
            except IOError:
                self.parser.parse()
                self.dataset.save(self._get_cache_file())
        else:
            self.parser.parse()

        num_nodes = self.dataset.num_vertices()
        logger.debug("Total nodes %d", num_nodes)
        progress = ProgressPrinter(num_nodes, desc="Remove kernel nodes")
        remove_list = []
        vertex_data = self.dataset.vp.data

        for node in self.dataset.vertices():
            # remove null capabilities
            # remove operations in kernel mode
            node_data = vertex_data[node]
            if ((node_data.pc and node_data.pc >= 0xFFFFFFFF0000000) or
                (node_data.cap.length == 0 and node_data.cap.base == 0)):
                # XXX we should remove the whole subtree!!
                remove_list.append(node)
            progress.advance()
        self.dataset.remove_vertex(remove_list)
        progress.finish()

        num_nodes = self.dataset.num_vertices()
        logger.debug("Filtered kernel nodes, remaining %d", num_nodes)
        progress = ProgressPrinter(
            num_nodes, desc="Merge (cfromptr + csetbounds) sequences")
        remove_list = []

        for node in self.dataset.vertices():
            progress.advance()
            # merge cfromptr -> csetbounds subtrees
            num_parents = node.in_degree()
            if num_parents == 0:
                # root node
                continue
            elif num_parents > 1:
                logger.error("Found node with more than a single parent %s", node)
                raise RuntimeError("Too many parents for a node")

            parent = next(node.in_neighbours())
            parent_data = self.dataset.vp.data[parent]
            node_data = self.dataset.vp.data[node]
            if (parent_data.origin == CheriNodeOrigin.FROMPTR and
                node_data.origin == CheriNodeOrigin.SETBOUNDS):
                # the child must be unique to avoid complex logic
                # when merging, it may be desirable to do so with
                # more complex traces
                node_data.origin = CheriNodeOrigin.PTR_SETBOUNDS
                if parent.in_degree() == 1:
                    next_parent = next(parent.in_neighbours())
                    remove_list.append(parent)
                    self.dataset.add_edge(next_parent, node)
                elif parent.in_degree() == 0:
                    remove_list.append(parent)
                else:
                    logger.error("Found node with more than a single parent %s",
                                 parent)
                    raise RuntimeError("Too many parents for a node")
        self.dataset.remove_vertex(remove_list)
        progress.finish()

        num_nodes = self.dataset.num_vertices()
        logger.debug("Merged (cfromptr + csetbounds), remaining %d", num_nodes)
