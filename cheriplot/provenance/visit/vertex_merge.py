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
"""
Transformations for the provenance vertex layer.

These transformations mask, or merge vertices in the provenance layer
based on different properties such as origin and bounds.
"""

import logging

import pandas as pd
from graph_tool.all import GraphView

from cheriplot.provenance.visit import BFSGraphVisit
from cheriplot.provenance.model import (
    CheriNodeOrigin, ProvenanceVertexData, CheriCap)

logger = logging.getLogger(__name__)

class MaskBFSVisit(BFSGraphVisit):
    """
    Base class for BFS visits that generate a masked graph-view
    """

    def __init__(self, pgm):
        super().__init__(pgm)

        self.vertex_mask = self.pgm.graph.new_vertex_property("bool", val=True)
        """Vertex filter property"""

    def finalize(self, graph_view):
        return GraphView(graph_view, vfilt=self.vertex_mask)


class FilterNullVertices(MaskBFSVisit):
    """
    Generate a graph_view that masks all NULL capabilities.
    """

    description = "Mask NULL capabilities"

    def examine_vertex(self, u):
        if self.pgm.layer_prov[u]:
            data = self.pgm.data[u]
            if ((data.cap.length == 0 and data.cap.base == 0) or
                not data.cap.valid):
                self.vertex_mask[u] = False

class FilterKernelVertices(MaskBFSVisit):
    """
    Generate a graph_view that masks all kernel vertices and NULL capabilities.
    """

    description = "Mask Kernel capabilities"

    def examine_vertex(self, u):
        if self.pgm.layer_prov[u]:
            data = self.pgm.data[u]
            if data.pc != 0 and data.is_kernel:
                self.vertex_mask[u] = False


class FilterStackVertices(MaskBFSVisit):
    """
    Mask capabilities that point to the stack.
    """

    description = "Mask capabilities to stack objects"

    def __init__(self, pgm, stack_begin, stack_end):
        super().__init__(pgm)

        self.stack_begin = stack_begin
        self.stack_end = stack_end

    def examine_vertex(self, u):
        if not self.pgm.layer_prov[u]:
            return
        data = self.pgm.data[u]
        if data.cap.base >= self.stack_begin and data.cap.bound <= self.stack_end:
            self.vertex_mask[u] = False


class FilterCfromptr(MaskBFSVisit):
    """
    Transform that removes cfromptr vertices that are never stored
    in memory nor used for dereferencing.
    """

    description = "Filter temporary cfromptr"

    def examine_vertex(self, u):
        if not self.pgm.layer_prov[u]:
            return
        data = self.pgm.data[u]
        if data.origin == CheriNodeOrigin.FROMPTR:
            self.vertex_mask[u] = False
            # if (data.origin == CheriNodeOrigin.FROMPTR and
            #     len(data.address) == 0 and
            #     len(data.deref["load"]) == 0 and
            #     len(data.deref["load"]) == 0):
            #     # remove cfromptr that are never stored or used in
            #     # a dereference
            #     self.vertex_mask[u] = True


class MergeCfromptr(MaskBFSVisit):
    """
    Transform that adds merged vertices that represent
    a cfromtpr immediately followed by a csetbounds and masks the
    original cfromptr and csetbounds vertices.
    """

    description = "Merge cfromptr+csetbounds sequences"

    def _get_parent(self, u):
        """Return the provenance-layer parent of a vertex, if any."""
        prov_view = self.pgm.prov_view()
        parents = prov_view.vertex(u).in_neighbours()
        valid_parents = [p for p in parents if self.vertex_mask[p]]
        if len(valid_parents) > 1:
            msg = "Found provenance-layer vertex %s with "\
                  "multiple parents %s" % (u, parents)
            logger.error(msg)
            raise ValueError(msg)
        elif len(valid_parents) == 1 and valid_parents[0].out_degree() == 1:
            return self.pgm.graph.vertex(valid_parents[0])
        else:
            return None

    def _make_merged(self, p, u):
        """
        Create a merged vertex in the provenance layer representing
        a cfromptr + csetbounds sequence.

        :param p: parent of u, the CFROMPTR vertex
        :param u: the CSETBOUNDS vertex
        """
        p_data = self.pgm.data[p]
        u_data = self.pgm.data[u]
        v = self.pgm.graph.add_vertex()
        v_data = ProvenanceVertexData()        
        v_data.origin = CheriNodeOrigin.PTR_SETBOUNDS
        v_data.pc = u_data.pc
        v_data.is_kernel = u_data.is_kernel or v_data.is_kernel
        v_data.cap = CheriCap.from_copy(u_data.cap)
        if min(u_data.cap.t_free, p_data.cap.t_free) != -1:
            v_data.cap.t_free = max(u_data.cap.t_free, p_data.cap.t_free)
        else:
            v_data.cap.t_free = -1
        # XXX making the dataframe for sorting is somewhat a waste
        # it may be mitigated if the v_data could be left as a dataframe so
        # we don't need to recreate it later on.
        events = pd.DataFrame({k: p_data.events[k] + u_data.events[k]
                               for k in v_data.events.keys()})
        v_data.events = events.sort_values("time").to_dict(orient="list")
        # copy edges
        for w in p.in_neighbours():
            e = self.pgm.graph.add_edge(w, v)
        for w in u.out_neighbours():
            # these can go to the call-layer so copy data as well
            f = self.pgm.graph.edge(u, w)
            e = self.pgm.graph.add_edge(v, w)
            self.pgm.edge_time[e] = self.pgm.edge_time[f]
            self.pgm.edge_addr[e] = self.pgm.edge_addr[f]
            self.pgm.edge_operation[e] = self.pgm.edge_operation[f]
            self.pgm.edge_regs[e] = self.pgm.edge_regs[f]

        self.pgm.data[v] = v_data
        self.pgm.layer_prov[v] = True
        self.vertex_mask[v] = True
        self.vertex_mask[p] = False
        self.vertex_mask[u] = False
    
    def examine_vertex(self, u):
        if not self.pgm.layer_prov[u]:
            return
        parent = self._get_parent(u)
        if parent is None:
            return
        parent_data = self.pgm.data[parent]
        data = self.pgm.data[u]
        if (parent_data.origin == CheriNodeOrigin.FROMPTR and
            data.origin == CheriNodeOrigin.SETBOUNDS):
            self._make_merged(parent, u)
