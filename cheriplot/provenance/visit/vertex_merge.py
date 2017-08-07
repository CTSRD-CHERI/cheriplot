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
from itertools import chain

from cheriplot.provenance.visit import MaskBFSVisit
from cheriplot.provenance.model import (
    CheriNodeOrigin, ProvenanceVertexData, CheriCap)

logger = logging.getLogger(__name__)


class MergeCfromptr(MaskBFSVisit):
    """
    Transform that adds merged vertices that represent
    a cfromtpr immediately followed by a csetbounds and masks the
    original cfromptr and csetbounds vertices.
    """

    description = "Merge cfromptr+csetbounds sequences"

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
        for col in v_data.events.keys():
            # XXX can I use a generator here to avoid creating the list?
            v_data.events[col] = p_data.events[col] + u_data.events[col]
        # join active memory references
        delta = len(p_data.events["time"])
        u_mem = ((k, idx + delta) for k, idx in u_data.active_memory.items())
        p_mem = p_data.active_memory.items()
        v_data.active_memory = dict(chain(p_mem, u_mem))
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

    def _get_progress_range(self, graph_view):
        return (0, graph_view.num_edges())

    def examine_edge(self, e):
        self.progress.advance()
        src = e.source()
        dst = e.target()
        if (not self.pgm.layer_prov[src] or
            not self.pgm.layer_prov[dst]):
            return
        src_data = self.pgm.data[src]
        if src_data.origin == CheriNodeOrigin.FROMPTR:
            dst_data = self.pgm.data[dst]
            if dst_data.origin == CheriNodeOrigin.SETBOUNDS:
                self._make_merged(src, dst)
