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
Graph visits that produce a slice of the provenance and call graph.
"""

import logging

import pandas as pd
from graph_tool.all import GraphView

from cheriplot.provenance.visit import BFSGraphVisit
from cheriplot.provenance.model import (
    CheriNodeOrigin, ProvenanceVertexData, CheriCap)

logger = logging.getLogger(__name__)

class ProvGraphTimeSlice(BFSGraphVisit):
    """
    Generate a graph view containing only the provenance vertices that
    have been manipulated during a given time interval.

    The visit can consider creation time, dereference and load/store time
    or both.
    """
    description = "Filter provenance vertices by manipulation time"

    def __init__(self, pgm, start, end, creation_time=True,
                 deref_time=False, access_time=False):
        super().__init__(pgm)

        assert start < end, "Invalid time order {:d} < {:d}".format(start, end)

        self.start = start
        """Start time of the slice."""

        self.end = end
        """End time of the slice."""

        self.slice_vertices = self.pgm.graph.new_vertex_property("bool", val=False)
        """Mask filtering the vertices in the slice."""

        self._filters = []
        """Callables used to determine whether a vertex is filtered."""

        if creation_time:
            self._filters.append(self._filter_alloc_time)
        if deref_time:
            self._filters.append(self._filter_deref_time)
        if access_time:
            self._filters.append(self._filter_access_time)

    def _filter_alloc_time(self, v):
        """Filter vertices by creation time."""
        v_data = self.pgm.data[v]
        if self.start <= v_data.cap.t_alloc and v_data.cap.t_alloc <= self.end:
            return True
        return False

    def _filter_event_time(self, v, mask):
        """
        Filter vertices by event time.

        :param v: vertex
        :param mask: EventType mask
        """
        v_data = self.pgm.data[v]
        events = (v_data.event_tbl["type"] & mask) != 0
        times = v_data.event_tbl[events]["time"]
        return times.between(self.start, self.end).any()

    def _filter_deref_time(self, v):
        mask = ProvenanceVertexData.EventType.deref_mask()
        return self._filter_event_time(v, mask)

    def _filter_access_time(self, v):
        mask = ProvenanceVertexData.EventType.memop_mask()
        return self._filter_event_time(v, mask)

    def examine_vertex(self, v):
        if not self.pgm.layer_prov[v]:
            return
        match = False
        for f in self._filters:
            match |= f(v)
        self.slice_vertices[v] = match

    def finalize(self, graph_view):
        return GraphView(graph_view, self.slice_vertices)
