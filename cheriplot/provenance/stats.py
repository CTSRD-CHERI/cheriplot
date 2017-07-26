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
import pandas as pd

from functools import reduce

from cheriplot.core import SubCommand, TaskDriver, ProgressTimer, CumulativeTimer
from cheriplot.provenance.model import (
    CheriNodeOrigin, ProvenanceVertexData, EdgeOperation)
from cheriplot.provenance.visit import BFSGraphVisit

logger = logging.getLogger(__name__)

class MmapStatsVisitor(BFSGraphVisit):
    """
    Visitor that gather informations about the vertices in the graph
    """

    def __init__(self, pgm):
        super().__init__(pgm)
        self.graph = pgm.graph
        self.stats = {
            # number of successors of syscall-returned capabilities
            "syscall_derived": 0,
            # number of capabilities returned by syscalls
            # (in c3 when the syscall returns)
            "syscall_return": 0,
            # number of times a capability is dereferenced for store
            "deref_store": 0,
            # number of times a capability is dereferenced for load
            "deref_load": 0,
            # number of times a capability is stored in memory
            # note this is not the unique number of locations
            "stored": 0,
            # number of unique memory addresses to which a capability
            # is stored
            "stored_unique": 0,
            # number of capabilities originating (being loaded) from the
            # initial stack region for argv, envv and ELF auxargs
            "from_args_stack": 0,
        }

        self.syscall_derived = pgm.graph.new_vertex_property("bool", val=False)
        """
        Mark vertices that are successors of a syscall-returned
        capability.
        """

    def examine_vertex(self, u):
        data = self.graph.vp.data[u]
        events = data.event_tbl
        self._get_syscall_stats(u, events)
        self._get_deref_stats(events)
        self._get_memop_stats(events)
        self._get_argv_stats(events)

    def _get_syscall_stats(self, u, events):
        if not self.syscall_derived[u]:
            # get unfiltered vertex so that we can access call-layer
            # vertices
            uu = self.pgm.graph.vertex(u)
            for w in uu.out_neighbours():
                e = self.pgm.graph.edge(uu, w)
                if self.pgm.edge_operation[e] == EdgeOperation.RETURN:
                    # check if the call-layer vertex is created by a SYSCALL
                    # for this we need the edge from the call-parent
                    call_view = self.pgm.call_view()
                    call_vertex = call_view.vertex(e.target())
                    call_parents = list(call_vertex.in_neighbours())
                    assert len(call_parents) <= 1
                    if len(call_parents):
                        edge = self.pgm.graph.edge(call_parents[0], call_vertex)
                        if self.pgm.edge_operation[edge] == EdgeOperation.SYSCALL:
                            self.syscall_derived[u] = True
                    break
            if not self.syscall_derived[u]:
                return
        # the vertex is used in a syscall return
        self.stats["syscall_derived"] += 1
        for v in u.out_neighbours():
            self.syscall_derived[v] = True

    def _get_deref_stats(self, events):
        n_deref_load = (
            (events["type"] & ProvenanceVertexData.EventType.DEREF_LOAD) != 0).sum()
        n_deref_store = (
            (events["type"] & ProvenanceVertexData.EventType.DEREF_STORE) != 0).sum()
        self.stats["deref_load"] += n_deref_load
        self.stats["deref_store"] += n_deref_store

    def _get_memop_stats(self, events):
        mem_store = (events["type"] & ProvenanceVertexData.EventType.STORE) != 0
        n_store = mem_store.sum()
        n_store_unq = len(events[mem_store]["addr"].unique())

        self.stats["stored"] += n_store
        self.stats["stored_unique"] += n_store_unq

    def _get_argv_stats(self, events):
        stack_base = self.graph.gp.stack.base + self.graph.gp.stack.offset
        stack_bound = self.graph.gp.stack.bound
        n_args_stack_load = (
            ((events["type"] & ProvenanceVertexData.EventType.LOAD) != 0) &
            (events["addr"] >= stack_base) &
            (events["addr"] <= stack_bound)).sum()
        if n_args_stack_load > 0:
            self.stats["from_args_stack"] += 1


class ProvenanceStatsDriver(TaskDriver):
    """
    Generate statistics from the provenance graph that help understanding the
    distribution of pointers in the program.
    """

    def __init__(self, pgm, **kwargs):
        super().__init__(**kwargs)

        self.pgm = pgm
        """Provenance graph model"""

    def run(self):
        mmap_stats = MmapStatsVisitor(self.pgm)
        mmap_stats(self.pgm.prov_view())

        stats = pd.DataFrame(mmap_stats.stats, index=[0])
        print(stats)
