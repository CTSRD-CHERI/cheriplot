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

from cheriplot.core import NestedConfig, TaskDriver, ProgressTimer, CumulativeTimer
from cheriplot.vmmap import VMMapFileParser
from cheriplot.provenance.model import (
    CheriNodeOrigin, ProvenanceVertexData, EdgeOperation, EventType)
from cheriplot.provenance.visit import BFSGraphVisit

logger = logging.getLogger(__name__)

class MmapStatsVisitor(BFSGraphVisit):
    """
    Visitor that gather informations about the vertices in the graph
    """

    def __init__(self, pgm, vmmap):
        super().__init__(pgm)
        self.pgm = pgm
        self.graph = pgm.graph
        self.stats = {
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
            # number of csetbounds that generate from different places
            "stack_alloc": 0,
            "mmap_alloc": 0,
            "malloc_alloc": 0,
            "globals": 0,
            # total number of setbounds operations
            "num_setbounds": 0,
        }

        for entry in vmmap:
            if entry.grows_down:
                self.stack = entry
                break
        else:
            self.stack = None

    def examine_vertex(self, u):
        self.progress.advance()
        if not self.pgm.layer_prov[u]:
            return
        data = self.pgm.data[u]
        events = data.event_tbl
        self._get_deref_stats(events)
        self._get_memop_stats(events)
        self._get_argv_stats(events)
        self._get_alloc_stack(data)
        if (data.origin == CheriNodeOrigin.SETBOUNDS or
            data.origin == CheriNodeOrigin.PTR_SETBOUNDS):
            self.stats["num_setbounds"] += 1

    def examine_edge(self, e):
        if self.pgm.layer_prov[e.source()] and self.pgm.layer_call[e.target()]:
            self._get_alloc_stats(e)

    def _get_alloc_stats(self, edge):
        if not self.pgm.edge_operation == EdgeOperation.RETURN:
            return
        target = edge.target()
        if (self.pgm.data[target].symbol == "malloc" or
            self.pgm.data[target].symbol == "__malloc"):
            self.stats["malloc_alloc"] += 1
        elif self.pgm.data[target].address == 447:
            self.stats["mmap_alloc"] += 1

    def _get_alloc_stack(self, data):
        """
        Check if the vertex is a setbounds referencing the stack.
        XXX note this is not the same of a stack allocation, we need information
        about the current function frame boundaries.
        """
        if self.stack is None:
            return

        if ((data.origin == CheriNodeOrigin.SETBOUNDS or
             data.origin == CheriNodeOrigin.PTR_SETBOUNDS) and
            data.cap.base >= self.stack.start and
            data.cap.bound <= self.stack.end):
            self.stats["stack_alloc"] += 1

    def _get_deref_stats(self, events):
        n_deref_load = (
            (events["type"] & EventType.DEREF_LOAD) != 0).sum()
        n_deref_store = (
            (events["type"] & EventType.DEREF_STORE) != 0).sum()
        self.stats["deref_load"] += n_deref_load
        self.stats["deref_store"] += n_deref_store

    def _get_memop_stats(self, events):
        mem_store = (events["type"] & EventType.STORE) != 0
        n_store = mem_store.sum()
        n_store_unq = len(events[mem_store]["addr"].unique())

        self.stats["stored"] += n_store
        self.stats["stored_unique"] += n_store_unq

    def _get_argv_stats(self, events):
        stack_base = self.graph.gp.stack.base + self.graph.gp.stack.offset
        stack_bound = self.graph.gp.stack.bound
        n_args_stack_load = (
            ((events["type"] & EventType.LOAD) != 0) &
            (events["addr"] >= stack_base) &
            (events["addr"] <= stack_bound)).sum()
        if n_args_stack_load > 0:
            self.stats["from_args_stack"] += 1


class ProvenanceStatsDriver(TaskDriver):
    """
    Generate statistics from the provenance graph that help understanding the
    distribution of pointers in the program.
    """

    def __init__(self, pgm_list, vmmap, **kwargs):
        super().__init__(**kwargs)

        self.vmmap = vmmap

        self.pgm = pgm_list[0]
        """Provenance graph model"""

    def run(self):
        mmap_stats = MmapStatsVisitor(self.pgm, self.vmmap)
        mmap_stats(self.pgm.graph)

        stats = pd.DataFrame(mmap_stats.stats, index=[0])
        print(stats)
