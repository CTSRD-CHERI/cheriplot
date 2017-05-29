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

from cheriplot.core import SubCommand, TaskDriver, ProgressTimer
from cheriplot.provenance.transforms import BFSTransform, bfs_transform
from cheriplot.provenance.model import CheriNodeOrigin, NodeData

logger = logging.getLogger(__name__)


class MmapStatsVisitor(BFSTransform):
    """
    Visitor that gather informations about the vertices in the graph
    """

    def __init__(self, graph):
        self.graph = graph
        self.stats = {
            # number of successors of syscall-returned capabilities
            "syscall_derived": 0,
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
        }

        self.syscall_derived = graph.new_vertex_property("bool", val=False)
        """
        Mark vertices that are successors of a syscall-returned
        capability.
        """

    def examine_vertex(self, u):
        data = self.graph.vp.data[u]
        syscall_ret = len(data.call["type"]) > 0
        if syscall_ret or self.syscall_derived[u]:
            logger.debug("Data call %s", data.call)
            self.stats["syscall_derived"] += 1
            for v in u.out_neighbours():
                self.syscall_derived[v] = True
        self._get_stats(data)

    def _get_stats(self, data):
        n_load = reduce(lambda t,a: a + 1 if
                        t == NodeData.DerefType.DEREF_LOAD else a,
                        data.deref["type"], 0)
        n_store = reduce(lambda t,a: a + 1 if
                         t == NodeData.DerefType.DEREF_STORE else a,
                         data.deref["type"], 0)
        self.stats["deref_load"] += n_load
        self.stats["deref_store"] += n_store
        self.stats["stored"] += len(data.address)
        self.stats["stored_unique"] += len(set(data.address.values()))


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
        with ProgressTimer("Gather mmap stats", logger):
            bfs_transform(self.pgm, [mmap_stats])

        stats = pd.DataFrame(mmap_stats.stats, index=[0])
        print(stats)
