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

    def __init__(self, graph):
        self.graph = graph
        self.stats = {"derived": 0, "deref_store": 0,
                      "deref_load": 0, "stored": 0}
        self.mmap_derived = graph.new_vertex_property("bool", val=False)
    
    def examine_vertex(self, u):
        data = self.graph.vp.data[u]
        if (data.origin == CheriNodeOrigin.SYS_MMAP or
            self.mmap_derived[u]):
            self._get_stats(data)
            for v in u.out_neighbours():
                self.mmap_derived[v] = True

    def _get_stats(self, data):
        self.stats["derived"] += 1
        n_load = reduce(lambda t,a: a + 1 if
                        t == NodeData.DerefType.DEREF_LOAD else a,
                        data.deref["type"], 0)
        n_store = reduce(lambda t,a: a + 1 if
                         t == NodeData.DerefType.DEREF_STORE else a,
                         data.deref["type"], 0)
        self.stats["deref_load"] += n_load
        self.stats["deref_store"] += n_store
        self.stats["stored"] += len(data.address)


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
