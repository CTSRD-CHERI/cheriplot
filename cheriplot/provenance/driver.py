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

from cheriplot.core import SubCommand, BaseToolTaskDriver, Argument
from cheriplot.provenance.plot import (
    AddressMapPlotDriver, AddressMapDerefPlotDriver, PtrSizeDerefDriver,
    PtrSizeBoundDriver, PtrSizeCdfDriver)
from cheriplot.provenance.model import ProvenanceGraphManager
from cheriplot.provenance.stats import ProvenanceStatsDriver
from cheriplot.provenance.visit import (
    FilterNullAndKernelVertices, FilterCfromptr, MergeCfromptr)

logger = logging.getLogger(__name__)

class GraphAnalysisDriver(BaseToolTaskDriver):
    """
    Main task driver that registers all the other plot driver tools and gives them
    the provenance graph as input.
    """
    description = """
    Graph processing and plotting tool.
    This tool processes a cheriplot graph to produce plots and statistics.
    """

    graph = Argument(help="Path to the cheriplot graph.")
    addrmap = SubCommand(AddressMapPlotDriver)
    addrmap_deref = SubCommand(AddressMapDerefPlotDriver)
    ptrsize_cdf = SubCommand(PtrSizeCdfDriver)
    ptrsize_bound = SubCommand(PtrSizeBoundDriver)
    ptrsize_deref = SubCommand(PtrSizeDerefDriver)
    stats = SubCommand(ProvenanceStatsDriver)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.pgm = ProvenanceGraphManager.load(self.config.graph)
        """Loaded graph manager."""

    def run(self):
        # do the filtering of the graph here
        filters = (FilterNullAndKernelVertices(self.pgm) +
                   MergeCfromptr(self.pgm) +
                   FilterCfromptr(self.pgm))
        filtered_graph = filters(self.pgm.graph)
        vfilt, _ = filtered_graph.get_vertex_filter()
        self.pgm.graph.set_vertex_filter(vfilt)

        sub = self.config.subcommand_class(self.pgm, config=self.config)
        sub.run()
