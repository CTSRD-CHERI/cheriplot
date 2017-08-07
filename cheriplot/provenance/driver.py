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
from contextlib import suppress

from cheriplot.core import (
    SubCommand, BaseToolTaskDriver, Argument, Option, NestedConfig)
from cheriplot.vmmap import VMMapFileParser
from cheriplot.provenance.plot import (
    AddressMapPlotDriver, AddressMapDerefPlotDriver, PtrSizeDerefDriver,
    PtrSizeBoundDriver, PtrSizeCdfDriver, AddressMapAccessPlotDriver)
from cheriplot.provenance.model import ProvenanceGraphManager
from cheriplot.provenance.stats import ProvenanceStatsDriver
from cheriplot.provenance.visit import (
    FilterNullVertices, FilterKernelVertices, FilterCfromptr, MergeCfromptr,
    ProvGraphTimeSlice, FilterStackVertices)

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

    graphs = Argument(nargs="+", help="Path to the cheriplot graph.")
    vmmap = NestedConfig(VMMapFileParser)
    addrmap = SubCommand(AddressMapPlotDriver)
    addrmap_deref = SubCommand(AddressMapDerefPlotDriver)
    addrmap_access = SubCommand(AddressMapAccessPlotDriver)
    ptrsize_cdf = SubCommand(PtrSizeCdfDriver)
    ptrsize_bound = SubCommand(PtrSizeBoundDriver)
    ptrsize_deref = SubCommand(PtrSizeDerefDriver)
    stats = SubCommand(ProvenanceStatsDriver)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        loaded_graphs = {}

        self.pgm_list = []
        """Loaded graph managers."""

        for path in self.config.graphs:
            # if a graph is specified multiple times, avoid loading it twice
            try:
                self.pgm_list.append(loaded_graphs[path])
            except KeyError:
                pgm = ProvenanceGraphManager.load(path)
                loaded_graphs[path] = pgm
                self.pgm_list.append(pgm)

        self._vmmap_parser = VMMapFileParser(config=self.config.vmmap)
        """Process memory mapping CSV parser"""

    def run(self):
        self._vmmap_parser.parse()
        vmmap = self._vmmap_parser.get_model()
        sub = self.config.subcommand_class(self.pgm_list, vmmap, config=self.config)
        sub.run()
