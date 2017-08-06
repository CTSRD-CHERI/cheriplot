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
    filters = Option(
        nargs="*",
        default=[],
        choices=("no-kernel", "no-cfromptr", "tslice", "no-stack"),
        help="Enable filters, default no-null, no-kernel, no-cfromptr")
    tslice_mode = Option(
        nargs="+",
        choices=("deref", "create", "access"),
        default=["create"],
        help="""tslice filter mode parameter:
        deref: cap dereference time (load/store/call via capability)
        create: cap create time
        access: cap access time (load/store of the capability)
        """
    )
    tslice_time = Option(
        nargs=2,
        type=int,
        metavar=("start", "end"),
        help="tslice filter start-time and end-time parameters")
    addrmap = SubCommand(AddressMapPlotDriver)
    addrmap_deref = SubCommand(AddressMapDerefPlotDriver)
    addrmap_access = SubCommand(AddressMapAccessPlotDriver)
    ptrsize_cdf = SubCommand(PtrSizeCdfDriver)
    ptrsize_bound = SubCommand(PtrSizeBoundDriver)
    ptrsize_deref = SubCommand(PtrSizeDerefDriver)
    stats = SubCommand(ProvenanceStatsDriver)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.pgm_list = list(map(ProvenanceGraphManager.load, self.config.graphs))
        """Loaded graph managers."""

        self._vmmap_parser = VMMapFileParser(config=self.config.vmmap)
        """Process memory mapping CSV parser"""

    def _get_filter(self, pgm):
        """Get a combined filter for a given graph manager."""
        filters = FilterNullVertices(pgm) + MergeCfromptr(pgm)
        if "no-kernel" in self.config.filters:
            filters = FilterKernelVertices(pgm) + filters
        if "no-cfromptr" in self.config.filters:
            filters += FilterCfromptr(pgm)
        if "no-stack" in self.config.filters:
            for entry in vmmap:
                if entry.grows_down:
                    break
            else:
                logger.error("no-stack filter requires vmmap argument")
                raise RuntimeError("np-stack filter requires vmmap argument")
            filters += FilterStackVertices(pgm, entry.start, entry.end)
        if "tslice" in self.config.filters:
            start, end = self.config.tslice_time
            deref = "deref" in self.config.tslice_mode
            create = "create" in self.config.tslice_mode
            access = "access" in self.config.tslice_mode
            filters += ProvGraphTimeSlice(
                pgm, start, end, creation_time=create,
                deref_time=deref, access_time=access)
        return filters

    def run(self):
        self._vmmap_parser.parse()
        vmmap = self._vmmap_parser.get_model()
        for pgm in self.pgm_list:
            graph_filter = self._get_filter(pgm)
            filtered_graph = graph_filter(pgm.graph)
            vfilt, _ = filtered_graph.get_vertex_filter()
            pgm.graph.set_vertex_filter(vfilt)
        sub = self.config.subcommand_class(self.pgm_list, vmmap, config=self.config)
        sub.run()
