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

from cheriplot.core import SubCommand, BaseTraceTaskDriver, ProgressTimer, Option
from cheriplot.provenance.plot import (
    AddressMapPlotDriver, AddressMapDerefPlotDriver, PtrSizeDerefDriver,
    PtrSizeBoundDriver, PtrSizeCdfDriver)
from cheriplot.provenance.parser import PointerProvenanceParser
from cheriplot.provenance.stats import ProvenanceStatsDriver
from cheriplot.provenance.transforms import *

logger = logging.getLogger(__name__)

__all__ = ("ProvenancePlotDriver",)

class ProvenancePlotDriver(BaseTraceTaskDriver):
    """
    Main task driver that registers all the other plot driver tools and gives them
    the provenance graph as input.
    """
    addrmap = SubCommand(AddressMapPlotDriver)
    addrmap_deref = SubCommand(AddressMapDerefPlotDriver)
    ptrsize_cdf = SubCommand(PtrSizeCdfDriver)
    ptrsize_bound = SubCommand(PtrSizeBoundDriver)
    ptrsize_deref = SubCommand(PtrSizeDerefDriver)
    stats = SubCommand(ProvenanceStatsDriver)
    threads = Option(
        type=int,
        default=1,
        help="Run the tool with the given number of workers")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._parser = PointerProvenanceParser(cache=self.config.cache,
                                               trace_path=self.config.trace,
                                               threads=self.config.threads)

    def run(self):
        # XXX should probably change the way we encapsulte stuff here,
        # this should be a simple task driver and each subcommand should inherit
        # from a base driver that provides common arguments so that multiple
        # traces can be handled more consistently.
        self._parser.parse()
        # get the parsed provenance graph model
        pgm = self._parser.get_model()
        # free the parser to reclaim memory
        del self._parser

        # do the filtering of the graph here
        with ProgressTimer("Mask NULL and kernel capabilities", logger):
            flat_transform(pgm, [MaskNullAndKernelVertices(pgm)])
        with ProgressTimer("Merge cfromptr + csetbounds", logger):
            flat_transform(pgm, [MergeCFromPtr(pgm)])
        with ProgressTimer("Mask remaining cfromptr", logger):
            flat_transform(pgm, [MaskCFromPtr(pgm)])

        sub = self.config.subcommand_class(pgm, config=self.config)
        sub.run()
