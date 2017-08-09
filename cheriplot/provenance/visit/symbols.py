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
Transformations that handle symbols in the cheriplot graph.
"""

import logging

import pandas as pd
from graph_tool.all import GraphView

from cheriplot.provenance.visit import BFSGraphVisit
from cheriplot.provenance.model import (
    CheriNodeOrigin, ProvenanceVertexData, CheriCap, EdgeOperation)

logger = logging.getLogger(__name__)

class ResolveSymbolsGraphVisit(BFSGraphVisit):
    """
    Graph visitor that associates symbol names to vertices
    in the call-layer of the cheriplot graph.
    """

    description = "Resolve call symbols"

    def __init__(self, pgm, symreader, syscall_master):
        """
        Symbol resolver constructor.
        
        :param pgm: provenance graph manager
        :param vmmap: virtual memory map parser
        :param syscall_master: the syscall.master file parser
        :param symreader: ELF symbols reader
        """
        super().__init__(pgm)

        self.symreader = symreader
        """Symbols reader."""

        self.num_found = 0
        """Number of symbols found."""

    def _get_progress_range(self, graph_view):
        return (0, graph_view.num_edges())

    def examine_edge(self, e):
        self.progress.advance()
        src = e.source()
        dst = e.target()
        if (not self.pgm.layer_call[src] or
            not self.pgm.layer_call[dst]):
            return
        if self.pgm.edge_operation[e] == EdgeOperation.CALL:
            data = self.pgm.data[dst]
            try:
                sym, fname = self.symreader.find_address(data.address)
                data.symbol = sym
                data.symbol_file = fname
                logger.debug("Found symbol 0x%x -> (%s) %s",
                             data.address, data.symbol_file, data.symbol)
                self.num_found = 0
            except TypeError:
                return

    def finalize(self, graph_view):
        logger.info("Found %d symbols", self.num_found)
        return super().finalize(graph_view)
