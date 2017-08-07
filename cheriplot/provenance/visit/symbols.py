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
        """Symbols reader"""

    def _get_vertex_type(self, u):
        """
        Return the operation that generated the vertex (call, syscall, etc.)
        """
        call_view = self.pgm.call_view()
        parents = list(call_view.vertex(u).in_neighbours())
        if len(parents) == 0:
            return None
        elif len(parents) > 1:
            raise ValueError("Call vertex with multiple parents %s %s",
                             u, self.pgm.data[u])
        else:
            edge = call_view.edge(parents[0], u)
            return self.pgm.edge_operation[edge]

    def examine_vertex(self, u):
        self.progress.advance()
        if not self.pgm.layer_call[u]:
            return
        udata = self.pgm.data[u]
        if udata.address is None:
            return
        if self._get_vertex_type(u) == EdgeOperation.CALL:
            symdata = self.symreader.find_address(udata.address)
            if symdata is not None:
                udata.symbol, udata.symbol_file = symdata
                logger.debug("Found symbol 0x%x -> (%s) %s",
                             udata.address, udata.symbol_file, udata.symbol)
        
