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

from cheriplot.core import Option, Argument, NestedConfig, BaseTraceTaskDriver
from cheriplot.provenance.plot import AddressMapPlot
from cheriplot.provenance.parser import PointerProvenanceParser
from cheriplot.provenance.transforms import *

logger = logging.getLogger(__name__)

class ProvenancePlotDriver(BaseTraceTaskDriver):
    """
    Main task driver that registers all the other plot driver tools and gives them
    the provenance graph as input.
    """
    outfile = Option(help="Output file", default=None)
    plot = Argument(help="The plot to generate",
                    choices=("addrmap",))
    # vmmap = NestedConfig()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._parser = PointerProvenanceParser(cache=self.config.cache,
                                               trace_path=self.config.trace)

    def update_config(self, config):
        super().update_config(config)
        self._parser.update_config(config.parser)

    def run(self):
        self._parser.parse()
        # get the parsed provenance graph model
        pgm = self._parser.get_model()
        vmmap = None

        # do the filtering of the graph here
        bfs_transform(pgm, [MaskNullAndKernelVertices(pgm)])
        bfs_transform(pgm, [MergeCFromPtr(pgm)])
        bfs_transform(pgm, [MaskCFromPtr(pgm)])

        if self.config.plot == "addrmap":
            plot = AddressMapPlot(pgm, vmmap)
        plot.process(out_file=self.config.outfile)
