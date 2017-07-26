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
Driver for the graph parsing. This is the task that generates a cheriplot
graph from a trace input.
"""

import logging

from cheriplot.core import SubCommand, BaseTraceTaskDriver, ProgressTimer, Option
from cheriplot.provenance.parser import CheriMipsModelParser
from cheriplot.provenance.model import ProvenanceGraphManager

logger = logging.getLogger(__name__)

__all__ = ("GraphBuildDriver",)


class GraphParserDriver(BaseTraceTaskDriver):
    """
    Task driver that generates a cheriplot graph from a trace file.

    Available parameters are:
    
    - :class:`BaseTraceTaskDriver` parameters
    - threads: the number of threads to use (default 1)
    - outfile: the output trace file (default <trace_file_name>_graph.gt
    """
    threads = Option(
        type=int,
        default=1,
        help="Run the tool with the given number of workers (experimental)")
    outfile = Option(
        default=None,
        help="Output graph file name")
    display_name = Option(
        default=None,
        help="User-readable name of the dataset")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        default_outfile = "{}_graph.gt".format(self.config.trace)
        outfile = self.config.outfile or default_outfile

        self.pgm = ProvenanceGraphManager(outfile)
        """Graph manager."""

        self._parser = CheriMipsModelParser(
            self.pgm, trace_path=self.config.trace, threads=self.config.threads)
        """Graph parser strategy, depends on the architecture."""

    def run(self):
        self._parser.parse()
        # get the parsed provenance graph model
        self.pgm.save(name=self.config.display_name)        
        # force free the parser to reclaim memory
        del self._parser
