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

from cheriplot.core import (
    BaseToolTaskDriver, BaseTraceTaskDriver, Option, Argument, NestedConfig,
    ProgressTimer, file_path_validator)
from cheriplot.vmmap import VMMapFileParser
from cheriplot.dbg.symbols import SymReader
from cheriplot.provenance.parser import CheriMipsModelParser
from cheriplot.provenance.model import ProvenanceGraphManager
from cheriplot.provenance.visit import ResolveSymbolsGraphVisit

logger = logging.getLogger(__name__)

class GraphParserDriver(BaseTraceTaskDriver):
    """
    Task driver that generates a cheriplot graph from a trace file.

    Available parameters are:

    * :class:`BaseTraceTaskDriver` parameters
    * threads: the number of threads to use (default 1)
    * outfile: the output trace file (default <trace_file_name>_graph.gt
    """
    description = """
    Trace parse tool.
    This tool generates a cheriplot graph from a CHERI trace.
    """

    threads = Option(
        type=int,
        default=1,
        help="Run the tool with the given number of workers (experimental)")
    outfile = Option(
        default=None,
        type=file_path_validator,
        help="Output graph file name")
    display_name = Option(
        default=None,
        help="User-readable name of the dataset")
    cheri_cap_size = Option(
        default="256",
        choices=("128", "256"),
        help="Cheri capability size")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        default_outfile = "{}_graph.gt".format(self.config.trace)
        outfile = self.config.outfile or default_outfile
        if self.config.cheri_cap_size == "128":
            cap_size = 16
        elif self.config.cheri_cap_size == "256":
            cap_size = 32
        else:
            raise ValueError("Invalid capability size {}".format(self.config.cheri_cap_size))

        self.pgm = ProvenanceGraphManager(outfile)
        """Graph manager."""

        self._parser = CheriMipsModelParser(
            self.pgm, capability_size=cap_size, trace_path=self.config.trace,
            threads=self.config.threads)
        """Graph parser strategy, depends on the architecture."""

    def run(self):
        self._parser.parse()
        # get the parsed provenance graph model
        self.pgm.save(name=self.config.display_name)
        # force free the parser to reclaim memory
        del self._parser


class SymbolResolutionDriver(BaseToolTaskDriver):
    """
    Task driver that fetches symbol names from binary and source files.

    This step requires different input data:

    * Output from procstat-like commands in csv or tab-separated format,
      this is required to extract the base address of the sections of
      a binary in memory.
    * Binary ELF files containing the debug symbols.
    * Kernel syscalls.master file to map syscall numbers to a name/signature.
    """
    description = """
    Resolve call symbols in a cheriplot graph.
    This is a postprocessing tool that extracts debug information from
    ELF files, sources and runtime information to add symbol names and
    call signatures to the cheriplot graph.

    The tool is incremental, it can be run multiple times on the graph.
    """

    graph = Argument(
        type=file_path_validator,
        help="Path to the cheriplot graph.")
    no_output = Option(
        action="store_true",
        help="Do not store output graph, useful for cheriplot-runner")
    vmmap = NestedConfig(VMMapFileParser)
    elfpath = Option(
        nargs="+",
        type=file_path_validator,
        default=[],
        help="Paths where to look for ELF files with symbols")
    syscalls = Option(
        default=None,
        type=file_path_validator,
        help="Path to the syscalls.master file")
    outfile = Option(
        default=None,
        type=file_path_validator,
        help="Output file name, defaults to the input file")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.pgm = None
        """Loaded graph manager."""

        self.vmmap = VMMapFileParser(config=self.config.vmmap)
        """Memory map file parser."""

        self.vmmap.parse()
        self.symreader = SymReader(vmmap=self.vmmap, path=self.config.elfpath)
        """Symbol reader"""

        self._outfile = self.config.outfile or self.config.graph
        """Output file path, defaults to the input file"""

        # self.syscalls = BSDSyscallMasterParser(self.config.syscalls)
        # """Parser for the syscalls.master file."""
        self._load_graph()

    def _load_graph(self):
        self.pgm = ProvenanceGraphManager.load(self.config.graph)

    def run(self):
        # self.syscalls.parse()
        visitor = ResolveSymbolsGraphVisit(self.pgm, self.symreader, None)
        visitor(self.pgm.graph)
        if not self.config.no_output:
            with ProgressTimer("Write output graph", logger):
                self.pgm.save(self._outfile)
