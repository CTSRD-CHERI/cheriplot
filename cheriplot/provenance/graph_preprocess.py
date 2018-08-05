#-
# Copyright (c) 2016-2018 Alfredo Mazzinghi
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
    BaseToolTaskDriver, Argument, Option, NestedConfig, file_path_validator,
    ProgressTimer, SubCommand)
from cheriplot.vmmap import VMMapFileParser
from cheriplot.dbg.symbols import SymReader
from cheriplot.provenance.model import ProvenanceGraphManager
from cheriplot.provenance.visit import *
from cheriplot.provenance.plot import *

logger = logging.getLogger(__name__)

class UserGraphPreprocessDriver(BaseToolTaskDriver):

    description = """
    Prepare graph that represent a single user process trace captured with qtrace.
    This will perform the following:
    - Annotate graph with symbols
    - Find the last execve where we enter the process and find the stack pointer.
    - Annotate successors of the stack pointer (annotated_stack)
    - Annotate anything dereferenced in the stack map
    - Annotate vertices returned by malloc (annotated_malloc)
    - Annotate executable vertices (annotated_exec)
    - Annotate global pointers and pointers used to load from captable
    - Annotate pointers that are returned from syscalls
    - Annotate pointers that originated in the kernel and are loaded from memory
    - Mask out all vertices and calls that are created before the last call to execve()
      and have not been marked
    - Mask out NULL capabilities
    - Mask out kernel capabilities that have not been marked
    """

    elfpath = Option(
        required=True,
        nargs="+",
        type=file_path_validator,
        default=[],
        help="Paths where to look for ELF files with symbols")
    vmmap = NestedConfig(VMMapFileParser)
    graph = Argument(
        type=file_path_validator,
        help="Path to the cheriplot graph.")
    outfile = Option(
        default=None,
        type=file_path_validator,
        help="Path to the output file")
    display_name = Option(
        default=None,
        help="New display-name for the graph")

    # available plots
    ptrsize_cdf = SubCommand(PtrSizeCdfDriver)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.vmmap = VMMapFileParser(config=self.config.vmmap)
        """Memory map file parser"""

        self.vmmap.parse()
        self.symreader = SymReader(vmmap=self.vmmap, path=self.config.elfpath)
        """Symbol reader"""

        self.outfile = self.config.outfile or self.config.graph
        """Output file path, defaults to the current graph path"""

        self.pgm = ProvenanceGraphManager.load(self.config.graph)
        """Provenance graph manager"""

    def _get_stack_map(self):
        for vme in self.vmmap.get_model():
            if vme.grows_down:
                return (vme.start, vme.end)
        return None

    def _get_visit_chain(self):
        vchain = ChainGraphVisit(self.pgm)
        vchain += ResolveSymbolsGraphVisit(self.pgm, self.symreader, None)
        vchain += FindLastExecve(self.pgm)
        # vchain += DetectStackCapability(self.pgm)
        stack_begin, stack_end = self._get_stack_map()
        vchain += DecorateStackCapabilities(self.pgm)
        vchain += DecorateStackAll(self.pgm, stack_begin, stack_end)
        vchain += DecorateMalloc(self.pgm)
        vchain += DecorateExecutable(self.pgm)
        vchain += DecorateGlobalPointers(self.pgm, self.symreader)
        vchain += DecorateCapRelocs(self.pgm, self.symreader)
        vchain += DecorateKernelCapabilities(self.pgm)
        vchain += DecorateAccessedInUserspace(self.pgm)
        vchain += FilterBeforeExecve(self.pgm)
        vchain += FilterNullVertices(self.pgm)
        vchain += FilterUnusedKernelVertices(self.pgm)
        return vchain
        
    def run(self):
        """
        Run the tool filtering stages and save the output graph.
        """
        vmmap = self.vmmap.get_model()
        # reset filters on the graph
        self.pgm.graph.clear_filters()
        # get the new filter chain
        visitor_chain = self._get_visit_chain()
        # apply all operations in order
        filtered_graph = visitor_chain(self.pgm.graph)
        # get the resulting vertex filter and apply it to the main graph
        vfilt, _ = filtered_graph.get_vertex_filter()
        self.pgm.graph.set_vertex_filter(vfilt)
        # if we have to change the display name, do it
        if self.config.display_name:
            self.pgm.graph.gp.name = self.config.display_name
        # write out the graph
        with ProgressTimer("Write output graph", logger):
            self.pgm.save(self.outfile)

        with suppress(AttributeError):
            if self.config.subcommand_class:
                # generate plot (would be nice to support more than 1 per run)
                plot = self.config.subcommand_class([self.pgm], self.vmmap,
                                                    config=self.config)
                plot.run()
