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
import os

from graph_tool.all import *
from elftools.elf.elffile import ELFFile

from cheriplot.core.vmmap import VMMap

logger = logging.getLogger(__name__)

class CallGraphDumpVisitor(BFSVisitor):

    def __init__(self, graph):
        super().__init__()
        self.graph = graph

    def examine_vertex(self, u):
        logger.info("FN <%x> %s", self.graph.vp.addr[u],
                    self.graph.vp.name[u])

    def tree_edge(self, e):
        logger.info("<%x> --> <%x> calls:%s, bt:%s",
                    self.graph.vp.addr[e.source()],
                    self.graph.vp.addr[e.target()],
                    self.graph.ep.t_call[e],
                    self.graph.ep.backtrace[e])


class CallGraphManager:
    """
    Interface class for call graph manipulation
    """

    def __init__(self, cache_file=None):
        """
        Create a graph manager. A new graph is generated
        if the cache file is not specified or does not exist.
        """
        self.cache_file = cache_file
        if cache_file and os.path.exists(cache_file):
            self.graph = load_graph(cache_file)
        else:
            self.graph = Graph()
            # XXX maybe make them edge props
            # prop_t_call = self.graph.new_vertex_property("int64_t")
            # prop_t_return = self.graph.new_vertex_property("int64_t")
            prop_addr = self.graph.new_vertex_property("int64_t")
            prop_name = self.graph.new_vertex_property("string")
            prop_cap_call = self.graph.new_vertex_property("bool")
            prop_t_call = self.graph.new_edge_property("vector<int64_t>")
            prop_backtrace = self.graph.new_edge_property("int64_t")
            # self.graph.vp["t_call"] = prop_t_call
            # self.graph.vp["t_return"] = prop_t_return
            self.graph.vp["addr"] = prop_addr
            self.graph.vp["name"] = prop_name
            self.graph.vp["cap_call"] = prop_cap_call
            self.graph.ep["t_call"] = prop_t_call
            self.graph.ep["backtrace"] = prop_backtrace
        self._init_props()

    def _init_props(self):
        # address of a function vertex
        self.addr = self.graph.vp.addr
        # symbol name of a function vertex
        self.name = self.graph.vp.name
        # is the vertex called by capability calls
        self.cap_call = self.graph.vp.cap_call
        # vector of call times for each edge, every time A calls B
        # the cycle_time of the call is added to the t_call vector
        # for the edge (A,B)
        self.t_call = self.graph.ep.t_call
        # marks an edge being in the backtrace, the value is the cycle
        # time of the call that goes in the backtrace so that the backtrace
        # calls can be ordered by simple inspection of the graph.
        self.backtrace = self.graph.ep.backtrace

    def load(self, cache_file):
        self.graph = load_graph(cache_file)
        self.cache_file = cache_file
        self._init_props()

    def save(self, dest=None):
        if dest is None:
            dest = self.cache_file
        self.graph.save(dest)

    def dump(self):
        self.bfs_transform(CallGraphDumpVisitor(self.graph))

    def bfs_transform(self, transform):
        roots = []
        # find roots (normally there should be only one)
        for v in self.graph.vertices():
            if v.in_degree() == 0:
                roots.append(v)
        for v in roots:
            bfs_search(self.graph, v, transform)


class CallGraphAddSymbols(BFSVisitor):
    """
    Resolve symbols in the call graph based on one or more ELF files
    and their load addressess.
    """

    def __init__(self, cgm, files, vmmap_path):
        """
        Build the addSymbols graph transform

        :param files: the list of binary file paths
        :param vmmap: the vmmap file to be parsed
        """
        vmmap = VMMap(vmmap_path)

        self.elf_files = []
        """List of tuples (elf-file, start-addr, end-addr)"""

        for path in files:
            fname = os.path.basename(path)
            elf_file = ELFFile(open(path, "rb"))
            for entry in vmmap:
                entry_fname = os.path.basename(entry.path)
                if entry_fname == fname:
                    self.elf_files.append((elf_file, entry.start, entry.end))
                    break
            else:
                logger.info("No VM Map entry found for %s, skip", fname)

        self.cgm = cgm
        """The call-graph manager instance"""

    def examine_vertex(self, u):
        """
        Get function address associated with the vertex and lookup
        the corresponding symbol.
        """
        sym_addr = self.cgm.addr[u]
        logger.debug("search symbol for %d", sym_addr)
        for elf,start,end in self.elf_files:
            logger.debug("Inspect %s", elf.stream.name)
            if start <= sym_addr and end >= sym_addr:
                symtab = elf.get_section_by_name(".symtab")
                if symtab is None:
                    logger.debug("No symbol table for file %s",
                                 elf.stream.name)
                    continue
                symbol_name = ""
                for symbol in symtab.iter_symbols():
                    if symbol["st_value"] + start == sym_addr:
                        logger.debug("Found matching symbol for 0x%x in %s",
                                     sym_addr, elf.stream.name)
                        symbol_name = symbol.name
                        break
                if symbol_name:
                    logger.debug("Found symbol %s", symbol_name)
                    self.cgm.name[u] = symbol_name
                    break
