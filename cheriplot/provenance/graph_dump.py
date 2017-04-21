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

from functools import reduce
from itertools import repeat
from graph_tool.all import load_graph, bfs_iterator, dfs_iterator

from cheriplot.core import (
    BaseToolTaskDriver, Argument, Option, option_range_validator,
    any_int_validator)
from cheriplot.provenance.model import CheriNodeOrigin, NodeData

logger = logging.getLogger(__name__)

class ProvenanceGraphDumpDriver(BaseToolTaskDriver):
    """
    Dump and manually filter the nodes in the
    provenance graph.
    """

    range_format_help = "Accept a range in the form <start>-<end>, -<end>, "\
                        "<start>- or <single_value>"

    graph_file = Argument(help="Path to the provenance graph file")
    origin = Option(
        help="Find vertices with specific origin.",
        choices=("root", "csetbounds", "cfromptr", "ptrbounds",
                 "candperm", "mmap"),
        default=None)
    pc = Option(
        type=option_range_validator,
        default=None,
        help="Find vertices with PC in the given range. " + range_format_help)
    time = Option(
        type=option_range_validator,
        help="Find all vertices created at given time. " + range_format_help)
    mem = Option(
        type=option_range_validator,
        help="Show all vertices stored at a memory address. " + range_format_help)
    deref = Option(
        type=option_range_validator,
        help="Show all vertices dereferenced at a memory address. " + range_format_help)
    size = Option(
        type=option_range_validator,
        help="Show vertices with given length. " + range_format_help)
    syscall = Option(
        type=int,
        help="Show all syscall vertices for given code")
    perms = Option(
        type=any_int_validator,
        help="Find vertices with given permission bits set.")
    otype = Option(
        type=any_int_validator,
        help="Find vertices with given object type.")
    match_any = Option(
        action="store_true",
        help="Return a trace entry when matches any"
        " of the conditions, otherwise all conditions"
        " must be verified.")
    predecessors = Option(
        action="store_true",
        help="Show the predecessors of a matching capability.")
    successors = Option(
        action="store_true",
        help="Show the successors of a matching capability.")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.graph = load_graph(self.config.graph_file)
        """The graph to dump."""

        self.match_origin = None
        """Search for nodes with this origin"""

        self._check_origin_arg(self.config.origin)

        self.filters = [
            self._match_origin,
            self._match_pc,
            self._match_mem,
            self._match_deref,
            self._match_syscall,
            self._match_perms,
            self._match_otype,
            self._match_alloc,
            self._match_len
        ]

    def _check_origin_arg(self, match_origin):
        if match_origin == None:
            return
        elif match_origin == "root":
            self.match_origin = CheriNodeOrigin.ROOT
        elif match_origin == "csetbounds":
            self.match_origin = CheriNodeOrigin.SETBOUNDS
        elif match_origin == "cfromptr":
            self.match_origin = CheriNodeOrigin.FROMPTR
        elif match_origin == "ptrbounds":
            self.match_origin = CheriNodeOrigin.PTR_SETBOUNDS
        elif match_origin == "andperm":
            self.match_origin = CheriNodeOrigin.ANDPERM
        elif match_origin == "mmap":
            self.match_origin = CheriNodeOrigin.SYS_MMAP
        else:
            raise ValueError("Invalid match_origin parameter")

    def _update_match_result(self, match, value):
        """
        Combine the current match result with the value of
        a test according to the match mode.
        """
        if value is None:
            return match
        if self.config.match_any:
            return match or value
        else:
            return match and value

    def _check_limits(self, start, end, value):
        result = True
        if start != None and start > value:
            result = False
        if end != None and end < value:
            result = False
        return result

    def _match_origin(self, vdata):
        if self.match_origin:
            return vdata.origin == self.match_origin
        return None

    def _match_pc(self, vdata):
        if self.config.pc:
            start, end = self.config.pc
            return self._check_limits(start, end, vdata.pc)
        return None

    def _match_mem(self, vdata):
        if self.config.mem:
            start, end = self.config.mem
            result = False
            for addr in vdata.address.values():
                result |= self._check_limits(start, end, addr)
                if result:
                    break
            return result
        return None

    def _match_deref(self, vdata):
        if self.config.deref:
            start, end = self.config.deref
            result = False
            for addr in vdata.deref["addr"]:
                result |= self._check_limits(start, end, addr)
                if result:
                    break
            return result
        return None

    def _match_syscall(self, vdata):
        if self.config.syscall:
            raise NotImplementedError("Syscalls not currently stored")
        return None

    def _match_perms(self, vdata):
        if self.config.perms:
            return vdata.cap.has_perm(self.config.perms)
        return None

    def _match_otype(self, vdata):
        if self.config.otype:
            return vdata.cap.objtype == self.config.otype
        return None

    def _match_alloc(self, vdata):
        if self.config.time:
            start, end = self.config.time
            return self._check_limits(start, end, vdata.cap.t_alloc)
        return None

    def _match_len(self, vdata):
        if self.config.size:
            start, end = self.config.size
            return self._check_limits(start, end, vdata.cap.length)
        return None

    def _dump_vertex(self, vdata):
        n_load = reduce(lambda t,a: a + 1 if
                        t == NodeData.DerefType.DEREF_LOAD else a,
                        vdata.deref["type"], 0)
        n_store = reduce(lambda t,a: a + 1 if
                         t == NodeData.DerefType.DEREF_STORE else a,
                         vdata.deref["type"], 0)
        return "%s stored: %d, deref-load: %d deref-store: %d" % (
            vdata, len(vdata.address), n_load, n_store)

    def run(self):
        for v in self.graph.vertices():
            vdata = self.graph.vp.data[v]
            # initial match value, if match_any is true
            # we OR the match results so start with false
            # else we AND them, so start with true
            match = not self.config.match_any
            for checker in self.filters:
                result = checker(vdata)
                match = self._update_match_result(match, result)
            if match:
                if self.config.predecessors:
                    predecessors = [v]
                    while True:
                        try:
                            p = next(predecessors[0].in_neighbours())
                            predecessors.insert(0, p)
                        except StopIteration:
                            break
                    for p in predecessors:
                        pdata = self.graph.vp.data[p]
                        print("+- %s" % self._dump_vertex(pdata))
                        print("^")
                else:
                    print("+- %s" % self._dump_vertex(vdata))
                if self.config.successors:
                    # list of tuples (depth, vertex)
                    vertices = list(zip(repeat(1), v.out_neighbours()))
                    while len(vertices):
                        depth, s = vertices.pop(0)
                        successors = list(zip(repeat(depth + 1),
                                              s.out_neighbours()))
                        successors.extend(vertices)
                        vertices = successors
                        space = "  " * depth
                        sdata = self.graph.vp.data[s]
                        print("%s+- %s" % (space, self._dump_vertex(sdata)))
                print("######")
