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

from itertools import chain
from graph_tool.all import load_graph

from cheriplot.core.provenance import CheriNodeOrigin

logger = logging.getLogger(__name__)

class ProvenanceGraphInspector:
    """
    This class provides a way to manually filter and inspect the nodes in the
    provenance graph.
    """

    def __init__(self, graph_file, match_origin=None, match_pc_start=None,
                 match_pc_end=None, match_mem_start=None, match_mem_end=None,
                 match_deref_start=None, match_deref_end=None,
                 match_syscall=None, match_perms=None, match_otype=None,
                 match_alloc_start=None, match_alloc_end=None,
                 match_len_start=None, match_len_end=None,
                 match_any=None, show_predecessors=False):

        self.graph = load_graph(graph_file)
        """The graph to dump."""

        self.match_origin = None
        """Search for nodes with this origin"""
        self._check_origin_arg(match_origin)

        self.match_pc_start = match_pc_start
        self.match_pc_end = match_pc_end
        self.match_mem_start = match_mem_start
        self.match_mem_end = match_mem_end
        self.match_deref_start = match_deref_start
        self.match_deref_end = match_deref_end
        self.match_alloc_start = match_alloc_start
        self.match_alloc_end = match_alloc_end
        self.match_len_start = match_len_start
        self.match_len_end = match_len_end
        self.match_syscall = match_syscall
        self.match_perms = match_perms
        self.match_otype = match_otype
        self.match_any = match_any
        self.dump_predecessors = show_predecessors

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

    def _update_match_result(self, match=None, value=None):
        """
        Combine the current match result with the value of
        a test according to the match mode, if value is None
        return the initial value for the match
        """
        if self.match_any:
            match = False if value is None else (match or value)
        else:
            match = True if value is None else (match and value)
        return match

    def _check_limits(self, start, end, value):
        result = True
        if start != None and start > value:
            result = False
        if end != None and end < value:
            result = False
        return result

    def _match_origin(self, vdata, match):
        if self.match_origin == None:
            return match
        result = vdata.origin == self.match_origin
        return self._update_match_result(match, result)

    def _match_pc(self, vdata, match):
        if self.match_pc_start == None and self.match_pc_end == None:
            return match
        result = self._check_limits(self.match_pc_start, self.match_pc_end,
                                    vdata.pc)
        return self._update_match_result(match, result)

    def _match_mem(self, vdata, match):
        if self.match_mem_start == None and self.match_mem_end == None:
            return match
        result = False
        for addr in vdata.address.values():
            result = self._check_limits(self.match_mem_start,
                                        self.match_mem_end, addr)
            if result:
                break
        return self._update_match_result(match, result)

    def _match_deref(self, vdata, match):
        if self.match_deref_start == None and self.match_deref_end == None:
            return match
        result = False
        for addr in chain(vdata.deref["load"], vdata.deref["store"]):
            result = self._check_limits(self.match_deref_start,
                                        self.match_deref_end, addr)
            if result:
                break
        return self._update_match_result(match, result)

    def _match_syscall(self, vdata, match):
        if self.match_syscall == None:
            return match
        raise NotImplementedError("Syscalls not currently stored")
        return self._update_match_result(match, result)

    def _match_perms(self, vdata, match):
        if self.match_perms == None:
            return match
        result = vdata.cap.has_perm(self.match_perms)
        return self._update_match_result(match, result)

    def _match_otype(self, vdata, match):
        if self.match_otype == None:
            return match
        result = vdata.cap.objtype == self.match_otype
        return self._update_match_result(match, result)

    def _match_alloc(self, vdata, match):
        if self.match_alloc_start == None and self.match_alloc_end == None:
            return match
        result = self._check_limits(self.match_alloc_start,
                                    self.match_alloc_end,
                                    vdata.cap.t_alloc)
        return self._update_match_result(match, result)

    def _match_len(self, vdata, match):
        if self.match_len_start == None and self.match_len_end == None:
            return match
        result = self._check_limits(self.match_len_start,
                                    self.match_len_end,
                                    vdata.cap.length)
        return self._update_match_result(match, result)

    def _dump_vertex(self, vdata):
        return "%s stored: %d, deref-load: %d deref-store: %d" % (
            vdata, len(vdata.address), len(vdata.deref["load"]),
            len(vdata.deref["store"]))

    def dump(self):

        for v in self.graph.vertices():
            vdata = self.graph.vp.data[v]

            match = self._update_match_result()
            match = self._match_origin(vdata, match)
            match = self._match_pc(vdata, match)
            match = self._match_mem(vdata, match)
            match = self._match_deref(vdata, match)
            match = self._match_alloc(vdata, match)
            match = self._match_len(vdata, match)
            match = self._match_syscall(vdata, match)
            match = self._match_perms(vdata, match)
            match = self._match_otype(vdata, match)

            if match:
                print(self._dump_vertex(vdata))
                if self.dump_predecessors:
                    current = v
                    while True:
                        try:
                            # assume that there is always 1 or 0
                            # predecessors
                            pred = next(current.in_neighbours())
                            current = pred
                            vdata = self.graph.vp.data[pred]
                            print("^")
                            print("|")
                            print("+- %s" % self._dump_vertex(vdata))
                        except StopIteration:
                            break
