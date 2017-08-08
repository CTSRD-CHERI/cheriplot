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
Transformations for the provenance vertex layer.

These transformations mask, or merge vertices in the provenance layer
based on different properties such as origin and bounds.
"""

import logging

from cheriplot.provenance.visit import MaskBFSVisit, DecorateBFSVisit
from cheriplot.provenance.model import CheriNodeOrigin, EdgeOperation

logger = logging.getLogger(__name__)


class FilterNullVertices(MaskBFSVisit):
    """
    Generate a graph_view that masks all NULL capabilities.
    """

    description = "Mask NULL capabilities"

    def examine_vertex(self, u):
        self.progress.advance()
        if self.pgm.layer_prov[u]:
            data = self.pgm.data[u]
            if ((data.cap.length == 0 and data.cap.base == 0) or
                not data.cap.valid):
                self.vertex_mask[u] = False

class FilterKernelVertices(MaskBFSVisit):
    """
    Generate a graph_view that masks all kernel vertices and NULL capabilities.
    """

    description = "Mask Kernel capabilities"

    def examine_vertex(self, u):
        self.progress.advance()
        if self.pgm.layer_prov[u]:
            data = self.pgm.data[u]
            if data.pc != 0 and data.is_kernel:
                self.vertex_mask[u] = False


class FilterStackVertices(MaskBFSVisit):
    """
    Mask capabilities that point to the stack.
    """

    description = "Mask capabilities to stack objects"

    def __init__(self, pgm, stack_begin, stack_end):
        super().__init__(pgm)

        self.stack_begin = stack_begin
        self.stack_end = stack_end

    def examine_vertex(self, u):
        self.progress.advance()
        if not self.pgm.layer_prov[u]:
            return
        data = self.pgm.data[u]
        if data.cap.base >= self.stack_begin and data.cap.bound <= self.stack_end:
            self.vertex_mask[u] = False


class FilterCfromptr(MaskBFSVisit):
    """
    Transform that removes cfromptr vertices that are never stored
    in memory nor used for dereferencing.
    """

    description = "Filter temporary cfromptr"

    def examine_vertex(self, u):
        self.progress.advance()
        if not self.pgm.layer_prov[u]:
            return
        data = self.pgm.data[u]
        if data.origin == CheriNodeOrigin.FROMPTR:
            self.vertex_mask[u] = False
            # if (data.origin == CheriNodeOrigin.FROMPTR and
            #     len(data.address) == 0 and
            #     len(data.deref["load"]) == 0 and
            #     len(data.deref["load"]) == 0):
            #     # remove cfromptr that are never stored or used in
            #     # a dereference
            #     self.vertex_mask[u] = True


class FilterCandperm(MaskBFSVisit):
    """
    Transform that removes cfromptr vertices that are never stored
    in memory nor used for dereferencing.
    """

    description = "Filter candperm derived vertices"

    def examine_vertex(self, u):
        self.progress.advance()
        if not self.pgm.layer_prov[u]:
            return
        data = self.pgm.data[u]
        if data.origin == CheriNodeOrigin.ANDPERM:
            self.vertex_mask[u] = False


class FilterSyscallDerived(MaskBFSVisit):
    """
    Filter out all vertices derived from a system call.
    """
    pass


class DecorateStack(DecorateBFSVisit):
    """Mark capabilities that point to the stack."""

    description = "Mark capabilities to stack objects in a new vertex property"

    mask_name = "in_stack"
    mask_type = "bool"

    def __init__(self, pgm, stack_begin, stack_end):
        super().__init__(pgm)

        self.stack_begin = stack_begin
        self.stack_end = stack_end

    def examine_vertex(self, u):
        self.progress.advance()
        if not self.pgm.layer_prov[u]:
            return
        data = self.pgm.data[u]
        if (data.cap.base >= self.stack_begin and
            data.cap.bound <= self.stack_end):
            self.vertex_mask[u] = True


class DecorateMmap(DecorateBFSVisit):
    """Mark all mmap syscalls."""

    description = "Mark mmap syscalls"

    mask_name = "sys_mmap"
    mask_type = "bool"

    def _get_progress_range(self, graph):
        return (0, graph.num_edges())

    def examine_edge(self, e):
        self.progress.advance()
        src = e.source()
        dst = e.target()
        if (not self.pgm.layer_call[src] or
            not self.pgm.layer_call[dst]):
            return
        if (self.pgm.edge_operation[e] == EdgeOperation.SYSCALL and
            self.pgm.data[dst].address == 477):
            self.vertex_mask[dst] = True


class DecorateMmapReturn(DecorateBFSVisit):
    """
    Mark the capabilities that originate from an mmap syscall.
    All the children are also decorated.
    """

    description = "Mark capabilities originated from an mmap syscall"

    mask_name = "from_mmap"
    mask_type = "int64_t"
    mask_default = -1

    def _get_progress_range(self, graph):
        return (0, graph.num_edges())

    def examine_edge(self, e):
        self.progress.advance()
        src = e.source()
        dst = e.target()
        if self.pgm.layer_prov[src]:
            if (self.pgm.layer_call[dst] and
                self.pgm.edge_operation[e] == EdgeOperation.RETURN and
                self.pgm.graph.vp.sys_mmap[dst]):
                # src is the return value of a sys_mmap
                self.vertex_mask[src] = int(src)
            elif self.pgm.layer_prov[dst] and self.vertex_mask[src] >= 0:
                # src is mmap-derived
                self.vertex_mask[dst] = self.vertex_mask[src]


class DecorateMalloc(DecorateBFSVisit):
    """Mark all malloc calls."""

    description = "Mark malloc calls"

    mask_name = "call_malloc"
    mask_type = "bool"

    def _get_progress_range(self, graph):
        return (0, graph.num_edges())

    def examine_edge(self, e):
        self.progress.advance()
        src = e.source()
        dst = e.target()
        if (not self.pgm.layer_call[src] or
            not self.pgm.layer_call[dst]):
            return
        if (self.pgm.edge_operation[e] == EdgeOperation.CALL and
            self.pgm.data[dst].symbol and
            (self.pgm.data[dst].symbol == "__malloc" or
             self.pgm.data[dst].symbol == "__calloc" or
             self.pgm.data[dst].symbol == "malloc" or
             self.pgm.data[dst].symbol == "calloc")):
            self.vertex_mask[dst] = True


class DecorateMallocReturn(DecorateBFSVisit):
    """
    Mark the capabilities that originate from an mmap syscall.
    All the children are also decorated.
    """

    description = "Mark capabilities originated from an mmap syscall"

    mask_name = "from_malloc"
    mask_type = "int64_t"
    mask_default = -1

    def _get_progress_range(self, graph):
        return (0, graph.num_edges())

    def examine_edge(self, e):
        self.progress.advance()
        src = e.source()
        dst = e.target()
        if self.pgm.layer_prov[src]:
            if (self.pgm.layer_call[dst] and
                self.pgm.edge_operation[e] == EdgeOperation.RETURN and
                self.pgm.graph.vp.call_malloc[dst]):
                # src is the return value of a malloc
                self.vertex_mask[src] = int(src)
            elif self.pgm.layer_prov[dst] and self.vertex_mask[src] >= 0:
                # src is mmap-derived
                self.vertex_mask[dst] = self.vertex_mask[src]
