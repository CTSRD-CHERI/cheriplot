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

from cached_property import cached_property

from cheriplot.provenance.visit import MaskBFSVisit, DecorateBFSVisit, BFSGraphVisit
from cheriplot.provenance.model import CheriNodeOrigin, EdgeOperation, ProvenanceVertexData, CheriCapPerm

logger = logging.getLogger(__name__)


class FilterBeforeExecve(MaskBFSVisit):
    """
    Remova all vertices that come before the last call to execve.
    This assumes that the program does not execve.
    """

    description = "Mask pre-execve capabilities"

    def __init__(self, pgm):
        super().__init__(pgm)
        self.execve_time = self.find_last()

    def _get_progress_range(self, graph):
        return (0, graph.num_edges())

    def find_last(self):
        """
        Find last SYSCALL to execve
        """
        execve_code = 0x3b
        last_syscall = 0
        for e in self.pgm.graph.edges():
            src = e.source()
            dst = e.target()
            if self.pgm.edge_operation[e] == EdgeOperation.SYSCALL:
                data = self.pgm.data[dst]
                if data.address == execve_code and data.t_return > last_syscall:
                    logger.info("Found execve syscall, returning at %d",
                                data.t_return)
                    last_syscall = self.pgm.edge_time[e]
        logger.info("Execve call set at %d", last_syscall)
        return last_syscall

    def examine_edge(self, e):
        self.progress.advance()
        src = e.source()
        dst = e.target()
        if self.pgm.layer_call[src] and self.pgm.layer_call[dst]:
            # call or syscall
            if self.pgm.edge_time[e] < self.execve_time:
                self.vertex_mask[src] = False
                self.vertex_mask[dst] = False

    def examine_vertex(self, v):
        if self.pgm.layer_prov[v]:
            if self.pgm.data[v].cap.t_alloc < self.execve_time:
                self.vertex_mask[v] = False


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


class FilterRootVertices(MaskBFSVisit):
    """
    Transform that removes root vertices.
    """

    description = "Filter root vertices"

    def examine_vertex(self, u):
        self.progress.advance()
        if not self.pgm.layer_prov[u]:
            return
        data = self.pgm.data[u]
        if (data.origin == CheriNodeOrigin.ROOT or
            data.origin == CheriNodeOrigin.INITIAL_ROOT):
            self.vertex_mask[u] = False


class FilterSyscallDerived(MaskBFSVisit):
    """
    Filter out all vertices derived from a system call.
    """
    pass

class DetectStackCapability(BFSGraphVisit):
    """
    Find the stack capability by looking for a root capability
    in a stack-like location before the last return from execve.

    The stack capability vertex index is stored in the graph
    stack_vertex property.
    """

    description = "Detect stack capability"

    def __init__(self, pgm):
        super().__init__(pgm)
        self.execve_start = None
        """Last execve call time"""

        self.execve_end = None
        """Last execve return time"""

        stack_vertex = pgm.graph.new_graph_property("int", val=-1)
        pgm.graph.gp["stack_vertex"] = stack_vertex

        self.find_execve()

    def find_execve(self):
        """
        Find last SYSCALL to execve
        """
        execve_code = 0x3b
        last_vertex = None
        last_call = 0
        last_return = 0
        for e in self.pgm.graph.edges():
            src = e.source()
            dst = e.target()
            if self.pgm.edge_operation[e] == EdgeOperation.SYSCALL:
                data = self.pgm.data[dst]
                if data.address == execve_code:
                    # check if this is later than the last
                    if last_vertex is None or data.t_return > last_return:
                        logger.info("Found execve syscall, returning at %d",
                                    data.t_return)
                        last_vertex = dst
                        last_call = self.pgm.edge_time[e]
                        last_return = data.t_return
        self.execve_start = last_call
        self.execve_end = last_return
        logger.info("Last execve at call:%d return:%d", last_call, last_return)

    def check_parent(self, v):
        for e in v.in_edges():
            parent = e.source()
            if self.pgm.layer_prov[parent]:
                if int(parent) == self.pgm.graph.gp.stack_vertex:
                    return True
                else:
                    return self.check_parent(parent)
        return False

    def is_stack_root(self, v):
        """
        Check whether the given vertex is the expected root for the stack.
        """
        data = self.pgm.data[v]
        if (data.cap.base >= 0x7fff000000 and
            data.cap.base < 0x8000000000 and
            data.cap.length >= 0x80000):
            # possibly a root, check if it has ancestors that are already marked
            if not self.check_parent(v):
                logger.info("Guessing stack root at %s", data)
                return True
        return False

    def examine_vertex(self, v):
        if self.pgm.layer_prov[v]:
            data = self.pgm.data[v]
            if (data.cap.t_alloc >= self.execve_start and
                data.cap.t_alloc <= self.execve_end and
                self.is_stack_root(v)):
                logger.info("Set stack root vertex %d", v)
                self.pgm.graph.gp.stack_vertex = int(v)


class DecorateStackStrict(DecorateBFSVisit):
    """
    Mark capabilities that point to the stack.
    This marks all successors of the stack capability(es).
    """

    description = "Mark capabilities derived from the user stack "\
                  "capability in a new vertex property"

    mask_name = "annotated_usr_stack"
    mask_type = "bool"

    def __init__(self, pgm, stack_begin, stack_end):
        super().__init__(pgm)

        self.stack_begin = stack_begin
        self.stack_end = stack_end

    def _get_progress_range(self, graph):
        return (0, graph.num_edges())

    def is_stack_root(self, src):
        """
        Check whether the given vertex is the expected root for the stack.
        """
        if (self.pgm.data[src].cap.base >= 0x7fff000000 and
            self.pgm.data[src].cap.base < 0x8000000000 and
            self.pgm.data[src].cap.length >= 0x80000 and
            self.vertex_mask[src] == False):
            logger.info("Guessing stack root at %s", self.pgm.data[src])
            return True
        return False

    @cached_property
    def _has_stack_vertex(self):
        # called on the first vertex, so we also set the first masked vertex
        has_stack = ("stack_vertex" in self.pgm.graph.gp and
                     self.pgm.graph.gp.stack_vertex >= 0)
        if has_stack:
            v = self.pgm.graph.gp.stack_vertex
            logger.info("Decorate stack found stack capability at vertex %d %s",
                        v, self.pgm.data[v])
            self.vertex_mask[v] = True
        else:
            logger.info("No stack capability found (%s), guessing",
                        self.pgm.graph.gp.get("stack_vertex", None))
        return has_stack

    def examine_vertex(self, v):
        if not self.pgm.layer_prov[v] or self._has_stack_vertex:
            # disable automatic guessing of stack roots if we have
            # a stack root detected in the graph properties
            return
        if self.is_stack_root(v):
            logger.debug("Mark NEW stack root %s", self.pgm.data[v])
            self.vertex_mask[v] = True

    def examine_edge(self, e):
        self.progress.advance()
        src = e.source()
        dst = e.target()
        if self.pgm.layer_prov[src] and self.pgm.layer_prov[dst]:
            logger.debug("Edge %s -> %s", self.pgm.data[src], self.pgm.data[dst])
            if self.vertex_mask[src]:
                self.vertex_mask[dst] = True


class DecorateStackAll(DecorateBFSVisit):
    """
    Mark capabilities that point to the stack.
    This marks all capabilities that land in the stack capability but are
    not necessarily successors of the stack pointer.
    This includes kernel pointers to the user stack region.
    """

    description = "Mark capabilities to stack objects in a new vertex property"

    mask_name = "annotated_stack"
    mask_type = "bool"

    def __init__(self, pgm, stack_begin, stack_end):
        super().__init__(pgm)

        self.stack_begin = stack_begin
        self.stack_end = stack_end

    def examine_vertex(self, v):
        if not self.pgm.layer_prov[v]:
            return
        data = self.pgm.data[v]
        if (data.cap.base >= self.stack_begin and
            data.cap.bound <= self.stack_end):
            self.vertex_mask[v] = True


class DecorateMalloc(DecorateBFSVisit):
    """
    Mark capabilities that are returned from malloc or are descendants
    descendants of those.
    """

    description = "Mark capabilities to malloc-returned objects"
    mask_name = "annotated_malloc"
    mask_type = "bool"

    def __init__(self, pgm):
        super().__init__(pgm)

    def examine_vertex(self, v):
        self.progress.advance()
        if self.pgm.layer_prov[v]:
            # find call vertices that link to this
            for eout in v.out_edges():
                dst = eout.target()
                if (self.pgm.layer_call[dst] and
                    self.pgm.edge_operation[eout] == EdgeOperation.RETURN):
                    data = self.pgm.data[dst]
                    if data.symbol and (
                            data.symbol == "__malloc" or
                            data.symbol == "__calloc" or
                            data.symbol == "__je_malloc" or
                            data.symbol == "__je_calloc" or
                            data.symbol == "malloc" or
                            data.symbol == "calloc"):
                        self.vertex_mask[v] = True

    def examine_edge(self, e):
        src = e.source()
        dst = e.target()
        if self.pgm.layer_prov[src] and self.pgm.layer_prov[dst]:
            logger.debug("Edge %s -> %s", self.pgm.data[src], self.pgm.data[dst])
            if self.vertex_mask[src]:
                self.vertex_mask[dst] = True


class DecorateExecutable(DecorateBFSVisit):
    """
    Mark executable capabilities, non-executable capabilities are
    implicitly marked as well since annotated_exec is set to False
    for those.
    """

    description = "Mark executable capabilities"
    mask_name = "annotated_exec"
    mask_type = "bool"

    def __init__(self, pgm):
        super().__init__(pgm)

    def examine_vertex(self, v):
        self.progress.advance()
        if self.pgm.layer_prov[v]:
            data = self.pgm.data[v]
            if data.cap.has_perm(CheriCapPerm.EXEC):
                self.vertex_mask[v] = True


class DecorateHeap(DecorateBFSVisit):
    """Mark capabilities that point to the stack."""

    description = "Mark capabilities to malloc objects in a new vertex property"

    mask_name = "in_jemalloc"
    mask_type = "bool"

    def __init__(self, pgm, heap_begin, heap_end):
        super().__init__(pgm)

        self.heap_begin = heap_begin
        self.heap_end = heap_end

    def examine_vertex(self, u):
        self.progress.advance()
        if not self.pgm.layer_prov[u]:
            return
        data = self.pgm.data[u]
        if (data.cap.base >= self.heap_begin and
            data.cap.bound <= self.heap_end):
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


class DecorateMalloc_Deprecated(DecorateBFSVisit):
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
