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
from sortedcontainers import SortedDict
from elftools.elf.elffile import ELFFile

from cheriplot.provenance.visit import MaskBFSVisit, DecorateBFSVisit, BFSGraphVisit
from cheriplot.provenance.model import CheriNodeOrigin, EdgeOperation, ProvenanceVertexData, CheriCapPerm

logger = logging.getLogger(__name__)


class FindLastExecve(BFSGraphVisit):
    """
    Find last execve call, presumibly from qtrace.
    """

    description = "Find last execve"

    execve_code = 0x3b

    def __init__(self, pgm):
        super().__init__(pgm)

        self.last_execve = -1
        self.execve_vertex = -1
        self.execve_call = -1
        self.execve_return = -1

    def _get_progress_range(self, graph):
        return (0, graph.num_edges())

    def examine_edge(self, e):
        self.progress.advance()
        src = e.source()
        dst = e.target()
        if (self.pgm.layer_call[src] and self.pgm.layer_call[dst] and
            self.pgm.edge_operation[e] == EdgeOperation.SYSCALL):
            data = self.pgm.data[dst]
            if data.address == self.execve_code and data.t_return > self.last_execve:
                self.last_execve = self.pgm.edge_time[e]
                logger.info("Found execve syscall [%d, %d]",
                            self.last_execve, data.t_return)
                self.execve_call = self.last_execve
                self.execve_return = data.t_return
                self.execve_vertex = int(dst)

    def finalize(self, graph_view):
        # save the execve information in graph properties for later use
        execve_vertex = self.pgm.graph.new_graph_property(
            "long", int(self.execve_vertex))
        execve_call = self.pgm.graph.new_graph_property(
            "long", self.execve_call)
        execve_return = self.pgm.graph.new_graph_property(
            "long", self.execve_return)
        self.pgm.graph.gp["execve_vertex"] = execve_vertex
        self.pgm.graph.gp["execve_call"] = execve_call
        self.pgm.graph.gp["execve_return"] = execve_return
        logger.info("Last execve syscall [%d, %d]",
                    self.execve_call, self.execve_return)
        return graph_view


class FilterBeforeExecve(MaskBFSVisit):
    """
    Remova all vertices that come before the last call to execve.
    This assumes that the program does not execve.

    Depends on FindLastExecve.
    """

    description = "Mask pre-execve capabilities"

    def __init__(self, pgm):
        super().__init__(pgm)

        self.execve_time = None

    def _get_progress_range(self, graph):
        return (0, graph.num_edges())

    def examine_edge(self, e):
        self.progress.advance()
        src = e.source()
        dst = e.target()
        if self.pgm.layer_call[src] and self.pgm.layer_call[dst]:
            execve_time = self.pgm.graph.gp.execve_call
            # call or syscall
            if self.pgm.edge_time[e] < execve_time:
                self.vertex_mask[src] = False
                self.vertex_mask[dst] = False

    def examine_vertex(self, v):
        if self.pgm.layer_prov[v]:
            execve_time = self.pgm.graph.gp.execve_call
            if self.pgm.data[v].cap.t_alloc < execve_time:
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


class DetectStackCapability(BFSGraphVisit):
    """
    Find the stack capability by looking for a root capability
    in a stack-like location before the last return from execve.

    The stack capability vertex index is stored in the graph
    stack_vertex property.

    Depends on FindLastExecve
    """

    description = "Detect stack capability"

    def __init__(self, pgm):
        super().__init__(pgm)

        stack_vertex = pgm.graph.new_graph_property("int", val=-1)
        pgm.graph.gp["stack_vertex"] = stack_vertex

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
            execve_start = self.pgm.graph.gp.execve_call
            execve_end = self.pgm.graph.gp.execve_return
            data = self.pgm.data[v]
            if (data.cap.t_alloc >= execve_start and
                data.cap.t_alloc <= execve_end and
                self.is_stack_root(v)):
                logger.info("Set stack root vertex %d", v)
                self.pgm.graph.gp.stack_vertex = int(v)


class DecorateKernelCapabilities(DecorateBFSVisit):
    """
    Find capabilities that originate from the kernel but are
    visible in registers from userspace when returning from eret.
    """

    description = "Detect kernel-originated capabilities"

    mask_name = "annotated_korigin"
    mask_type = "bool"

    def __init__(self, pgm):
        super().__init__(pgm)

    def examine_edge(self, e):
        pass


class DecorateAccessdInUserspace(DecorateBFSVisit):
    """
    Detect capabilities that are accessed from code in user space.
    XXX-AM: this needs more support from the tracing and more thinkering
    because we want to see whether the capability ever floats to userspace,
    meaning it is used or even visible from there.
    """

    description = ""


class DecorateGlobalPointers(DecorateBFSVisit):
    """
    Find pointers that are loaded or stored in a cap table.
    This also marks the descendants of these pointers.
    """

    description = "Find pointers to global objects"

    mask_name = "annotated_globptr"
    mask_type = "bool"

    def __init__(self, pgm, symreader):
        super().__init__(pgm)

        self.symreader = symreader

        self._captable_mappings = SortedDict()
        """Hold capability table mappings as start => (end, file)"""

        self.captblptr = self.pgm.graph.new_vertex_property("bool", val=False)
        self.pgm.graph.vp["annotated_captblptr"] = self.captblptr

        self.globderived = self.pgm.graph.new_vertex_property("bool", val=False)
        self.pgm.graph.vp["annotated_globderived"] = self.globderived

        self._fetch_cap_tables()

    def _fetch_cap_tables(self):
        for path in self.symreader.loaded:
            elf = ELFFile(open(path, "rb"))
            if elf.header["e_type"] == "ET_DYN":
                map_base = self.symreader.map_base(path)
            else:
                map_base = 0
            # grab section with given name
            captable = elf.get_section_by_name(".cap_table")
            if captable is None:
                logger.info("No capability table for %s", path)
                continue
            sec_start = captable["sh_addr"] + map_base
            sec_end = sec_start + captable["sh_size"]
            logger.info("Found capability table %s @ [0x%x, 0x%x]",
                        path, sec_start, sec_end)
            self._captable_mappings[sec_start] = {"end": sec_end, "path": path}

    def _get_captable(self, addr):
        index = self._captable_mappings.bisect(addr) - 1
        if index < 0:
            return None
        key = self._captable_mappings.iloc[index]
        if addr > self._captable_mappings[key]["end"]:
            return None
        return self._captable_mappings[key]["path"]

    def examine_vertex(self, v):
        self.progress.advance()
        if not self.pgm.layer_prov[v]:
            return
        data = self.pgm.data[v]
        # has this vertex ever been stored/loaded in the cap table?
        mask = ((data.event_tbl["type"] == ProvenanceVertexData.EventType.LOAD) |
                (data.event_tbl["type"] == ProvenanceVertexData.EventType.STORE))
        for idx, evt in data.event_tbl[mask].iterrows():
            if self._get_captable(evt["addr"]) is not None:
                self.vertex_mask[v] = True
                # we just need to see one dereference for it
                # to be a global ptr
                break
        # has this vertex ever loaded/stored something in the cap table?
        load_type = (ProvenanceVertexData.EventType.DEREF_LOAD |
                     ProvenanceVertexData.EventType.DEREF_IS_CAP)
        store_type = (ProvenanceVertexData.EventType.DEREF_STORE |
                      ProvenanceVertexData.EventType.DEREF_IS_CAP)
        mask = ((data.event_tbl["type"] == load_type) |
                (data.event_tbl["type"] == store_type))
        for idx, evt in data.event_tbl[mask].iterrows():
            if self._get_captable(evt["addr"]) is not None:
                self.captblptr[v] = True
                # we just need to see one dereference for it
                # to be a pointer to captable
                break

    def examine_edge(self, e):
        # check if the dst is global-derived
        src = e.source()
        tgt = e.target()
        if self.pgm.layer_prov[src] and self.pgm.layer_prov[tgt]:
            if self.vertex_mask[src] or self.globderived[src]:
                self.globderived[tgt] = True


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
