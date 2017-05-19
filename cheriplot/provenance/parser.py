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

import numpy as np
import logging
import os

from enum import IntEnum
from functools import reduce
from graph_tool.all import Graph, load_graph

from cheriplot.core import (
    CallbackTraceParser, ProgressTimer, MultiprocessCallbackParser)
from cheriplot.provenance.model import *
from cheriplot.provenance.transforms import bfs_transform, BFSTransform

logger = logging.getLogger(__name__)

__all__ = ("PointerProvenanceParser", "MissingParentError",
           "DereferenceUnknownCapabilityError")

class SubgraphMergeError(RuntimeError):
    """
    Exception raised when there is an error during the merge
    of partial results from multiprocessing workers.
    """
    pass


class MissingParentError(RuntimeError):
    """
    Exception raised when attempting to create a provenance node but a
    valid parent is not found.
    This is a fatal error condition.
    """
    pass


class DereferenceUnknownCapabilityError(RuntimeError):
    """
    Exception raised when a capability dereference is found
    but it is not possible to determine the corresponding
    vertex in the graph where the dereference should be registered.
    This happens when a previously unseen capability register is
    dereferenced or in case of bugs in the vertex propagation in
    the register set.
    This is a fatal error condition.
    """
    pass


class UnexpectedOperationError(RuntimeError):
    """
    Exception raised when a seemingly impossible operation
    occurred.
    This is a fatal error condition.
    """
    pass


class SyscallContext:
    """
    Keeps the current syscall context information so that
    the correct return point can be detected.

    This class contains all the methods that manipulate
    registers and values that depend on the ABI and constants
    in CheriBSD.
    """
    class SyscallCode(IntEnum):
        """
        Enumerate system call numbers that are recognised by the
        parser and are used to add information to the provenance
        graph.
        """
        SYS_MMAP = 477
        SYS_MUNMAP = 73
        # also interesting mprotect and shm* stuff


    def __init__(self, *args, **kwargs):
        self.in_syscall = False
        """Flag indicates whether we are tracking a systemcall."""

        self.pc_syscall = None
        """Syscall instruction PC."""

        self.t_syscall = None
        """Syscall instruction cycle number."""

        self.pc_eret = None
        """Expected eret instruction PC."""

        self.code = None
        """Current syscall code."""

    def _get_syscall_code(self, regs):
        """Get the syscall code for direct and indirect syscalls."""
        # syscall code in $v0
        # syscall arguments in $a0-$a7/$c3-$c10
        code = regs.gpr[1] # $v0
        indirect_code = regs.gpr[3] # $a0
        is_indirect = (code == 0 or code == 198)
        return indirect_code if is_indirect else code

    def scan_syscall_start(self, inst, entry, regs, dataset, regset):
        """
        Scan a syscall instruction and detect the syscall type
        and arguments.
        """
        code = self._get_syscall_code(regs)
        try:
            self.code = self.SyscallCode(code)
        except ValueError:
            # we are not interested in this syscall
            return
        self.in_syscall = True
        self.pc_syscall = entry.pc
        self.t_syscall = entry.cycles
        self.pc_eret = entry.pc + 4

        # create a node at syscall start for those system calls for
        # which we care about the arguments
        if self.code.value == self.SyscallCode.SYS_MUNMAP:
            src_reg = 3 # argument in $c3
            origin = CheriNodeOrigin.SYS_MUNMAP
        else:
            # we do not do anything for other syscalls
            return None

        data = NodeData()
        data.cap = CheriCap(regs.cap_reg[src_reg])
        data.cap.t_alloc = entry.cycles
        # XXX may want a way to store call pc and return pc
        data.pc = entry.pc
        data.origin = origin
        data.is_kernel = False
        node = dataset.add_vertex()
        dataset.vp.data[node] = data
        # attach the new node to the capability node in src_reg
        # and replace it in the register set
        parent = regset[src_reg]
        dataset.add_edge(parent, node)
        regset[src_reg] = node
        return node

    def scan_syscall_end(self, inst, entry, regs, dataset, regset):
        """
        Scan registers to produce a syscall end node.
        """
        self.in_syscall = False

        # create a node for the syscall start
        if self.code.value == self.SyscallCode.SYS_MMAP:
            ret_reg = 3 # return in $c3
            origin = CheriNodeOrigin.SYS_MMAP
        else:
            # we do not do anything for other syscalls
            return None

        data = NodeData()
        data.cap = CheriCap(regs.cap_reg[ret_reg])
        data.cap.t_alloc = entry.cycles
        # XXX may want a way to store call pc and return pc
        data.pc = entry.pc
        data.origin = origin
        data.is_kernel = False
        node = dataset.add_vertex()
        dataset.vp.data[node] = data
        # attach the new node to the capability node in ret_reg
        # and replace it in the register set
        parent = regset[ret_reg]
        dataset.add_edge(parent, node)
        regset[ret_reg] = node
        return node


class VertexMemoryMap:
    """
    Helper object that keeps track of the graph vertex associated
    with each memory location used in the trace.
    """

    def __init__(self, graph):
        self.vertex_map = {}
        self.graph = graph

    def __getstate__(self):
        """
        Make object pickle-able, the graph-tool vertices index are used
        instead of the vertex object.
        """
        logger.debug("Pickling partial result vertex-memory map %d",
                     os.getpid())
        state = {
            "vertex_map": {k: int(v) for k,v in self.vertex_map.items()}
        }
        return state

    def __setstate__(self, data):
        """
        Make object pickle-able, the graph-tool vertices index are used
        instead of the vertex object.
        """
        logger.debug("Unpickling partial result vertex-memory map")
        self.vertex_map = data["vertex_map"]

    def clear(self, addr):
        """
        Unregister the vertex associated with the given memory location
        """
        del self.vertex_map[addr]

    def mem_load(self, addr, vertex=None):
        """
        Register a memory load at given address and return
        the vertex for that address if any.
        If a vertex is specified, the vertex is set
        in the memory map at the given address.
        """
        if vertex:
            self.vertex_map[addr] = vertex
        try:
            return self.vertex_map[addr]
        except KeyError:
            return None

    def mem_store(self, addr, vertex):
        """
        Register a memory store at given address and
        store the vertex in the memory map for the given
        address.
        """
        self.vertex_map[addr] = vertex


class MPVertexMemoryMap(VertexMemoryMap):
    """
    Vertex map used by multiprocessing workers to record the
    initial state of the map so that the initial vertices can
    be merged with the results from other workers.
    """

    def __init__(self, graph):
        super().__init__(graph)

        self.initial_map = {}

    def __getstate__(self):
        state = super().__getstate__()
        state["initial_map"] = {k: int(v) for k,v in self.initial_map.items()}
        return state

    def __setstate__(self, data):
        super().__setstate__(data)
        self.initial_map = data["initial_map"]

    def mem_load(self, addr, vertex=None):
        if vertex and addr not in self.initial_map:
            self.initial_map[addr] = vertex
        return super().mem_load(addr, vertex)


class RegisterSet:
    """
    Helper object that keeps track of the graph vertex associated
    with each register in the register file.

    We need to know where a register value has been read from
    and where it is stored to. The first is used to infer
    the correct CapNode to add as parent for a new node,
    the latter allows us to set the CapNode.address for
    a newly allocated capability.

    The register set is also used in the subgraph merge
    resolution to produce the full graph from partial
    results from worker processes.
    """

    def __init__(self, graph):
        self.reg_nodes = [None] * 32
        """Graph node associated with each register."""

        self._pcc = None
        """Current pcc node"""

        self.graph = graph
        """The provenance graph"""

    def __getstate__(self):
        """
        Make object pickle-able, graph-tool vertices are not pickleable
        but their index is.
        """
        logger.debug("Pickling partial result register set %d", os.getpid())
        state = {
            "reg_nodes": [self.graph.vertex_index[u] if u != None else None
                          for u in self.reg_nodes],
            "_pcc": (self.graph.vertex_index[self._pcc]
                     if self._pcc != None else None),
            }
        return state

    def __setstate__(self, data):
        """
        Make object pickle-able.

        Restore internal state. Note that this does not recover the vertex
        instances from the graph as we do not require this when propagating
        partial results from the workers.
        XXX Doing so saves some time although it may be desirable to
        perform the operation to avoid confusion.
        Note also that the graph is dropped, this is to avoid pickling the
        graph twice.
        """
        logger.debug("Unpickling partial result register set")
        self.reg_nodes = data["reg_nodes"]
        self._pcc = data["_pcc"]

    def _attach_subgraph_merge(self, regset_vertex, input_vertex):
        """
        If needed, attach a graph vertex to a
        partial-vertex marker in the register set

        :param regset_vertex: the vertex currently contained in the
        register set
        :param input_vertex: the vertex that is being assigned
        """
        # if the node is a root and we have a PARTIAL dummy node in the register
        # set and the node is not already attached to a PARTIAL dummy node,
        # the root is attached to the dummy.
        if input_vertex == None or regset_vertex == None:
            return

        in_data = self.graph.vp.data[input_vertex]
        if in_data.origin == CheriNodeOrigin.ROOT:
            for n in input_vertex.in_neighbours():
                if self.graph.vp.data[n].origin == CheriNodeOrigin.PARTIAL:
                    return
            curr_data = self.graph.vp.data[regset_vertex]
            if curr_data.origin == CheriNodeOrigin.PARTIAL:
                self.graph.add_edge(regset_vertex, input_vertex)

    @property
    def pcc(self):
        return self._pcc

    @pcc.setter
    def pcc(self, value):
        self._attach_subgraph_merge(self._pcc, value)
        self._pcc = value

    def has_pcc(self, allow_root=False):
        """
        Check if the register set contains a valid pcc

        :param idx: the register index to check
        :param allow_root: a root can be created if the register
        does not have a valid node.
        """
        if self.pcc == None:
            return False
        if allow_root:
            data = self.graph.vp.data[self.pcc]
            if data.origin == CheriNodeOrigin.PARTIAL:
                return False
        return True

    def has_reg(self, idx, allow_root=False):
        """
        Check if the register set contains a valid entry for
        the given register index

        :param idx: the register index to check
        :param allow_root: a root can be created if the register
        does not have a valid node.
        """
        assert idx < 32, "Out of bound register set index"
        if self[idx] == None:
            return False
        if allow_root:
            data = self.graph.vp.data[self[idx]]
            if data.origin == CheriNodeOrigin.PARTIAL:
                return False
        return True

    def __getitem__(self, idx):
        """
        Fetch the :class:`cheriplot.core.provenance.GraphNode`
        currently associated to a capability register with the
        given register number.
        """
        assert idx < 32, "Out of bound register set fetch"
        return self.reg_nodes[idx]

    def __setitem__(self, idx, val):
        """
        Fetch the :class:`cheriplot.core.provenance.GraphNode`
        currently associated to a capability register with the
        given register number.
        """
        assert idx < 32, "Out of bound register set assignment"
        # if the current value of the register set is short-lived
        # (never stored anywhere and not in any other regset node)
        # then it is effectively lost and "deallocated"
        # if self.reg_nodes[idx] is not None:
        #     n_refs = np.count_nonzero(self.reg_nodes == self.reg_nodes[idx])
        #     node_data = self.graph.vp.data[self.reg_nodes[idx]]
        #     # XXX may refine this by checking the memory_map to see if the
        #     # node is still there
        #     n_refs += len(node_data.address)
        #     if n_refs == 1:
        #         # can safely set the t_free
        #         disable because we need a way to actually get the current cycle
        self._attach_subgraph_merge(self.reg_nodes[idx], val)
        self.reg_nodes[idx] = val


class MergePartialSubgraph(BFSTransform):
    """
    Merge a partial subgraph into the main graph.

    This is used to merge partial results from
    multiprocessing workers that parse the
    provenance graph.

    The transform must be run on the subgraph that is
    should be merged.
    """

    def __init__(self, graph, subgraph, initial_regset, final_regset,
                 previous_regset, vertex_map, previous_vmap):

        self.graph = graph
        """Merged graph that we are building"""

        self.subgraph = subgraph
        """Subgraph to be merged"""

        self.initial_regset = initial_regset
        """
        Regset mapping initial register state to vertices in the
        subgraph.

        Note: the register set contains vertex handles for the subgraph.
        """

        self.final_regset = final_regset
        """
        Regset mapping the final register state of the worker to the
        vertices in the merged graph. This is generated from the final
        regset given to the transform, which contains vertex handles for
        the subgraph.
        """

        self.previous_regset = previous_regset
        """
        Regset mapping the final state of the registers of the last merged
        subgraph to vertices in the merged graph.

        Note: the register set contains vertex handles for the merged graph.
        """

        self.vertex_map = vertex_map
        """
        VertexMemoryMap with the initial and final state of graph
        vertices in memory after the subgraph has been parsed.

        Note: the map contains vertex handles from the subgraph.
        """

        self.previous_vmap = previous_vmap
        """
        VertexMemoryMap with the final state of graph vertices in memory
        from the previous subgraph merge step.

        Note: the map contains vertex handles from the merged graph.
        """

        self.copy_vertex_map = subgraph.new_vertex_property("long", val=-1)
        """
        Map vertex index in the subgraph to a vertex index in the
        merged graph.
        """

        self.omit_vertex_map = subgraph.new_vertex_property("bool", val=False)
        """
        Mark vertices in the subgraph that should be ignored when moving
        to the merged graph.
        """

    def get_final_regset(self):
        """
        Return the register set mapping the final state of the worker
        partial graph to vertices in the merged graph (that have been
        generated during this merge step).
        This is used as input to the next merge operation as previous_regset.
        """
        regset = RegisterSet(None)
        for idx in range(len(self.final_regset.reg_nodes)):
            v = self.final_regset[idx]
            if v == None or self.copy_vertex_map[v] < 0:
                regset.reg_nodes[idx] = None
            else:
                regset.reg_nodes[idx] = self.copy_vertex_map[v]

        v_pcc = self.final_regset.pcc
        regset.pcc = self.copy_vertex_map[v_pcc] if v_pcc != None else None
        # regset.memory_map = self.final_regset.memory_map
        return regset

    def get_final_vmap(self):
        """
        Return the vertex-memory-map containing the final state of
        the worker partial graph expressed with vertices in the merged graph
        (that have been generated during this merge step).
        This is used as input to the next merge operation as previous_vmap.
        """
        vmap = VertexMemoryMap(None)
        for key,u in self.vertex_map.vertex_map.items():
            if self.copy_vertex_map[u] >= 0:
                # valid vertex handle
                vmap.vertex_map[key] = self.copy_vertex_map[u]
        return vmap

    def _merge_partial_vertex_data(self, u_data, v_data):
        """
        Copy dereferences and stores from a subgraph dummy vertex
        to a vertex in the merged graph.

        :param u_data: the source vertex data
        :param v_data: the destination vertex data
        """
        v_data.address.update(u_data.address)
        for key, val in u_data.deref.items():
            v_data.deref[key].extend(val)

    def _merge_initial_vertex(self, u):
        """
        Merge a vertex that is contained in the initial register set.
        In this case u is a dummy vertex used only for marking.
        """
        # case (1) (2) in examine_vertex.
        # Do not add the dummy vertex to the copy_vertex_map
        # so the edges PARTIAL -> ROOT are not moved and
        # only ROOT vertices are moved normally when they are
        # found in case (3) of examine_vertex.
        if u in self.initial_regset.reg_nodes:
            index = self.initial_regset.reg_nodes.index(u)
            v = self.previous_regset[index]
        else:
            index = "pcc"
            v = self.previous_regset.pcc
        logger.debug("Merge initial vertex (register %s)", index)

        if v is None:
            self._merge_initial_vertex_to_none(u)
        else:
            self._merge_initial_vertex_to_prev(u, v)

    def _merge_initial_mem_vertex(self, u):
        """
        Merge a vertex that is contained in the initial vertex
        memory map of a worker.
        """
        u_addr = None
        for key,val in self.vertex_map.initial_map.items():
            if val == u:
                u_addr = key
                break
        try:
            v = self.previous_vmap.vertex_map[u_addr]
            u_data = self.subgraph.vp.data[u]
            v_data = self.graph.vp.data[v]
            if (u_data.cap.base != v_data.cap.base or
                u_data.cap.length != v_data.cap.length):
                # this is an error, the worker found something inconsistent
                # in the trace for this memory address.
                raise SubgraphMergeError(
                    "Incompatible vertex in prev_vmap at address 0x%x,"
                    " curr:%s prev:%s" % (u_addr, u_data, v_data))
            else:
                # the root can be merged with the prev_vmap content
                self.copy_vertex_map[u] = v
                if u_data.origin == CheriNodeOrigin.ROOT:
                    # if the vertex is root, remove the store address
                    # assigned in the root (it is always the one with lower
                    # key (i.e. time) value) because it does not really
                    # express a store but the fact that the root has been
                    # found there for the first time. (indeed the capability
                    # was at that address)
                    u_data.address.popitem()
                self._merge_partial_vertex_data(u_data, v_data)
        except KeyError:
            # otherwise merge the root vertex normally
            logger.debug("Root vertex found in merged vertex map: %s", u)
            self._merge_subgraph_vertex(u)

    def _merge_initial_vertex_to_none(self, u):
        """
        Merge an initial vertex that have no parent in
        the previous regset.
        """
        # case (1) in examine_vertex
        # The dummy vertex must not have been dereferenced,
        # because this counts as an empty register now.
        # it can have been stored, it is just storing None.
        u_data = self.subgraph.vp.data[u]
        if len(u_data.deref["time"]):
            raise SubgraphMergeError("PARTIAL vertex was dereferenced "
                                     "but is merged to None")
        logger.debug("initial vertex prev graph:None")
        for u_out in u.out_neighbours():
            u_out_data = self.subgraph.vp.data[u_out]
            if u_out_data.origin != CheriNodeOrigin.ROOT:
                raise MissingParentError(
                    "Missing parent for %s" % u_out_data)

    def _merge_initial_vertex_to_prev(self, u, v):
        """
        Merge an initial vertex that have an existing parent
        in the previous regset.
        """
        # case (2) of examine_vertex
        # propagate PARTIAL metadata to the parent.
        # remove ROOT children since the ROOT should not
        # have been created.
        u_data = self.subgraph.vp.data[u]
        logger.debug("initial vertex prev graph:%s", v)
        self.copy_vertex_map[u] = v
        v_data = self.graph.vp.data[v]
        self._merge_partial_vertex_data(u_data, v_data)
        for u_out in u.out_neighbours():
            logger.debug("initial vertex out-neighbour subgraph:%s",
                         u_out)
            # check that v_data agrees with all roots
            # that will be suppressed
            u_out_data = self.subgraph.vp.data[u_out]
            if u_out_data.origin == CheriNodeOrigin.ROOT:
                # suppress u_out but attach its children to
                # the dummy so the connectivity is preserved
                # so all dereferences and stores of u_out are merged in the
                # parent
                if len(list(u_out.in_neighbours())) != 1:
                    raise SubgraphMergeError(
                        "ROOT attached to multiple partial nodes")
                self._merge_partial_vertex_data(u_out_data, v_data)
                if (u_out_data.cap.base != v_data.cap.base or
                    u_out_data.cap.length != v_data.cap.length):
                    logger.debug("do not suppress ROOT %s, previous "
                                 "regset does not have matching "
                                 "bounds %s", u_out_data, v_data)
                else:
                    self.omit_vertex_map[u_out] = True
                    for w in u_out.out_neighbours():
                        self.subgraph.add_edge(u, w)

    def _merge_subgraph_vertex(self, u):
        """
        Merge a generic vertex from the subgraph to the main merged graph.
        """
        # case (3) of examine_vertex
        v = self.graph.add_vertex()
        self.graph.vp.data[v] = self.subgraph.vp.data[u]
        self.copy_vertex_map[u] = v
        for u_in in u.in_neighbours():
            logger.debug("in-neighbour subgraph:%s", u_in)
            # v_in must exist because we are doing BFS
            # however if u_in is a root v_in is None
            v_in = self.copy_vertex_map[u_in]
            if v_in >= 0:
                logger.debug("valid in-neighbour subgraph:%s", u_in)
                self.graph.add_edge(v_in, v)

    def examine_vertex(self, u):
        """
        Merge each vertex of the subgraph in the main merged graph.

        There are 3 cases:
        1. u is a dummy vertex (origin = PARTIAL) in the subgraph,
        therefore it is in the initial regset.
        The corresponding previous regset entry is None.
        2. same as (1) but the corresponding regset entry is not None.
        3. u is a normal vertex (all origin types except PARTIAL).

        Case (1) has 2 sub-cases:
        1.1. all the out-neighbours of u are ROOT vertices.
        In this case the dummy vertex u is deleted and the out-neightbours
        are moved to the merged-graph.
        1.2. there is at least 1 out-neighbour of u that is not a ROOT.
        In this case a MissingParentError is raised, there is nothing to
        derive a non-root vertex from.

        Case (2) has 2 sub-cases:
        2.1. all the out-neighbours of u are ROOT vertices.
        The ROOT vertices are not moved to the merged-graph, instead
        their out-neightbours are attached to the existing parent from
        the previous regset. This is because the ROOTs must not be created
        if we have something to derive from.
        2.2. there is at least 1 out-neightbour of u that is not a ROOT.
        In this case ROOT vertices are suppressed as in (2.1) and the
        non-ROOT vertices are directly attached to the corresponding vertex
        in the previous regset (in the merged-graph).

        Case (3) is trivial to handle, the vertex is moved to the merged
        graph and the edges are recreated.
        """
        if self.omit_vertex_map[u]:
            # nothing to do for this vertex, it is marked to be omitted
            return

        if u in self.initial_regset.reg_nodes or u == self.initial_regset.pcc:
            logger.debug("Merge initial vertex subgraph:%s", u)
            self._merge_initial_vertex(u)
        elif u in self.vertex_map.initial_map.values():
            logger.debug("Merge initial mem vertex subgraph:%s", u)
            self._merge_initial_mem_vertex(u)
        else:
            logger.debug("Merge normal vertex subgraph:%s", u)
            self._merge_subgraph_vertex(u)


class CapabilityBranchSubparser:
    """
    Handle capability branch instructions.
    Subparser that fixes the content of pcc/epcc
    when a capability branch with an exception is
    found.
    """

    def __init__(self, dataset, regset):
        self.dataset = dataset
        self.regset = regset
        """The main parser register set"""

        self._exc_pcc = None
        self._exc_addr = None

    def scan_mfc0(self, inst, entry, regs, last_regs, idx):
        if self._exc_addr != None:
            # badvaddr
            if inst.op1.gpr_index == 8:
                badvaddr = inst.op0.value
                if badvaddr == self._exc_addr + 4:
                    # not committed
                    # epcc = pcc_before_jmp
                    self.regset[31] = self._exc_pcc
            self._exc_addr = None
        return False

    def scan_cjr(self, inst, entry, regs, last_regs, idx):
        """
        Discard current pcc and replace it.
        If the cjr has an exception, the previous pcc is saved
        so that if the instruction did not commit, epcc can
        be set to the correct pcc.
        """
        if inst.has_exception:
            self._exc_pcc = self.regset.pcc
            self._exc_addr = entry.pc
        # discard current pcc and replace it
        if self.regset.has_reg(inst.op0.cap_index):
            # we already have a node for the new PCC
            self.regset.pcc = self.regset[inst.op0.cap_index]
            pcc_data = self.dataset.vp.data[self.regset.pcc]
            if not pcc_data.cap.has_perm(CheriCapPerm.EXEC):
                logger.error("Loading PCC without exec permissions? %s %s",
                             inst, pcc_data)
                raise UnexpectedOperationError(
                    "Loading PCC without exec permissions")
        else:
            # we should create a node here but this should really
            # not be happening, the node is None only when the
            # register content has never been seen before.
            logger.error("Found cjr with unexpected "
                         "target capability %s", inst)
            raise UnexpectedOperationError("cjr to unknown capability")
        return False

    def scan_cjalr(self, inst, entry, regs, last_regs, idx):
        if inst.has_exception:
            self._exc_pcc = self.regset.pcc
            self._exc_addr = entry.pc
        # save current pcc
        cd_idx = inst.op0.cap_index
        if not self.regset.has_pcc(allow_root=True):
            # create a root node for PCC that is in cd
            old_pcc_node = self.make_root_node(entry, inst.op0.value,
                                                   time=entry.cycles)
        else:
            old_pcc_node = self.regset.pcc
        self.regset[cd_idx] = old_pcc_node

        # discard current pcc and replace it
        if self.regset.has_reg(inst.op1.cap_index):
            # we already have a node for the new PCC
            self.regset.pcc = self.regset[inst.op1.cap_index]
            pcc_data = self.dataset.vp.data[self.regset.pcc]
            if not pcc_data.cap.has_perm(CheriCapPerm.EXEC):
                logger.error("Loading PCC without exec permissions? %s %s",
                             inst, pcc_data)
                raise UnexpectedOperationError(
                    "Loading PCC without exec permissions")
            else:
                # we should create a node here but this should really
                # not be happening, the node is None only when the
                # register content has never been seen before.
                logger.error("Found cjalr with unexpected "
                             "target capability %s", inst)
                raise UnexpectedOperationError("cjalr to unknown capability")
        return False

    def scan_ccall(self, inst, entry, regs, last_regs, idx):
        # XXX TODO the semantic regarding ccall
        # depends on the selector field, we may not
        # have an exception here, or always have one
        raise NotImplementedError("ccall pcc fixup not yet implemented")

    def scan_creturn(self, inst, entry, regs, last_regs, idx):
        # XXX TODO the semantic regarding ccall
        # depends on the selector field, we may not
        # have an exception here, or always have one
        raise NotImplementedError("creturn pcc fixup not yet implemented")


class ExceptionEpccFixupSubparser:
    """
    Update pcc and epcc on exception
    """
    pass

class PointerProvenanceParser(MultiprocessCallbackParser):
    """
    Parsing logic that builds the provenance graph used in
    all the provenance-based plots.
    """

    def __init__(self, cache=False, **kwargs):
        super().__init__(**kwargs)

        self.cache = cache
        """Are we using a cached dataset"""

        self._init_graph()
        self.regs_valid = False
        """
        Flag used to disable parsing until the registerset
        is completely initialised.
        """

        self.regset = RegisterSet(self.dataset)
        """
        Register set that maps capability registers
        to nodes in the provenance tree.
        """

        self.vertex_map = VertexMemoryMap(self.dataset)
        """
        Helper that tracks the graph vertex stored at
        a given memory location.
        Internally also keeps track of the vertices that are
        stored/loaded in previously unseen memory addresses.
        This is used to correctly merge the subgraphs from
        multiprocessing workers.
        """

        self.initial_regset = None
        """
        The initial register set is created in worker processes
        to keep track of the initial dummy graph vertices that
        are created. This is used to correctly merge the
        subgraphs.
        """

        self.syscall_context = SyscallContext()
        """Keep state related to system calls entry end return"""

        pcc_fixup = CapabilityBranchSubparser(self.dataset, self.regset)
        self._add_subparser(pcc_fixup)

    def _init_graph(self):
        cache_file = self.path + "_provenance_plot.gt"
        if self.cache and os.path.exists(cache_file):
            with ProgressTimer("Load cached graph", logger):
                self.dataset = load_graph(cache_file)
        else:
            self.dataset = Graph(directed=True)
            vdata = self.dataset.new_vertex_property("object")
            gpath = self.dataset.new_graph_property("string", self.path)
            self.dataset.vp["data"] = vdata
            self.dataset.gp["path"] = gpath

    def parse(self, *args, **kwargs):
        cache_file = self.path + "_provenance_plot.gt"
        with ProgressTimer("Parse provenance graph", logger):
            if self.cache:
                if not os.path.exists(cache_file):
                    super().parse(*args, **kwargs)
                    self.dataset.save(cache_file)
            else:
                super().parse(*args, **kwargs)

    def get_model(self):
        return self.dataset

    def mp_result(self):
        """
        Return the partial result from a worker process.

        The returned data is a tuple containing:
        - the partial graph
        - the initial register set if this worker did not
          parse the first chunk of the trace
        - the final register set
        - the initial and final vertex memory maps,
        holding the live vertices in memory

        :return: (partial_graph, initial_regset, final_regset,
        vertex_map)
        """
        return (self.get_model(), self.initial_regset,
                self.regset, self.vertex_map)

    def mp_merge(self, results):
        """
        Populate the dataset from the partial results.

        Note: this method is run in the main process,
        assuming that the results are in-order w.r.t.
        the trace entries indexes that were used.
        """
        # regset and vertex-map carried from the previous subgraph
        # merge step
        prev_regset = None
        prev_vmap = None
        for idx, result in enumerate(results):
            (graph, initial_regset, final_regset, vertex_map) = result
            with ProgressTimer("Merge partial worker result [%d/%d]" % (
                    idx + 1, len(results)), logger):
                if initial_regset == None:
                    self.dataset = graph
                    prev_regset = final_regset
                    prev_vmap = vertex_map
                else:
                    # copy the graph into the merged dataset and
                    # merge the root nodes from the initial register set
                    # with the previous register set
                    transform = MergePartialSubgraph(
                        self.dataset, graph,
                        initial_regset, final_regset, prev_regset,
                        vertex_map, prev_vmap)
                    bfs_transform(graph, [transform])
                    prev_regset = transform.get_final_regset()
                    prev_vmap = transform.get_final_vmap()

    def _do_parse(self, start, end, direction):
        """
        This sets up the different initialization of the graph and
        register set, depending on the start index.

        If the start == 0 then we initialize the register set from
        what we find before the first return to userspace.
        Otherwise we create dummy graph roots for each register
        that will be used during the merge.
        """
        if start != 0: # check that we are in a worker process instead
            self.initial_regset = RegisterSet(self.dataset)
            # create dummy initial nodes
            reg_nodes = list(self.dataset.add_vertex(32))
            pcc_node = self.dataset.add_vertex()
            for n in reg_nodes + [pcc_node]:
                data = NodeData()
                data.origin = CheriNodeOrigin.PARTIAL
                self.dataset.vp.data[n] = data
            self.initial_regset.reg_nodes = reg_nodes
            self.initial_regset.pcc = pcc_node
            self.regset.reg_nodes = list(reg_nodes)
            self.regset.pcc = pcc_node
            self.regs_valid = True
            # use the MP vertex map
            self.vertex_map = MPVertexMemoryMap(self.dataset)
        super()._do_parse(start, end, direction)

    def _set_initial_regset(self, inst, entry, regs):
        """
        Setup the registers after the first eret
        """
        self.regs_valid = True
        logger.debug("Scan initial register set cycle: %d", entry.cycles)
        for idx in range(0, 32):
            cap = regs.cap_reg[idx]
            valid = regs.valid_caps[idx]
            if valid:
                node = self.make_root_node(entry, cap, pc=0)
                self.regset[idx] = node
            else:
                logger.warning("c%d not in initial set", idx)
                if idx == 29:
                    node = self.make_root_node(entry, None, pc=0)
                    cap = CheriCap()
                    cap.base = 0
                    cap.offset = 0
                    cap.length = 0xffffffffffffffff
                    # all XXX should we only have EXEC and few other?
                    cap.permissions = CheriCapPerm.all()
                    cap.objtype = 0
                    cap.valid = True
                    cap.t_alloc = 0
                    self.dataset.vp.data[node].cap = cap
                    self.regset[idx] = node
                    logger.warning("Guessing KCC %s", self.dataset.vp.data[node])
                if idx == 30:
                    # guess the value of KDC and use this in the initial register set
                    node = self.make_root_node(entry, None, pc=0)
                    self.regset[idx] = node
                    cap = CheriCap()
                    cap.base = 0
                    cap.offset = 0
                    cap.length = 0xffffffffffffffff
                    cap.objtype = 0
                    cap.permissions = CheriCapPerm.all()
                    cap.valid = True
                    cap.t_alloc = 0
                    self.dataset.vp.data[node].cap = cap
                    self.regset[idx] = node
                    logger.warning("Guessing KDC %s", self.dataset.vp.data[node])

    def _has_exception(self, entry, code=None):
        """
        Check if an exception occurred in the given trace entry
        """
        if code is not None:
            return entry.exception == code
        else:
            return entry.exception != 31

    def _instr_committed(self, inst, entry, regs, last_regs):
        """
        Check if an instruction has been committed and will
        not be replayed.

        """
        # XXX disable it because things break when the exception does
        # not roll-back the instruction, there is no way of detecting
        # this so we just assume that it can happen.
        # if self._has_exception(entry) and entry.exception != 0:
        #     return False
        return True

    def _do_scan(self, entry):
        """
        Check if the scan of an instruction can proceed.
        This disables scanning until the regiser set is initialized
        after the first eret and do not scan instructions that did
        not commit due to exceptions being raised.
        """
        # if self.regs_valid and self._instr_committed(entry):
        if self.regs_valid:
            return True
        return False

    def scan_all(self, inst, entry, regs, last_regs, idx):
        """
        Detect end of syscalls by checking the expected return PC
        after an eret
        """
        if not self.regs_valid:
            return False

        if self._has_exception(entry):
            # If an exception occurred adjust EPCC node from PCC,
            # this also handles syscall exceptions.
            # if the instruction is an eret that is causing an exception
            # EPCC and PCC do not change and we end up in an handler again.
            logger.debug("except {%d}: update epcc %s, update pcc %s",
                         entry.cycles,
                         self.dataset.vp.data[self.regset.pcc],
                         self.dataset.vp.data[self.regset[29]])
            self.regset[31] = self.regset.pcc # saved pcc
            self.regset.pcc = self.regset[29] # pcc <- kcc

        if (self.syscall_context.in_syscall and
            entry.pc == self.syscall_context.pc_eret):
            node = self.syscall_context.scan_syscall_end(
                    inst, entry, regs, self.dataset, self.regset)
            logger.debug("Built syscall node %s", node)
        return False

    def scan_eret(self, inst, entry, regs, last_regs, idx):
        """
        Detect the first eret that enters the process code
        and initialise the register set and the roots of the tree.
        """
        if not self.regs_valid:
            self._set_initial_regset(inst, entry, regs)

        # eret may throw an exception, in which case the nodes
        # are handled again in scan_all (which is always executed
        # after per-opcode scan_* methods)
        logger.debug("eret {%d}: update pcc %s", entry.cycles,
                     self.dataset.vp.data[self.regset[31]])
        self.regset.pcc = self.regset[31] # restore saved pcc
        return False

    def scan_syscall(self, inst, entry, regs, last_regs, idx):
        """
        Record entering mmap system calls so that we can grab the return
        value at the end
        """
        if not self.regs_valid:
            return False

        self.syscall_context.scan_syscall_start(inst, entry, regs,
                                                self.dataset, self.regset)
        return False

    def scan_cclearregs(self, inst, entry, regs, last_regs, idx):
        """
        Clear the register set according to the mask.
        The result can not be immediately found in the trace, it
        is otherwise spread among all the uses of the registers.
        """
        raise NotImplementedError("cclearregs not yet supported")
        return False

    def _handle_cpreg_get(self, regnum, inst, entry):
        """
        When a cgetXXX is found, propagate the node from the special
        register XXX (i.e. kcc, kdc, ...) to the destination or create a
        new node if nothing was there.

        :param regnum: the index of the special register in the register set
        :type regnum: int

        :param inst: parsed instruction
        :type inst: :class:`cheriplot.core.parser.Instruction`

        :parm entry: trace entry
        :type entry: :class:`pycheritrace.trace_entry`
        """
        if not self._do_scan(entry):
            return False
        if not self.regset.has_reg(regnum, allow_root=True):
            # no node was ever created for the register, it contained something
            # invalid
            node = self.make_root_node(entry, inst.op0.value,
                                       time=entry.cycles)
            self.regset[regnum] = node
            logger.debug("cpreg_get: new node from $c%d %s",
                         regnum, self.dataset.vp.data[node])
        self.regset[inst.op0.cap_index] = self.regset[regnum]

    def _handle_cpreg_set(self, regnum, inst, entry):
        """
        When a csetXXX is found, propagate the node to the special
        register XXX (i.e. kcc, kdc, ...) or create a new node.

        :param regnum: the index of the special register in the register set
        :type regnum: int

        :param inst: parsed instruction
        :type inst: :class:`cheriplot.core.parser.Instruction`

        :parm entry: trace entry
        :type entry: :class:`pycheritrace.trace_entry`
        """
        if not self._do_scan(entry):
            return False
        if not self.regset.has_reg(inst.op0.cap_index, allow_root=True):
            node = self.make_root_node(entry, inst.op0.value,
                                       time=entry.cycles)
            self.regset[inst.op0.cap_index] = node
            logger.debug("cpreg_set: new node from c<%d> %s",
                         regnum, self.dataset.vp.data[node])
        self.regset[regnum] = self.regset[inst.op0.cap_index]

    def scan_cgetepcc(self, inst, entry, regs, last_regs, idx):
        self._handle_cpreg_get(31, inst, entry)
        return False

    def scan_csetepcc(self, inst, entry, regs, last_regs, idx):
        self._handle_cpreg_set(31, inst, entry)
        return False

    def scan_cgetkcc(self, inst, entry, regs, last_regs, idx):
        self._handle_cpreg_get(29, inst, entry)
        return False

    def scan_csetkcc(self, inst, entry, regs, last_regs, idx):
        self._handle_cpreg_set(29, inst, entry)
        return False

    def scan_cgetkdc(self, inst, entry, regs, last_regs, idx):
        self._handle_cpreg_get(30, inst, entry)
        return False

    def scan_csetkdc(self, inst, entry, regs, last_regs, idx):
        self._handle_cpreg_set(30, inst, entry)
        return False

    def scan_cgetdefault(self, inst, entry, regs, last_regs, idx):
        self._handle_cpreg_get(0, inst, entry)
        return False

    def scan_csetdefault(self, inst, entry, regs, last_regs, idx):
        self._handle_cpreg_set(0, inst, entry)
        return False

    def scan_cgetpcc(self, inst, entry, regs, last_regs, idx):
        if not self._do_scan(entry):
            return False
        if not self.regset.has_pcc(allow_root=True):
            # never seen anything in pcc so we create a new node
            node = self.make_root_node(entry, inst.op0.value,
                                       time=entry.cycles)
            self.regset.pcc = node
            logger.debug("cgetpcc: new node from pcc %s",
                         self.dataset.vp.data[node])
        self.regset[inst.op0.cap_index] = self.regset.pcc
        return False

    def scan_cgetpccsetoffset(self, inst, entry, regs, last_regs, idx):
        return self.scan_cgetpcc(inst, entry, regs, last_regs, idx)

    def scan_csetbounds(self, inst, entry, regs, last_regs, idx):
        """
        Each csetbounds is a new pointer allocation
        and is recorded as a new node in the provenance tree.
        The destination register is associated to the new node
        in the register set.

        csetbounds:
        Operand 0 is the register with the new node
        Operand 1 is the register with the parent node
        """
        if not self._do_scan(entry):
            return False
        node = self.make_node(entry, inst, origin=CheriNodeOrigin.SETBOUNDS)
        self.regset[inst.op0.cap_index] = node
        return False

    def scan_cfromptr(self, inst, entry, regs, last_regs, idx):
        """
        Each cfromptr is a new pointer allocation and is
        recodred as a new node in the provenance tree.
        The destination register is associated to the new node
        in the register set.

        cfromptr:
        Operand 0 is the register with the new node
        Operand 1 is the register with the parent node
        """
        if not self._do_scan(entry):
            return False
        node = self.make_node(entry, inst, origin=CheriNodeOrigin.FROMPTR)
        self.regset[inst.op0.cap_index] = node
        return False

    def scan_candperm(self, inst, entry, regs, last_regs, idx):
        """
        Each candperm is a new pointer allocation and is recorded
        as a new node in the provenance tree.

        candperm:
        Operand 0 is the register with the new node
        Operand 1 is the register with the parent node
        """
        if not self._do_scan(entry):
            return False
        node = self.make_node(entry, inst, origin=CheriNodeOrigin.ANDPERM)
        self.regset[inst.op0.cap_index] = node
        return False

    def scan_cap(self, inst, entry, regs, last_regs, idx):
        """
        Whenever a capability instruction is found, update
        the mapping from capability register to the provenance
        tree node associated to the capability in it.
        """
        if not self._do_scan(entry):
            return False
        if (inst.opcode == "ccall" or inst.opcode == "creturn" or
              inst.opcode == "cjr" or inst.opcode == "cjalr"):
            # these are handled by software so all register assignments
            # are already parsed there
            return False
        elif entry.is_store or entry.is_load:
            return False
        else:
            self.update_regs(inst, entry, regs, last_regs)
        return False

    def _handle_dereference(self, inst, entry, ptr_reg):
        """
        Store offset at time of dereference of a given capability.
        """
        try:
            node = self.regset[ptr_reg]
        except KeyError:
            logger.error("{%d} Dereference unknown capability %s",
                         entry.cycles, inst)
            raise DereferenceUnknownCapabilityError(
                "Dereference unknown capability")
        if node is None:
            logger.error("{%d} Dereference unknown capability %s",
                         entry.cycles, inst)
            raise DereferenceUnknownCapabilityError(
                "Dereference unknown capability")
        node_data = self.dataset.vp.data[node]
        # instead of the capability register offset we use the
        # entry memory_address so we capture any extra offset in
        # the instruction as well
        is_cap = inst.opcode.startswith("clc") or inst.opcode.startswith("csc")
        if entry.is_load:
            node_data.add_load(entry.cycles, entry.memory_address, is_cap)
        elif entry.is_store:
            node_data.add_store(entry.cycles, entry.memory_address, is_cap)
        else:
            if not self._has_exception(entry):
                logger.error("Dereference is neither a load or a store %s", inst)
                raise RuntimeError("Dereference is neither a load nor a store")

    def scan_cap_load(self, inst, entry, regs, last_regs, idx):
        """
        Store all offsets at time of dereference of a given capability.

        clX[u] have pointer argument in op3
        clXr and clXi have pointer argument in op2
        cllX have pointer argument in op1
        """
        if not self._do_scan(entry):
            return False

        # get the register with the address capability
        # this may be a normal capability load or a linked-load
        if inst.opcode.startswith("cll"):
            ptr_reg = inst.op1.cap_index
        else:
            if inst.opcode[-1] == "r" or inst.opcode[-1] == "i":
                ptr_reg = inst.op2.cap_index
            else:
                ptr_reg = inst.op3.cap_index
        self._handle_dereference(inst, entry, ptr_reg)
        return False

    def scan_cap_store(self, inst, entry, regs, last_regs, idx):
        """
        Store all offsets at time of dereference of a given capability.

        csX have pointer argument in op3
        csXr and csXi have pointer argument in op2
        cscX conditionals use op2
        """
        if not self._do_scan(entry):
            return False
        # get the register with the address capability
        # this may be a normal capability store or an atomic-store
        if inst.opcode != "csc" and inst.opcode.startswith("csc"):
            # atomic
            ptr_reg = inst.op2.cap_index
        else:
            if inst.opcode[-1] == "r" or inst.opcode[-1] == "i":
                ptr_reg = inst.op2.cap_index
            else:
                ptr_reg = inst.op3.cap_index
        self._handle_dereference(inst, entry, ptr_reg)
        return False

    def scan_clc(self, inst, entry, regs, last_regs, idx):
        """
        clc:
        Operand 0 is the register with the new node
        The parent is looked up in memory or a root node is created
        """
        if not self._do_scan(entry):
            return False
        logger.debug("scan clc")
        cd = inst.op0.cap_index
        node = self.vertex_map.mem_load(entry.memory_address)
        if node is None:
            logger.debug("Load c%d from new location 0x%x",
                         cd, entry.memory_address)
        # if the capability loaded from memory is valid, it
        # can be safely assumed that it corresponds to the node
        # stored in the memory_map for that location, if there is
        # one. If there is no node in the memory_map then a
        # new node can be created from the valid capability.
        # Otherwise something has changed the memory location so we
        # clear the memory_map and the regset entry.
        if not inst.op0.value.valid:
            logger.debug("clc load invalid, clear memory vertex map")
            self.regset[cd] = None
            if node is not None:
                self.vertex_map.clear(entry.memory_address)
        else:
            # check if the load instruction has committed
            old_cd = CheriCap(last_regs.cap_reg[cd])
            curr_cd = CheriCap(regs.cap_reg[cd])
            logger.debug("clc op0 valid old_cd %s curr_cd %s", old_cd, curr_cd)
            if old_cd != curr_cd or not self._has_exception(entry):
                # the destination register was updated so the
                # instruction did commit

                if node is None:
                    # add a node as a root node because we have never
                    # seen the content of this register yet.
                    node = self.make_root_node(entry, inst.op0.value,
                                               time=entry.cycles)
                    node_data = self.dataset.vp.data[node]
                    node_data.address[entry.cycles] = entry.memory_address
                    logger.debug("Found %s value %s from memory load",
                                 inst.op0.name, node_data)
                    self.vertex_map.mem_load(entry.memory_address, node)
                self.regset[cd] = node
        return False

    scan_clcr = scan_clc
    scan_clci = scan_clc

    def scan_csc(self, inst, entry, regs, last_regs, idx):
        """
        Record the locations where a capability node is stored.
        This is later used if the capability is loaded again with
        a clc.
        The locations where a capability is stored are also saved in
        the graph.
        It may happen that a previously unseen register is stored,
        the value of the register is now known to be valid because it
        is stored in the trace entry, a root node is created.

        csc:
        Operand 0 is the capability being stored, the node already exists
        """
        if not self._do_scan(entry):
            return False

        cd = inst.op0.cap_index

        if inst.op0.value.valid:
            # if this is not a data access

            if not self.regset.has_reg(cd, allow_root=True):
            # if self.regset[cd] == None: XXX
                # XXX may decide to disable and have an exception here
                # need to create one
                node = self.make_root_node(entry, inst.op0.value,
                                           time=entry.cycles)
                self.regset[cd] = node
                logger.debug("Found %s value %s from memory store",
                             inst.op0.name, node)
            else:
                node = self.regset[cd]

            # if there is a node associated with the register that is
            # being stored, save it in the memory_map for the memory location
            # written by csc
            self.vertex_map.mem_store(entry.memory_address, node)
            # set the address attribute of the node vertex data property
            node_data = self.dataset.vp.data[node]
            node_data.address[entry.cycles] = entry.memory_address

        return False

    scan_cscr = scan_csc
    scan_csci = scan_csc

    def make_root_node(self, entry, cap, time=0, pc=None):
        """
        Create a root node of the provenance graph and add it to the dataset.

        :param entry: trace entry of the current instruction
        :type entry: `pycheritrace.trace_entry`
        :param cap: capability register value
        :type cap: :class:`pycheritrace.capability_register`
        :param time: optional allocation time
        :type time: int
        :param: pc: optional PC value for the root node
        :type pc: int
        :return: the newly created node
        :rtype: :class:`graph_tool.Vertex`
        """
        data = NodeData()
        data.cap = CheriCap(cap)
        # if pc is 0 indicate that we do not have a specific
        # instruction for this
        data.cap.t_alloc = time
        data.pc = entry.pc if pc is None else pc
        data.origin = CheriNodeOrigin.ROOT
        data.is_kernel = entry.is_kernel()

        # create graph vertex and assign the data to it
        vertex = self.dataset.add_vertex()
        self.dataset.vp.data[vertex] = data
        return vertex

    def make_node(self, entry, inst, origin=None, src_op_index=1, dst_op_index=0):
        """
        Create a node in the provenance tree.
        The parent is fetched from the register set depending on the source
        registers of the current instruction.

        :param entry: trace entry info object
        :type entry: :class:`pycheritrace.trace_entry`
        :param inst: instruction parsed
        :type inst: :class:`cheriplot.core.parser.Instruction`
        :param origin: the instruction/construction that originated the node
        :type origin: :class:`cheriplot.core.provenance.CheriNodeOrigin`
        :param src_op_index: index of the instruction operand that
        associated with the parent node
        :type src_op_index: int
        :param dst_op_index: index of the instruction operand with
        the node data
        :type dst_op_index: int
        :return: the new node
        :rtype: :class:`graph_tool.Vertex`
        """
        data = NodeData.from_operand(inst.operands[dst_op_index])
        data.origin = origin
        # try to get a parent node
        op = inst.operands[src_op_index]
        if self.regset.has_reg(op.cap_index, allow_root=False):
            parent = self.regset[op.cap_index]
        else:
            logger.error("Error searching for parent node of %s", data)
            raise MissingParentError("Missing parent for %s" % data)

        # there must be a parent if the root nodes for the initial register
        # set have been created
        # Note that we may chose to add a root node when no parent is
        # available, this may be the case of replacing the guess of KDC
        if parent == None:
            logger.error("Missing parent for %s, src_operand=%d %s, "
                         "dst_operand=%d %s", data,
                         src_op_index, inst.operands[src_op_index],
                         dst_op_index, inst.operands[dst_op_index])
            raise MissingParentError("Missing parent for %s" % data)

        # create the vertex in the graph and assign the data to it
        vertex = self.dataset.add_vertex()
        self.dataset.add_edge(parent, vertex)
        self.dataset.vp.data[vertex] = data
        return vertex

    def update_regs(self, inst, entry, regs, last_regs):
        """
        Try to update the registers-node mapping when a capability
        instruction is executed so that nodes are propagated in
        the registers when their bounds do not change.
        """
        cd = inst.op0
        cb = inst.op1
        if not cd or not cb:
            return
        if (cb.is_capability and cd.is_capability):
            self.regset[cd.cap_index] = self.regset[cb.cap_index]
