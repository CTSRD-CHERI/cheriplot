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
Base parsing infrastructure to build the cheriplot graph.

This module defines the common helpers used to implement
architecture-specific subparsers and multiprocessing parsing.
"""

import logging
import os
from functools import partial

from cheriplot.core import ProgressTimer, MultiprocessCallbackParser
from cheriplot.provenance.model import (
    ProvenanceVertexData, ProvenanceGraphManager, CheriNodeOrigin, CheriCap)

from .error import *

logger = logging.getLogger(__name__)

class VertexMemoryMap:
    """
    Helper object that keeps track of the graph vertex associated
    with each memory location used in the trace.

    Vertex map used by multiprocessing workers to record the
    initial state of the map so that the initial vertices can
    be merged with the results from other workers.
    """

    def __init__(self, pgm):
        self.vertex_map = {}
        """Map memory address to the vertex stored in memory."""

        self.initial_map = {}
        """Map memory address to the first vertex seen at a location."""

        self.pgm = pgm
        """Graph manager."""

    def __getstate__(self):
        """
        Make object pickle-able, the graph-tool vertices index are used
        instead of the vertex object.
        """
        logger.debug("Pickling partial result vertex-memory map %d",
                     os.getpid())
        state = {
            "vertex_map": {k: int(v) for k,v in self.vertex_map.items()},
            "initial_map": {k: int(v) for k,v in self.initial_map.items()}
        }
        return state

    def __setstate__(self, data):
        """
        Make object pickle-able, the graph-tool vertices index are used
        instead of the vertex object.
        """
        logger.debug("Unpickling partial result vertex-memory map")
        self.vertex_map = data["vertex_map"]
        self.initial_map = data["initial_map"]

    def clear(self, addr):
        """
        Unregister the vertex associated with the given memory location
        """
        del self.vertex_map[addr]

    def vertex_at(self, addr):
        """Return the vertex currently stored at a given address."""
        try:
            return self.vertex_map[addr]
        except KeyError:
            return None

    def mem_load(self, addr, vertex=None):
        """
        Register a memory load at given address and return
        the vertex for that address if any.
        If a vertex is specified, the vertex is set
        in the memory map at the given address.
        """
        if vertex:
            if addr not in self.initial_map:
                self.initial_map[addr] = vertex                
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


class RegisterSet:
    """
    Helper object that keeps track of the graph vertex associated
    with each register in the register file.

    The register set is also used in the subgraph merge
    resolution to produce the full graph from partial
    results from worker processes.
    """

    cap_regfile_size = 32
    """Number of capability registers in the register file."""

    def __init__(self, pgm):
        """
        Initialize the register set with partial vertices.
        The initial register mapping is also initialized.
        """

        self.pgm = pgm
        """The provenance graph manager"""

        vertices = self.pgm.graph.add_vertex(self.cap_regfile_size + 1)
        # the + 1 adds pcc to the list
        self.reg_nodes = list(vertices)
        """Graph node associated with each register."""

        self.initial_reg_nodes = list(self.reg_nodes)
        """
        The initial register set is created in worker processes
        to keep track of the initial dummy graph vertices that
        are created. This is used to correctly merge the
        subgraphs.
        """

        self._pause_recovered = [True] * len(self.reg_nodes)

        for n in self.reg_nodes:
            data = ProvenanceVertexData()
            data.cap = CheriCap()
            data.origin = CheriNodeOrigin.PARTIAL
            self.pgm.data[n] = data

    def __getstate__(self):
        """
        Make object pickle-able, graph-tool vertices are not pickleable
        but their index is.
        """
        logger.debug("Pickling partial result register set %d", os.getpid())
        state = {
            "reg_nodes": [self.pgm.graph.vertex_index[u] if u != None else None
                          for u in self.reg_nodes],
            "initial_reg_nodes": [self.pgm.graph.vertex_index[u]
                                  for u in self.initial_reg_nodes],
            }
        return state

    def __setstate__(self, data):
        """
        Make object pickle-able.

        Restore internal state. Note that this does not recover the vertex
        instances from the graph as we do not require this when propagating
        partial results from the workers.
        Note also that the graph is dropped, this is to avoid pickling the
        graph twice.
        XXX Doing so saves some time although it may be desirable to
        perform the operation to avoid confusion.
        """
        logger.debug("Unpickling partial result register set")
        self.reg_nodes = data["reg_nodes"]
        self.initial_reg_nodes = data["initial_reg_nodes"]

    def _attach_partial_vertex(self, regset_vertex, input_vertex):
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

        in_data = self.pgm.data[input_vertex]
        if in_data.origin == CheriNodeOrigin.ROOT:
            # if the root is already attached to a partial, do nothing
            for n in input_vertex.in_neighbours():
                if self.pgm.data[n].origin == CheriNodeOrigin.PARTIAL:
                    return
            # else attach it to current partial if it exists
            curr_data = self.pgm.data[regset_vertex]
            if curr_data.origin == CheriNodeOrigin.PARTIAL:
                self.pgm.graph.add_edge(regset_vertex, input_vertex)

    def _handle_out_of_scope(self, regset_vertex, time):
        """
        Check if a register-set vertex is removed from the
        register set completely and if it is not stored in memory
        anywhere then set the t_free time.
        """
        if regset_vertex in self.reg_nodes or regset_vertex is None:
            return
        v_data = self.pgm.data[regset_vertex]
        if not v_data.has_active_memory():
            v_data.cap.t_free = time

    def set_reg(self, index, value, time):
        """
        Set a register in the register set.

        :param index: index of the register
        :param value: new vertex to store
        :param time: time of the vertex store
        """
        old_vertex = self.reg_nodes[index]
        logger.debug("{%d} reg[%d] %s <- %s", time, index,
                     self.pgm.data[old_vertex] if old_vertex else None,
                     self.pgm.data[value] if value else None)
        self._attach_partial_vertex(old_vertex, value)
        self.reg_nodes[index] = value
        if value != old_vertex:
            self._handle_out_of_scope(old_vertex, time)

    def get_reg(self, index):
        """
        Get the vertex associated with a register

        :param index: the register index
        """
        return self.reg_nodes[index]

    def get_pcc(self):
        return self.get_reg(32)

    def set_pcc(self, value, time):
        self.set_reg(32, value, time)

    def has_pcc(self, expected, time, allow_root=False):
        return self.has_reg(32, expected, time, allow_root)

    def has_reg(self, idx, expected, time, allow_root=False):
        """
        Check if the register set contains a valid entry for
        the given register index

        :param idx: the register index to check
        :param expected: the expected cheritrace capability value
        in the trace, the registers should be compatible with
        the current content of the regset.
        :param allow_root: a root can be created if the register
        does not have a valid node.
        """
        if self.reg_nodes[idx] is None:
            return False
        if allow_root:
            data = self.pgm.data[self.reg_nodes[idx]]
            if data.origin == CheriNodeOrigin.PARTIAL:
                return False
        if not self._pause_recovered[idx]:
            logger.debug("Resume register %d %s", idx, CheriCap(expected))
            self._recover_paused_reg(idx, expected, time)
            return self.reg_nodes[idx] is not None
        return True

    def _is_cap_compatible(self, data, cap):
        """
        Check if a provenance vertex data entry is compatible
        with a cheritrace capability_regiseter.

        :param data: ProvenanceVertexData to check
        :param cap: cheritrace capability_register
        :return: bool
        """
        if (data.cap.base == cap.base and
            data.cap.length == cap.length and
            data.cap.permissions == cap.permissions and
            data.cap.objtype == cap.type & CheriCap.MAX_OTYPE and
            data.cap.valid == cap.valid and
            data.cap.sealed == cap.unsealed):
            return True
        return False

    def _recover_paused_reg(self, idx, expected, time):
        """
        Try to recover a vertex after a tracing pause.

        :param idx: index of the register, the current registerset
        content for the index is expected to be a valid vertex.
        :param expected: expected value found in the trace.
        """
        data = self.pgm.data[self.reg_nodes[idx]]
        self._pause_recovered[idx] = True
        if self._is_cap_compatible(data, expected):
            # everything is ok
            return
        # lookup a compatible capability in the register set and replace
        # the target register with that.
        for reg_idx, vertex in enumerate(self.reg_nodes):
            if vertex is None or reg_idx == idx:
                continue
            vdata = self.pgm.data[vertex]
            if self._is_cap_compatible(vdata, expected):
                self.set_reg(idx, vertex, time)
                return
        self.set_reg(idx, None, time)

    def handle_pause(self):
        """
        The trace scanning is paused so the registers that we
        find afterwards may change without notice.
        """
        self._pause_recovered = [False] * len(self.reg_nodes)

    def __str__(self):
        dump = "Register set:\n"
        for i, v in enumerate(self.reg_nodes):
            origin = self.pgm.data[v].origin if v else ""
            dump += "c%d -> %s %s\n" % (i, v, origin)
        origin = self.pgm.data[self.pcc].origin if self.pcc else ""
        dump += "pcc -> %s %s\n" % (self.pcc, origin)
        return dump

    
class CheriplotModelParser(MultiprocessCallbackParser):
    """
    Cheri-mips top-level cheriplot trace parser
    """

    subgraph_merge_context_class = None
    """Subgraph merge strategy class, this is architecture-specific."""

    def __init__(self, pgm, **kwargs):
        super().__init__(**kwargs)

        self.pgm = ProvenanceGraphManager(None)
        """Local graph manager, holds the intermediate subgraph."""

        self.final_pgm = pgm
        """Result graph manager, this is where the final graph is produced."""

    def parse(self, start=None, end=None, direction=0):
        """
        Parse the trace and save the resulting graph if configured to do so.
        If the cached graph exists do nothing, the graph manager should have
        loaded the graph from the cache.

        See :meth:`MultiprocessCallbackParser.parse`.
        """
        with ProgressTimer("Parse provenance graph", logger):
            super().parse(start, end, direction)

    def mp_worker(self):
        return partial(self.__class__, self.pgm, is_worker=True, **self.kwargs)

    def mp_result(self):
        """
        Return the partial result from a worker process.
        This should be overridden by architecture-specific implementation.

        The returned data is a dict containing:
        - start and end cycle number to compute the relative cycles during merge
        - the partial subgraph manager

        :return: dict containing the state as it is interpreted by the
        :class:`MergePartialSubgraphContext`
        """
        state = {
            "cycles_start": self.cycles_start,
            "cycles_end": self.cycles_end,
            "pgm": self.pgm,
        }
        return state

    def mp_merge(self, results):
        """
        Populate the dataset from the partial results.

        Note: this method is run in the main process,
        assuming that the results are in-order w.r.t.
        the trace entries indexes that were used.
        """
        # if self.mp.threads == 1:
        #     # need to merge partial vertices from the beginning of
        #     # the trace anyway, reinit the graph manager with an
        #     # empty one, the previous is in the results list
        #     # XXX this is potentially wasteful for the 1-thread case
        #     self._init_graph()
        merge_ctx = self.subgraph_merge_context_class(self.final_pgm)
        for idx, result in enumerate(results):
            with ProgressTimer("Merge partial worker result [%d/%d]" % (
                    idx + 1, len(results)), logger):
                merge_ctx.step(result)
