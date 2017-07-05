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


import numpy as np
import logging
import os

from enum import IntEnum
from functools import reduce
from graph_tool.all import Graph, load_graph

from cheriplot.core import ProgressTimer, MultiprocessCallbackParser

from cheriplot.provenance.model import *
from cheriplot.provenance.transforms import bfs_transform, BFSTransform

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

        self.reg_nodes = list(self.pgm.graph.add_vertex(self.cap_regfile_size))
        """Graph node associated with each register."""

        self._pcc = self.pgm.graph.add_vertex()
        """Current pcc node"""

        self.initial_reg_nodes = list(self.reg_nodes)
        """
        The initial register set is created in worker processes
        to keep track of the initial dummy graph vertices that
        are created. This is used to correctly merge the
        subgraphs.
        """

        self.initial_pcc = self._pcc
        """Initial pcc vertex."""

        for n in self.reg_nodes + [self._pcc]:
            data = NodeData()
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
            "_pcc": self.pgm.graph.vertex_index[self._pcc] if self._pcc != None else None,
            "initial_reg_nodes": [self.pgm.graph.vertex_index[u] for u in self.initial_reg_nodes],
            "initial_pcc": self.pgm.graph.vertex_index[self.initial_pcc],
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
        self._pcc = data["_pcc"]
        self.initial_reg_nodes = data["initial_reg_nodes"]
        self.initial_pcc = data["initial_pcc"]

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
            for n in input_vertex.in_neighbours():
                if self.pgm.data[n].origin == CheriNodeOrigin.PARTIAL:
                    return
            curr_data = self.pgm.data[regset_vertex]
            if curr_data.origin == CheriNodeOrigin.PARTIAL:
                self.pgm.graph.add_edge(regset_vertex, input_vertex)

    @property
    def pcc(self):
        return self._pcc

    @pcc.setter
    def pcc(self, value):
        self._attach_partial_vertex(self._pcc, value)
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
            data = self.pgm.data[self.pcc]
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
        assert idx < self.cap_regfile_size, "Out of bound register set index"
        if self[idx] == None:
            return False
        if allow_root:
            data = self.pgm.data[self[idx]]
            if data.origin == CheriNodeOrigin.PARTIAL:
                return False
        return True

    def __getitem__(self, idx):
        """
        Fetch the :class:`cheriplot.core.provenance.GraphNode`
        currently associated to a capability register with the
        given register number.
        """
        assert idx < self.cap_regfile_size, "Out of bound register set fetch"
        return self.reg_nodes[idx]

    def __setitem__(self, idx, val):
        """
        Fetch the :class:`cheriplot.core.provenance.GraphNode`
        currently associated to a capability register with the
        given register number.
        """
        assert idx < self.cap_regfile_size,\
            "Out of bound register set assignment"
        self._attach_partial_vertex(self.reg_nodes[idx], val)
        self.reg_nodes[idx] = val

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
    """
    Subgraph merge strategy, this is architecture-specific.
    """

    def __init__(self, cache=False, **kwargs):
        super().__init__(**kwargs)

        self.cache = cache
        """Are we using a cached dataset."""

        self.pgm = None
        """Provenance graph manager, proxy access to the provenance graph."""

        self._init_graph()

    def _init_graph(self):
        """Initialize the graph model manager."""
        if self.cache:
            cache_file = self.path + "_provenance.gt"
            self.pgm = ProvenanceGraphManager(self.path, cache_file)
        else:
            self.pgm = ProvenanceGraphManager(self.path)

    def parse(self, start=None, end=None, direction=0):
        """
        Parse the trace and save the resulting graph if configured to do so.
        If the cached graph exists do nothing, the graph manager should have
        loaded the graph from the cache.

        See :meth:`MultiprocessCallbackParser.parse`.
        """
        with ProgressTimer("Parse provenance graph", logger):
            if self.cache and not self.pgm.cache_exists:
                super().parse(start, end, direction)
                self.pgm.save()
            elif not self.cache:
                super().parse(start, end, direction)

    def get_model(self):
        return self.pgm

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
            "pgm": self.get_model(),
        }
        return state

    def mp_merge(self, results):
        """
        Populate the dataset from the partial results.

        Note: this method is run in the main process,
        assuming that the results are in-order w.r.t.
        the trace entries indexes that were used.
        """
        if self.mp.threads == 1:
            # need to merge partial vertices from the beginning of
            # the trace anyway, reinit the graph manager with an
            # empty one, the previous is in the results list
            # XXX this is potentially wasteful for the 1-thread case
            self._init_graph()
        merge_ctx = self.subgraph_merge_context_class(self.pgm)
        for idx, result in enumerate(results):
            with ProgressTimer("Merge partial worker result [%d/%d]" % (
                    idx + 1, len(results)), logger):
                merge_ctx.step(result)
