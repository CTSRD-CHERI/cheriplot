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
Provenance graph implementation and helper classes.
"""

import os
import logging
from enum import IntEnum, IntFlag, auto
from functools import partialmethod
from collections import OrderedDict

import numpy as np
import pandas as pd
from cached_property import cached_property
from graph_tool.all import Graph, GraphView, load_graph
from cheriplot.core import ProgressTimer

__all__ = ("CheriCapPerm", "CheriNodeOrigin", "CheriCap",
           "ProvenanceGraphManager", "CallVertexData", "ProvenanceVertexData")

logger = logging.getLogger(__name__)

class CheriCapPerm(IntFlag):
    """
    Enumeration of bitmask for the capability permission bits.
    """

    GLOBAL = 1
    EXEC = 1 << 1
    LOAD = 1 << 2
    STORE = 1 << 3
    CAP_LOAD = 1 << 4
    CAP_STORE = 1 << 5
    CAP_STORE_LOCAL = 1 << 6
    SEAL = 1 << 7
    # XXXAM qemu currently uses 8, spec says 10
    SYSTEM_REGISTERS = 1 << 10 | 1 << 8

    @classmethod
    def all(cls):
        return (cls.GLOBAL | cls.EXEC | cls.LOAD | cls.STORE |
                cls.CAP_LOAD | cls.CAP_STORE | cls.CAP_STORE_LOCAL |
                cls.SEAL | cls.SYSTEM_REGISTERS)


class CheriNodeOrigin(IntFlag):
    """
    Enumeration of the possible originators of
    nodes in the provenance graph.
    """
    UNKNOWN = auto()
    # partial result used in mutiprocessing parser
    PARTIAL = auto()
    # root node
    ROOT = auto()
    INITIAL_ROOT = auto()
    # instructions
    SETBOUNDS = auto()
    FROMPTR = auto()
    ANDPERM = auto()
    # aggregate nodes
    PTR_SETBOUNDS = auto()


class CheriCap:
    """
    Hold the data of a CHERI capability.
    """

    MAX_ADDR = 0xffffffffffffffff
    MAX_OTYPE = 0x00ffffff

    def __init__(self, pct_cap=None):
        """
        Initialize CHERI capability data.

        :param pct_cap: pycheritrace capability
        :type pct_cap: :class:`pycheritrace.capability_register`
        """
        self.base = pct_cap.base if pct_cap else None
        """Capability base."""

        self.length = pct_cap.length if pct_cap else None
        """Capability length."""

        self.offset = pct_cap.offset if pct_cap else None
        """Capability offset."""

        self.permissions = pct_cap.permissions if pct_cap else None
        """Capability permissions bitmap."""

        self.objtype = pct_cap.type & self.MAX_OTYPE if pct_cap else None
        """Capability object type."""

        self.valid = pct_cap.valid if pct_cap else False
        """Is the capability valid?"""

        # XXX the unsealed property actually contains the sealed bit
        # the naming is confusing and should be changed.
        self.sealed = pct_cap.unsealed if pct_cap else False
        """Is the capability sealed?"""

        self.t_alloc = -1
        """Allocation time"""

        self.t_free = -1
        """Free time"""

    @property
    def bound(self):
        """Convenience property to get base + length."""
        if (self.base is not None and self.length is not None):
            return (self.base + self.length) % self.MAX_ADDR
        return None

    def __str__(self):
        """Get string representation of the capability."""
        base = "%x" % self.base if self.base is not None else "-"
        leng = "%x" % self.length if self.length is not None else "-"
        off = "%x" % self.offset if self.offset is not None else "-"
        perms = self.str_perm()
        objtype = "%x" % self.objtype if self.objtype is not None else "-"
        return "[b:%s o:%s l:%s p:(%s) t:%s v:%s s:%s] t_alloc:%d t_free:%d" % (
            base, off, leng, perms, objtype, self.valid, self.sealed,
            self.t_alloc, self.t_free)

    def has_perm(self, perm):
        """
        Check whether the node has the given permission bit set

        :param perm: permission bit
        :type perm: :class:`.CheriCapPerm`
        :return: True or False
        :rtype: bool
        """
        if self.permissions & perm:
            return True
        return False

    def str_perm(self):
        """
        Convert permission bitmask to human readable list of flags

        :return: string containing the names of the set permission bits
        :rtype: string
        """
        perm_string = ""
        if self.permissions:
            for perm in CheriCapPerm:
                if self.permissions & perm.value:
                    if perm_string:
                        perm_string += " "
                    perm_string += perm.name
        if not perm_string:
            perm_string = "None"
        return perm_string

    def __eq__(self, other):
        """
        Override equality test to have a shorthand way to
        compare capability equality.
        """
        return (self.base == other.base and
                self.length == other.length and
                self.offset == other.offset and
                self.permissions == other.permissions and
                self.objtype == other.objtype and
                self.valid == other.valid and
                self.sealed == other.sealed and
                self.t_alloc == other.t_alloc and
                self.t_free == other.t_free)

    def __ne__(self, other):
        return not self == other


class ProvenanceVertexData:
    """
    All the data associated with a node in the capability
    graph.
    """

    class EventType(IntFlag):
        LOAD = auto()
        """Vertex loaded from memory."""

        STORE = auto()
        """Vertex stored to memory."""

        DEREF_LOAD = auto()
        """Load via this vertex."""

        DEREF_STORE = auto()
        """Store via this vertex."""

        DEREF_CALL = auto()
        """Call via this vertex."""

        DEREF_IS_CAP = auto()
        """Dereference via this vertex targets a capability."""

        USE_CALL = auto()
        """Vertex used in a function call."""

        USE_CCALL = auto()
        """Vertex used in a domain transition."""

        USE_SYSCALL = auto()
        """Vertex used in a syscall."""

        USE_IS_ARG = auto()
        """Vertex used as an argument, w/o as a return value."""

        @classmethod
        def memop_mask(cls):
            """
            Return a mask of flags used to qualify events that
            represent a memory operation on this capability.
            """
            return (cls.LOAD | cls.STORE)

        @classmethod
        def deref_mask(cls):
            """
            Return a mask of flags used to qualify events that
            represent a dereference via this capability.
            """
            return (cls.DEREF_LOAD | cls.DEREF_STORE |
                    cls.DEREF_CALL | cls.DEREF_IS_CAP)

        @classmethod
        def use_mask(cls):
            """
            Return a mask of flags used to qualify events that
            represent an use instance of this capability in some
            kind of function/operation.
            """
            return (cls.USE_CALL | cls.USE_CCALL |
                    cls.USE_SYSCALL | cls.USE_IS_ARG)

    @classmethod
    def from_operand(cls, op):
        """
        Create data from a :class:`cheriplot.core.parser.Operand`
        """
        data = cls()
        if not op.is_register or not op.is_capability:
            logger.error("Attempt to create provenance node from "
                         "non-capability operand %s", op)
            raise ValueError("Operand is not a capability")
        data.cap = CheriCap(op.value)
        data.cap.t_alloc = op.instr.entry.cycles
        data.pc = op.instr.entry.pc
        data.is_kernel = op.instr.entry.is_kernel()
        return data

    def __init__(self):

        self.events = {"time": [], "addr": [], "type": []}
        """
        Event table. This is initialised as a fast-append structure.
        It will be transformed to a DataFrame for fast indexing/update
        when the parsing finishes.
        """

        self.cap = None
        """Cheri capability data, see :class:`.CheriCap`."""

        self.origin = CheriNodeOrigin.UNKNOWN
        """What produced this node."""

        self.pc = None
        """The PC of the instruction that produced this node."""

        self.is_kernel = False
        """
        XXX isn't this redundant? can we infer it from pc except maybe
        for the initial root registers.
        Is this node coming from a trace entry executed in kernel space?
        """

    @cached_property
    def event_tbl(self):
        """
        Tabular equivalent of ProvenanceVertexData.events for fast filtering and lookup.

        XXX since when this is used effectively doubles the space occupied by
        the address table we may want to destroy self.address and replace it
        with the dataframe. In the event of an address update the dataframe
        should be converted back to dict. This is assumed to be rare enough
        that the conversion cost is negligible vs the gain obtained by the
        fast mutability of the dict representation vs the fast indexing and filtering
        of dataframes.
        In general the mutable structure is used during graph construction,
        the dataframe is used during graph postprocessing.
        """
        df = pd.DataFrame(self.events)
        df = df.astype({"time": "u8", "addr": "u8", "type": "u4"}, copy=False)
        return df

    def add_event(self, time, addr, type_):
        """Append an event to the event table."""
        self.events["time"].append(time)
        self.events["addr"].append(addr)
        self.events["type"].append(type_)
        # invalidate cached property
        try:
            del self.__dict__["event_tbl"]
        except KeyError:
            pass

    def add_deref(self, time, addr, cap, type_):
        """
        Append a dereference event.

        :param time: time of dereference
        :param addr: target address
        :param cap: True if the reference targets a capability object
        :param type_: type of the dereference (load, store...),
        see :class:`EventType`
        """
        if cap:
            type_ |= ProvenanceVertexData.EventType.DEREF_IS_CAP
        self.add_event(time, addr, type_)

    def add_use(self, time, addr, arg_or_ret, type_):
        """
        Append an use event.

        :param time: time of dereference
        :param addr: address of symbol that uses this capability.
        In case of a system call this is the syscall code.
        :param arg_or_ret: True if the capability is used as an argument,
        False if it is used as a return value.
        :param type_: type of the use (call, syscall...),
        see :class:`EventType`
        """
        if arg_or_ret:
            type_ |= ProvenanceVertexData.EventType.USE_IS_ARG
        self.add_event(time, addr, type_)

    # shortcuts for use events
    add_use_call = partialmethod(add_use, type_=EventType.USE_CALL)
    add_use_ccall = partialmethod(add_use, type_=EventType.USE_CCALL)
    add_use_syscall = partialmethod(add_use, type_=EventType.USE_SYSCALL)

    # shortcuts for mem-op events
    add_mem_load = partialmethod(add_event, type_=EventType.LOAD)
    add_mem_store = partialmethod(add_event, type_=EventType.STORE)

    # shortcuts for dereference events
    add_deref_load = partialmethod(add_deref, type_=EventType.DEREF_LOAD)
    add_deref_store = partialmethod(add_deref, type_=EventType.DEREF_STORE)
    add_deref_call = partialmethod(add_deref, type_=EventType.DEREF_CALL)

    def __str__(self):
        return "%s origin:%s pc:0x%x kernel:%d" % (
            self.cap, self.origin.name, self.pc or 0, self.is_kernel)


class CallVertexData:
    """
    Data for vertices in the call layer of the graph.
    """

    def __init__(self, address):

        self.symbol = None
        """Symbol name of the callee."""

        self.symbol_file = None
        """File name where the callee symbol was found."""

        self.address = address
        """Address of the callee."""

        self.t_return = None
        """Time of the return."""

        self.addr_return = None
        """Address of the return instruction."""

    def __str__(self):
        if self.address is None:
            return "(unknown)"
        dump = "call 0x%x" % self.address
        if self.symbol is not None:
            dump += " (%s)" % self.symbol
        return dump


class EdgeOperation(IntEnum):
    """
    Enumeration representing valid operations that an edge can represent.
    """

    CALL = auto()
    """Call in the call layer."""

    SYSCALL = auto()
    """Syscall in the call layer."""

    CALL_TARGET = auto()
    """Capability used as call target, links provenance and call layers."""


class ProvenanceGraphManager:
    """
    Handle graph operations, load and save and
    provides shortcuts to the graph properties

    Graph vertex and edges have the following properties associated:

    * vertex

      * data (object): vertex data object, the type depends on the layer
      * layer_prov (bool): vertex belongs to the provenance layer
      * layer_call (bool): vertex belongs to the call layer
    * edge

      * operation (int): :class:`EdgeOperation` type for the operation
        represented by the edge
      * time (object): integer (uint64_t) marking the time of the event
    * graph

      * stack (object): initial stack :class:`CheriCap` object
    """

    def __init__(self, source, cache_file=None):
        """
        Create a graph manager. A new graph is generated
        if the cache file is not specified or does not exist.

        :param source: source file path
        :param cache_file: file where the graph is cached, if it exists the
        graph is loaded from the file. Default None.
        """
        self.source_file = source
        self.cache_file = cache_file

        if cache_file and os.path.exists(cache_file):
            with ProgressTimer("Load cached graph", logger):
                self.graph = load_graph(cache_file)
        else:
            self.graph = Graph()
            # CHERI capability properties
            # XXX unless graph-tool support uint64_t vertex properties
            # it makes no sense to split the content of the ProvenanceVertexData
            # class in multiple properites.
            prop_initial_stack = self.graph.new_graph_property("object")
            prop_data = self.graph.new_vertex_property("object")
            # edge properties
            prop_edge_op = self.graph.new_edge_property("int")
            prop_edge_time = self.graph.new_edge_property("object")
            prop_edge_address = self.graph.new_edge_property("object")
            # layers
            layer_prov = self.graph.new_vertex_property("bool", val=False)
            layer_call = self.graph.new_vertex_property("bool", val=False)
            self.graph.vp["data"] = prop_data
            self.graph.vp["layer_prov"] = layer_prov
            self.graph.vp["layer_call"] = layer_call
            self.graph.ep["operation"] = prop_edge_op
            self.graph.ep["time"] = prop_edge_time
            self.graph.ep["addr"] = prop_edge_address
            self.graph.gp["stack"] = prop_initial_stack

        self._init_props()

    def _init_props(self):
        """
        Setup graph property shorthand accessors.
        """
        # graph data
        self.data = self.graph.vp.data
        self.layer_prov = self.graph.vp.layer_prov
        self.layer_call = self.graph.vp.layer_call
        self.edge_operation = self.graph.ep.operation
        self.edge_time = self.graph.ep.time
        self.edge_addr = self.graph.ep.addr
        self.prov_view = GraphView(self.graph, vfilt=self.graph.vp.layer_prov)
        self.call_view = GraphView(self.graph, vfilt=self.graph.vp.layer_call)

    @property
    def stack(self):
        """Shorthand getter for the stack global property."""
        return self.graph.gp.stack

    @stack.setter
    def stack(self, value):
        """Shorthand setter for the stack global property."""
        self.graph.gp["stack"] = value

    @property
    def name(self):
        """Return the display name of the dataset"""
        base = os.path.basename(self.source_file)
        ext_start = base.rfind(".")
        if ext_start > 0:
            return base[:ext_start]
        return base

    @property
    def is_cached(self):
        return self.cache_file != None

    @property
    def cache_exists(self):
        return os.path.exists(self.cache_file)

    def load(self, cache_file):
        with ProgressTimer("Load cached graph", logger):
            self.graph = load_graph(cache_file)
        self.cache_file = cache_file
        self._init_props()

    def save(self, dest=None):
        if dest is None:
            dest = self.cache_file
        self.graph.save(dest)
