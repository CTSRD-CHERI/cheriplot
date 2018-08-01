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
from contextlib import suppress

import numpy as np
import pandas as pd
from sortedcontainers import SortedSet
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
    CCALL = 1 << 8
    UNSEAL = 1 << 9
    SYSTEM_REGISTERS = 1 << 10

    @classmethod
    def all(cls):
        return (cls.GLOBAL | cls.EXEC | cls.LOAD | cls.STORE |
                cls.CAP_LOAD | cls.CAP_STORE | cls.CAP_STORE_LOCAL |
                cls.SEAL | cls.SYSTEM_REGISTERS | cls.CCALL | cls.UNSEAL)


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

    MAX_OTYPE = 0x00ffffff

    @classmethod
    def from_copy(cls, other):
        """Create a copy of a CheriCap."""
        cap = cls()
        cap.base = other.base
        cap.length = other.length
        cap.offset = other.offset
        cap.permissions = other.permissions
        cap.objtype = other.objtype
        cap.valid = other.valid
        cap.sealed = other.sealed
        cap.t_alloc = other.t_alloc
        cap.t_free = other.t_free
        return cap

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
            return self.base + self.length
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

        DELETE = auto()
        """Vertex removed from a memory location."""

        @classmethod
        def memop_mask(cls):
            """
            Return a mask of flags used to qualify events that
            represent a memory operation on this capability.
            """
            return (cls.LOAD | cls.STORE | cls.DELETE)

        @classmethod
        def deref_mask(cls):
            """
            Return a mask of flags used to qualify events that
            represent a dereference via this capability.
            """
            return (cls.DEREF_LOAD | cls.DEREF_STORE |
                    cls.DEREF_CALL | cls.DEREF_IS_CAP)

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

        self._active_memory = {}
        """Map active memory addresses to rows in the events table."""

    @property
    def active_memory(self):
        """XXX temporary alias to avoid rebuilding existin graphs."""
        return self._active_memory

    @active_memory.setter
    def active_memory(self, val):
        """XXX temporary alias to avoid rebuilding existin graphs."""
        self._active_memory = val

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
        with suppress(KeyError):
            del self.__dict__["event_tbl"]
        if type_ == ProvenanceVertexData.EventType.STORE:
            self._active_memory[addr] = len(self.events["time"]) - 1
        elif type_ == ProvenanceVertexData.EventType.DELETE:
            with suppress(KeyError):
                del self._active_memory[addr]

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

    def get_active_memory(self):
        """
        Return a list of memory addresses where the vertex is
        currently stored, based on the event table.
        Note: this relies on temporal ordering of entries in the event
        table, no sorting is done.
        """
        return self.active_memory.keys()

    def has_active_memory(self):
        """
        Check whether this vertex is currnetly stored in memory.
        """
        return len(self.active_memory) > 0

    # shortcuts for mem-op events
    add_mem_load = partialmethod(add_event, type_=EventType.LOAD)
    add_mem_store = partialmethod(add_event, type_=EventType.STORE)
    add_mem_del = partialmethod(add_event, type_=EventType.DELETE)

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

        self.stack_frame_base = None
        """Base address of the function call stack frame."""

        self.stack_frame_size = 0
        """Size of the function call stack frame."""

    def __str__(self):
        if self.address is None:
            addr = "(unknown/root)"
        else:
            addr = "0x{:x}".format(self.address)
        if self.addr_return is None:
            addr_ret = None
        else:
            addr_ret = "0x{:x}".format(self.addr_return)
        if self.t_return is None:
            t_ret = None
        else:
            t_ret = "{:d}".format(self.t_return)
        if self.symbol is None:
            symbol = ""
        else:
            symbol = "({}){}".format(self.symbol_file, self.symbol)
        dump = "call {} target:{}, ret:{} @ t_ret={}".format(
            symbol, addr, addr_ret, t_ret)
        if self.symbol is not None:
            dump += " ({})".format(self.symbol)
        return dump

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return (self.address == other.address and
                self.t_return == other.t_return and
                self.addr_return == other.addr_return)


class EdgeOperation(IntEnum):
    """
    Enumeration representing valid operations that an edge can represent.
    """

    UNKNOWN = 0

    CALL = auto()
    """Call in the call layer."""

    SYSCALL = auto()
    """Syscall in the call layer."""

    CALL_TARGET = auto()
    """Capability used as call target, links provenance and call layers."""

    VISIBLE = auto()
    """Capability visible (from the register set) in a called function."""

    RETURN = auto()
    """Capability visible at the time of return."""


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
      * time (object): integer (uint64_t) meaning depends on the operation:
        * CALL/SYSCALL: marking the time of the event
        * VISIBLE/RETURN: index of the register where the visible capability was found
      * addr (object): integer (uint64_t) meaning depends on the operation:
        * CALL/SYSCALL: address of the call instruction
        * VISIBLE: offset of the capability that is visible (source vertex)
        * RETURN: offset of the capability that is marked
          as return (source vertex)
      * reg (int): Only valid for VISIBLE edges, index of the register where
        the source vertex is found at the time of the call. This is used to
        link capabilities to function arguments.
    * graph

      * stack (object): initial stack :class:`CheriCap` object
    """

    @classmethod
    def load(cls, source):
        """
        Create a graph manager for an existing graph.
        The graph is loaded from the given source file.

        :param source: source file path
        """
        pgm = cls(source)
        with ProgressTimer("Load graph ({})".format(source), logger):
            pgm.graph = load_graph(source)
            pgm.graph.set_directed(True)
        pgm._init_props()
        return pgm

    def __init__(self, outfile):
        """
        Create the graph manager with an empty graph.

        :param outfile: The output file path
        """
        self.outfile = outfile
        """Output graph file."""

        self.graph = Graph(directed=True)
        """The graph instance."""

        # XXX unless graph-tool support uint64_t vertex properties
        # it makes no sense to split the content of the ProvenanceVertexData
        # class in multiple properites.

        # graph properties
        prop_graph_name = self.graph.new_graph_property("string")
        prop_initial_stack = self.graph.new_graph_property("object")
        # vertex properties
        prop_data = self.graph.new_vertex_property("object")
        layer_prov = self.graph.new_vertex_property("bool", val=False)
        layer_call = self.graph.new_vertex_property("bool", val=False)
        # edge properties
        prop_edge_op = self.graph.new_edge_property("int", val=0)
        prop_edge_regs = self.graph.new_edge_property("vector<int>")
        prop_edge_time = self.graph.new_edge_property("object")
        prop_edge_address = self.graph.new_edge_property("object")
        self.graph.vp["data"] = prop_data
        self.graph.vp["layer_prov"] = layer_prov
        self.graph.vp["layer_call"] = layer_call
        self.graph.ep["operation"] = prop_edge_op
        self.graph.ep["time"] = prop_edge_time
        self.graph.ep["addr"] = prop_edge_address
        self.graph.ep["regs"] = prop_edge_regs
        self.graph.gp["stack"] = prop_initial_stack
        self.graph.gp["name"] = prop_graph_name

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
        self.edge_regs = self.graph.ep.regs
        self.stack_capability = self.graph.gp.stack

    def prov_view(self):
        """Provenance graph layer."""
        return GraphView(self.graph, vfilt=self.graph.vp.layer_prov)

    def call_view(self):
        """Call graph layer."""
        return GraphView(self.graph, vfilt=self.graph.vp.layer_call)

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
        """
        Return the display name of the dataset.
        The name is defined in a graph property or
        is the base name of the output file.
        """
        if self.graph.gp.name is None:
            base = os.path.basename(self.outfile)
            ext_start = base.rfind(".")
            if ext_start > 0:
                return base[:ext_start]
            return base
        else:
            return self.graph.gp.name

    def save(self, outfile=None, name=None):
        """
        Save the graph to a file.

        :param dest: output file path, default to the manager outfile
        :param name: a name given to the dataset for display (e.g. legends)
        """
        dest = outfile or self.outfile
        if name is not None:
            self.graph.gp.name = name
        self.graph.save(dest)
