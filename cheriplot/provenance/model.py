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

from enum import IntEnum, IntFlag
from cached_property import cached_property
from functools import partialmethod
from collections import OrderedDict
from graph_tool.all import *

__all__ = ("CheriCapPerm", "CheriNodeOrigin", "CheriCap", "NodeData",
           "ProvenanceGraphManager")

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
    UNKNOWN = 0
    # partial result used in mutiprocessing parser
    PARTIAL = 1
    # root node
    ROOT = 2
    # instructions
    SETBOUNDS = 3
    FROMPTR = 4
    ANDPERM = 5
    # aggregate nodes
    PTR_SETBOUNDS = 6


class ProvenanceGraphManager:
    """
    Handle graph operations, load and save and
    provides shortcuts to the graph properties
    """

    def __init__(self, cache_file=None):
        """
        Create a graph manager. A new graph is generated
        if the cache file is not specified or does not exist.
        """
        self.cache_file = cache_file
        if cache_file and os.path.exists(cache_file):
            with ProgressTimer("Load cached graph", logger):
                self.graph = load_graph(cache_file)
        else:
            self.graph = Graph()
            # CHERI capability properties
            # prop_base = self.graph.new_vertex_property("object")
            # prop_len = self.graph.new_vertex_property("object")
            # prop_off = self.graph.new_vertex_property("object")
            # prop_perm = self.graph.new_vertex_property("int32_t")
            # prop_otype = self.graph.new_vertex_property("int32_t")
            # prop_valid = self.graph.new_vertex_property("bool")
            # prop_seal = self.graph.new_vertex_property("bool")
            # prop_t_alloc = self.graph.new_vertex_property("object")
            # prop_t_free = self.graph.new_vertex_property("object")
            prop_data = self.graph.new_vertex_property("object")
            self.graph.vp["data"] = prop_data
        self._init_props()

    def set_graph(self, graph):
        self.graph = graph
        self._init_props()

    @property
    def is_cached(self):
        return self.cache_file != None

    @property
    def cache_exists(self):
        return os.path.exists(cache_file)

    def _init_props(self):
        # graph data
        self.data = self.graph.vp.data
    
    def load(self, cache_file):
        with ProgressTimer("Load cached graph", logger):
            self.graph = load_graph(cache_file)
        self.cache_file = cache_file
        self._init_props()

    def save(self, dest=None):
        if dest is None:
            dest = self.cache_file
        self.graph.save(dest)


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


class NodeData:
    """
    All the data associated with a node in the capability
    graph.
    """

    class DerefType(IntEnum):
        """Types of capability dereference."""
        DEREF_LOAD = 1
        DEREF_STORE = 2
        DEREF_CALL = 3


    class CallType(IntFlag):
        """Types of uses of the capability vertex"""

        ARG = 1
        """Vertex is argument (set) or return value (unset)"""

        SYSCALL = 0x2
        """Vertex used in a syscall."""

        CALL = 0x4
        """Vertex used in a capability branch to a function."""

        CCALL = 0x8
        """Vertex used in a capability call domain transition."""


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
        self.address = OrderedDict()
        """
        Map the time when the capability is stored in memory to
        the address where it is stored location.
        """

        self.deref = {"time": [], "addr": [], "is_cap": [], "type": []}
        """
        Store dereferences of a capability, in a table-like structure,
        the type is defined in :class:`NodeData.DerefType`
        """

        self.call = {"time": [], "symbol": [], "type": []}
        """
        This vertex was returned by these functions/syscalls.
        XXX Maybe it can be merged in the deref data structure since
        the fields are basically the same
        """

        self.initial_stack = False
        """This vertex comes from the initial stack."""

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

    def add_deref(self, time, addr, cap, type_):
        """Append a dereference to the dereference table."""
        self.deref["time"].append(time)
        self.deref["addr"].append(addr)
        self.deref["is_cap"].append(cap)
        self.deref["type"].append(type_)

    def add_call_evt(self, time, symbol, type_):
        self.call["time"].append(time)
        self.call["symbol"].append(symbol)
        self.call["type"].append(type_)

    # shortcuts for add_deref
    add_load = partialmethod(add_deref, type_=DerefType.DEREF_LOAD)
    add_store = partialmethod(add_deref, type_=DerefType.DEREF_STORE)
    add_call = partialmethod(add_deref, type_=DerefType.DEREF_CALL)

    def __str__(self):
        return "%s origin:%s pc:0x%x (kernel %d)" % (
            self.cap, self.origin.name, self.pc or 0, self.is_kernel)
