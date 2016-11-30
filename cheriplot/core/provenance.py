#-
# Copyright (c) 2016 Alfredo Mazzinghi
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

from enum import IntEnum

from graph_tool.all import *

class CheriCapPerm(IntEnum):
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
    SYSTEM_REGISTERS = 1 << 10


class CheriNodeOrigin(IntEnum):
    """
    Enumeration of the possible originators of
    nodes in the provenance graph.
    """
    
    UNKNOWN = -1
    ROOT = 0
    # instructions
    SETBOUNDS = 1
    FROMPTR = 2
    # aggregate nodes
    PTR_SETBOUNDS = 3
    # system calls
    SYS_MMAP = 4


class CheriCap:
    """
    Hold the data of a CHERI capability.
    """

    MAX_ADDR = 0xffffffffffffffff

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

        self.valid = pct_cap.valid if pct_cap else False
        """Is the capability valid?"""

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
        base = self.base if self.base is not None else 0
        leng = self.length if self.length is not None else 0
        off = self.offset if self.offset is not None else 0
        perms = self.str_perm()
        return "[b:%x o:%x l:%x p:%s v:%s]" % (
            base, off, leng, perms, self.valid)

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


class NodeData:
    """
    All the data associated with a node in the capability
    graph.
    """

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
        data.is_kernel = bool(op.instr.entry.is_kernel)
        return data

    def __init__(self):
        self.address = {}
        """
        Map the address where the node is stored to a list
        of times (cycle number) when the node is stored to that
        location.
        """
        self.cap = None
        """Cheri capability data, see :class:`.CheriCap`."""

        self.origin = CheriNodeOrigin.UNKNOWN
        """What produced this node."""

        self.pc = None
        """The PC of the instruction that produced this node."""

        self.is_kernel = False
        """Is this node coming from a trace entry executed in kernel space?"""

    def __str__(self):
        return "%s origin:%s pc:0x%x (kernel %d)" % (
            self.cap, self.origin.name, self.pc or 0, self.is_kernel)


### all good until here
# keeping the abstraction may too costly, without further justification it is
# not worth spending time on it so try without it.
        
class GraphNode:
    """
    Interface representation of a provenance graph node

    This abstract the internal graph representation of
    the node properties
    """

    @classmethod
    def from_operand(cls, op):
        """
        Create a node from a :class:`cheriplot.core.parser.Operand`
        """

        data = NodeData()
        if not op.is_register or not op.is_capability:
            logger.error("Attempt to create provenance node from "
                         "non-capability operand %s", op)
            raise ValueError("Operand is not a capability")
        data.cap = CheriCap(op.value)
        data.cap.t_alloc = op.instr.entry.cycles
        data.pc = op.instr.entry.pc
        data.is_kernel = op.instr.entry.is_kernel
        node = cls(data)
        return node

    @classmethod
    def from_vertex(cls, mgr, v):
        node = cls(mgr._graph.vp.data[v])
        node._mgr = mgr
        node._vertex = v
        return node

    def __init__(self, data=None):
        """
        Create new node data instance.
        
        Each node data is associated to a vertex
        handle in the graph, the handle is used
        to perform graph operations.
        """
        self._data = data if data is not None else NodeData()
        """The data associated to this node."""

        self._vertex = None
        """Reference to the corresponding :class:`graph_tool.Vertex`."""

        self._mgr = None
        """Reference to the graph manager :class:`.GraphManager`."""

    @property
    def data(self):
        """Node data getter."""
        return self._data

    @data.setter
    def set_data(self, data):
        """
        Setter for the data property.

        If the node is in the graph, we need to keep in sync the
        internal reference to the data and the data associated to
        the graph vertex.
        """
        self._data = data
        if self._vertex:            
            self._mgr._graph.vp.data[self._vertex] = data

    def add(self, node):
        """
        Add given node as a successor of this node.

        :param node: the child node to add
        :type node: :class:`.GraphNode`
        """
        if not (self._vertex and self._graph):
            logger.error("Attempt to add node %s to this node %s, "
                         "but this node is not in the graph", node, self)
            raise RuntimeError("Can not add node to a node that is "
                               "not in the graph")
        self._mgr.add(self, node)

    def __iter__(self):
        """
        Iterate over direct children
        """
        for v in self._vertex.out_neighbours():
            yield GraphNode.from_vertex(self._mgr, v)


class GraphManager:
    """
    Graph dataset manager.

    This decouples the graph library from the cheriplot dataset
    because I got bored of changing things around when trying
    a new graph library.
    The idea is the if we change graph library for some reason
    only :class:`.GraphManager` and :class:`.ProvenanceTreeNode`
    have to change. Algorithms that modify the graph should be
    implemented in subclasses of :class:`.GraphManager`.
    """

    @classmethod
    def empty(cls):
        """
        Create new empty graph.
        """
        graph = Graph(directed=True)
        # create graph properties
        vdata = graph.new_vertex_property("object")
        graph.vertex_properties["data"] = vdata
        mgr = cls(graph)
        return mgr

    @classmethod
    def from_file(cls, path):
        """
        Load provenance graph from file
        """
        graph = load_graph(path)
        mgr = cls(graph)
        return mgr

    def __init__(self, graph):
        """
        Initialise manager private data to defaults.

        To create or load a graph use :meth:`.GraphManager.from_file`
        and :meth:`.GraphManager.emtpy`.

        :param graph: a graph-tool graph
        :type graph: :class:`graph_tool.Graph`
        """
        self._graph = graph
        """The graph-tool graph"""

    def __len__(self):
        """Return the number of vertices in the graph"""
        return self._graph.num_vertices()

    def save(self, filename):
        """
        Save graph to file.
        """
        self.graph.save(filename)

    def add(self, parent, node):
        """
        Add new node to given parent.
        """
        if node._vertex != None:
            # node already in the graph
            if (node._vertex in parent._vertex.out_neighbours() or
                node._vertex in parent._vertex.in_neighbours()):
                logger.error("Nodes %s and %s are already connected")
                raise RuntimeError("Can not connect same nodes multiple times")
            new_v = node._vertex
        else:
            new_v = self._graph.add_vertex()
            node._vertex = new_v
            node._mgr = self
        self._graph.vp.data[new_v] = node.data
        if parent:
            # if this is not a root node attach it
            self._graph.add_edge(parent._vertex, new_v)

    def remove(self, nodes):
        """
        Remove one or more nodes from the graph
        along with all adjacent edges.
        """
        try:
            vertices = [n._vertex for n in nodex]
        except TypeError:
            # nodes is not iterable, is a single node
            vertices = nodes._vertex
        self._graph.remove_vertex(vertices)

    def __iter__(self):
        """
        Iterate over all the nodes in the graph.
        """
        for v in self._graph.vertices():
            yield GraphNode.from_vertex(self, v)
