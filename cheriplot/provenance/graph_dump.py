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

import logging

from io import StringIO
from itertools import repeat

import numpy as np

from cheriplot.core import (
    BaseToolTaskDriver, Argument, Option, option_range_validator,
    any_int_validator)
from cheriplot.provenance.model import (
    CheriNodeOrigin, ProvenanceVertexData, ProvenanceGraphManager,
    EdgeOperation)

logger = logging.getLogger(__name__)

class ProvenanceGraphDumpDriver(BaseToolTaskDriver):
    """
    Dump and manually filter the nodes in the
    provenance graph.
    """

    range_format_help = "Accept a range in the form <start>-<end>, -<end>, "\
                        "<start>- or <single_value>"

    graph = Argument(help="Path to the provenance graph file")
    layer = Option(
        help="Graph layer to dump.",
        choices=("prov", "call", "all"),
        default="all")
    # provenance layer filters
    origin = Option(
        help="Find vertices with specific origin.",
        choices=("root", "csetbounds", "cfromptr", "ptrbounds",
                 "candperm", "partial", "call", "syscall"),
        default=None)
    pc = Option(
        type=option_range_validator,
        default=None,
        help="Find vertices with PC in the given range. " + range_format_help)
    time = Option(
        type=option_range_validator,
        help="Find all vertices created at given time. " + range_format_help)
    lifetime = Option(
        type=option_range_validator,
        help="Find all vertices with a lifetime (t_free - t_alloc) "
        "in the given range. " + range_format_help)
    mem = Option(
        type=option_range_validator,
        help="Show all vertices stored at a memory address. " + range_format_help)
    deref = Option(
        type=option_range_validator,
        help="Show all vertices dereferenced at a memory address. " + range_format_help)
    size = Option(
        type=option_range_validator,
        help="Show vertices with given length. " + range_format_help)
    perms = Option(
        type=any_int_validator,
        help="Find vertices with given permission bits set.")
    otype = Option(
        type=any_int_validator,
        help="Find vertices with given object type.")
    match_any = Option(
        action="store_true",
        help="Return a trace entry when matches any"
        " of the conditions, otherwise all conditions"
        " must be verified.")
    predecessors = Option(
        action="store_true",
        help="Show the predecessors of a matching capability.")
    successors = Option(
        action="store_true",
        help="Show the successors of a matching capability.")
    full_info = Option(
        action="store_true",
        help="Show the full vertex information")
    # call layer filters
    target = Option(
        help="Show calls to the given target address or symbol name.")
    related = Option(
        action="store_true",
        help="Show vertices in the provenance layer related to each call.")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.pgm = ProvenanceGraphManager.load(self.config.graph)
        """Manager for the graph to dump."""

        self.match_origin = None
        """Search for nodes with this origin"""

        self._check_origin_arg(self.config.origin)

        self.prov_filters = [
            self._match_origin,
            self._match_pc,
            self._match_mem,
            self._match_deref,
            self._match_perms,
            self._match_otype,
            self._match_alloc,
            self._match_len,
            self._match_lifetime,
        ]
        self.call_filters = [
            self._match_call_type,
        ]

    def _check_origin_arg(self, match_origin):
        if match_origin == None:
            return
        elif match_origin == "root":
            self.match_origin = CheriNodeOrigin.ROOT
        elif match_origin == "csetbounds":
            self.match_origin = CheriNodeOrigin.SETBOUNDS
        elif match_origin == "cfromptr":
            self.match_origin = CheriNodeOrigin.FROMPTR
        elif match_origin == "ptrbounds":
            self.match_origin = CheriNodeOrigin.PTR_SETBOUNDS
        elif match_origin == "andperm":
            self.match_origin = CheriNodeOrigin.ANDPERM
        elif match_origin == "partial":
            self.match_origin = CheriNodeOrigin.PARTIAL
        elif match_origin == "call":
            self.match_origin = EdgeOperation.CALL
        elif match_origin == "syscall":
            self.match_origin = EdgeOperation.SYSCALL
        else:
            raise ValueError("Invalid match_origin parameter")

    def _update_match_result(self, match, value):
        """
        Combine the current match result with the value of
        a test according to the match mode.
        """
        if value is None:
            return match
        if self.config.match_any:
            return match or value
        else:
            return match and value

    def _check_limits(self, start, end, value):
        if start is None:
            start = 0
        if end is None:
            end = np.inf
        if start <= value and value <= end:
            return True
        return False

    def _match_lifetime(self, edge, vdata):
        if self.config.lifetime:
            start, end = self.config.lifetime
            if vdata.cap.t_free >= 0:
                lifetime = vdata.cap.t_free - v_data.cap.t_alloc
            else:
                lifetime = np.inf
            return self._check_limits(start, end, lifetime)
        return None

    def _match_origin(self, edge, vdata):
        if self.match_origin:
            return vdata.origin == self.match_origin
        return None

    def _match_pc(self, edge, vdata):
        if self.config.pc:
            start, end = self.config.pc
            return self._check_limits(start, end, vdata.pc)
        return None

    def _match_mem(self, edge, vdata):
        if self.config.mem:
            start, end = self.config.mem
            result = False
            for addr in vdata.address["addr"]:
                result |= self._check_limits(start, end, addr)
                if result:
                    break
            return result
        return None

    def _match_deref(self, edge, vdata):
        if self.config.deref:
            start, end = self.config.deref
            result = False
            for addr in vdata.deref["addr"]:
                result |= self._check_limits(start, end, addr)
                if result:
                    break
            return result
        return None

    def _match_perms(self, edge, vdata):
        if self.config.perms:
            return vdata.cap.has_perm(self.config.perms)
        return None

    def _match_otype(self, edge, vdata):
        if self.config.otype:
            return vdata.cap.objtype == self.config.otype
        return None

    def _match_alloc(self, edge, vdata):
        if self.config.time:
            start, end = self.config.time
            return self._check_limits(start, end, vdata.cap.t_alloc)
        return None

    def _match_len(self, edge, vdata):
        if self.config.size:
            start, end = self.config.size
            return self._check_limits(start, end, vdata.cap.length)
        return None

    def _match_call_type(self, edge, vdata):
        if self.config.origin and edge is not None:
            eop = self.pgm.edge_operation[edge]
            return eop == self.match_origin
        return None

    def _dump_prov_vertex(self, edge, v):
        vdata = self.pgm.data[v]
        str_vertex = StringIO()
        str_vertex.write("(provenance) {} ".format(vdata))
        events = vdata.event_tbl
        n_load = (events["type"] & ProvenanceVertexData.EventType.DEREF_LOAD).sum()
        n_store = (events["type"] & ProvenanceVertexData.EventType.DEREF_STORE).sum()
        str_vertex.write(
            "deref-load: {:d} deref-store: {:d} ".format(n_load, n_store))
        n_loaded = (events["type"] & ProvenanceVertexData.EventType.LOAD).sum()
        n_stored = (events["type"] & ProvenanceVertexData.EventType.STORE).sum()
        str_vertex.write("load: {:d} store: {:d}".format(n_loaded, n_stored))
        if self.config.full_info:
            str_vertex.write("\n")
            frame_str = vdata.event_tbl.to_string(formatters={
                "addr": "0x{0:x}".format,
                "type": lambda t: str(ProvenanceVertexData.EventType(t))
            })
            str_vertex.write("Event table:\n{}\n".format(frame_str))
        return str_vertex.getvalue()

    def _dump_call_vertex(self, edge, v):
        vdata = self.pgm.data[v]
        str_vertex = StringIO()
        if edge is not None:
            eop = EdgeOperation(self.pgm.edge_operation[edge])
            eaddr = self.pgm.edge_addr[edge]
            etime = self.pgm.edge_time[edge]
        else:
            eop = None
            eaddr = etime = 0
        str_vertex.write(
            "(call) op:{!s} caller:0x{:x} t_call:{:d} {!s}\n".format(
                eop, eaddr, etime, vdata))
        return str_vertex.getvalue()

    def _dump_vertex(self, edge, v):
        if self.pgm.layer_prov[v]:
            return self._dump_prov_vertex(edge, v)
        elif self.pgm.layer_call[v]:
            return self._dump_call_vertex(edge, v)
        else:
            logger.warning("dump_vertex: invalid layer %s", self.pgm.data[v])

    def _dump_predecessors(self, view, v):
        if not self.config.predecessors or v is None:
            return
        predecessors = []
        current = v
        while True:
            parent, edge = self._get_parent(view, current)
            predecessors.insert(0, (current, edge))
            if parent is None:
                break
            current = parent
        for pred, edge in predecessors:
            print("+- {}".format(self._dump_vertex(edge, pred)))
            print("^")

    def _dump_successors(self, v):
        if not self.config.successors:
            return
        vertices = list(zip(repeat(1), repeat(v), v.out_neighbours()))
        # list of tuples (depth, vertex)
        while len(vertices):
            depth, parent, s = vertices.pop(0)
            edge = self.pgm.graph.edge(parent, s)
            successors = list(
                zip(repeat(depth + 1), repeat(s), s.out_neighbours()))
            successors.extend(vertices)
            vertices = successors
            space = "  " * depth
            print("{}+- {}".format(space, self._dump_vertex(edge, s)))

    def _dump_related(self, v):
        if not self.config.related or not self.pgm.layer_call[v]:
            return
        for edge in v.in_edges():
            if not self.pgm.layer_prov[edge.source()]:
                continue
            eop = self.pgm.edge_operation[edge]
            src = self.pgm.data[edge.source()]
            print("[{}] +-> {}".format(eop, src))

    def _get_parent(self, view, v):
        """
        Get the parent vertex in the given layer and the connecting
        edge.
        """
        parents = list(v.in_neighbours())
        if len(parents) == 0:
            return None, None
        return parents[0], view.edge(parents[0], v)

    def _dump_layer(self, view):
        for v in view.vertices():
            vdata = self.pgm.data[v]
            parent, edge = self._get_parent(view, v)
            # initial match value, if match_any is true
            # we OR the match results so start with false
            # else we AND them, so start with true
            match = not self.config.match_any
            if self.pgm.layer_prov[v]:
                filters = self.prov_filters
            elif self.pgm.layer_call[v]:
                filters = self.call_filters
            else:
                logger.warning("dump_layer: invalid layer %s", vdata)

            for checker in filters:
                result = checker(edge, vdata)
                match = self._update_match_result(match, result)
            if match:
                self._dump_predecessors(view, parent)
                print("+- {}".format(self._dump_vertex(edge, v)))
                self._dump_related(v)
                self._dump_successors(v)
                print("######")

    def run(self):
        if self.config.layer == "all" or self.config.layer == "prov":
            self._dump_layer(self.pgm.prov_view())
        if self.config.layer == "all" or self.config.layer == "call":
            self._dump_layer(self.pgm.call_view())
