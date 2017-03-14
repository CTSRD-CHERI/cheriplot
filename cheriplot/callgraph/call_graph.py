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

from contextlib import suppress
from collections import deque
from graph_tool.all import *

from cheriplot.core import (
    CallbackTraceParser, Option, Argument, SubCommand, NestedConfig, TaskDriver,
    ConfigurableComponent, interactive_tool)
from cheriplot.callgraph.model import CallGraphManager
from cheriplot.callgraph.plot import CallGraphPlot

logger = logging.getLogger(__name__)

class CallGraphTraceParser(CallbackTraceParser, TaskDriver):
    """
    Dump a stack trace given a cheri trace instruction.
    We also detect all the functions that have been called and returned
    during the backtrace.

    Keep 2 data structures:
    - a deque that holds the last return address found
    - a pandas dataframe that holds the function landing pad and return points for nested functions

    The deque is used during parsing to detect nested functions and call sites
    The pandas dataframe holds:
    - the nested functions (symbol address, return address, parent symbol address, resolved symbol info)
    - the backtrace functions (symbol address, parent symbol address, resolved symbol info)
    Starting from the given instruction (cycle) iterate the trace
    backwards and detect all the (c)jalr and (c)jr instructions.
    When a <return> is found, it is added to the pandas dataset
    """

    start = Option(
        "-s",
        type=int,
        help="Backtrace starting from trace position",
        default=None)
    end = Option(
        "-e",
        type=int,
        help="Stop backtrace at given position",
        default=None)
    depth = Option(
        "-d",
        help="Build the call graph/backtrace for the "
        "last <depth> function calls",
        type=int,
        default=None)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self._backtrace_num = 0

        self.backtrace_depth = self.config.depth
        """Stop parsing after the backtrace has length <depth>"""

        self.return_stack = deque()
        """Stack of return instructions found"""

        self.call_site_map = {}
        """Map call site addresses to vertices"""

        self.cgm = CallGraphManager()
        """Handle the structure of the call graph"""

        self.root = self.cgm.graph.add_vertex()
        """
        Root is an empty node that is filled with the current function info
        as the trace is parsed backwards.
        """

    def parse(self, start=None, end=None):
        # parse from the given start backwards
        logger.info("Scan trace %s", self.path)
        super().parse(self.config.start, self.config.end, 1)

    def do_scan(self, inst, entry):
        """Decide whether we should scan this instruction or not"""
        if entry.is_kernel():
            return False
        return True

    def check_depth(self):
        """Check backtrace depth and decide whether to stop backtracing"""
        if self.backtrace_depth != None:
            if self.backtrace_depth <= self._backtrace_num:
                return True
        return False

    def add_call(self, target, time, pc):
        """
        Register a call in the call graph when the call is not part of
        the backtrace.
        A new edge is added between the current "root" vertex and the 
        call target vertex. If the target vertex does not exist it is
        created.
        """
        logger.debug("[%d] Call to 0x%x", time, target)
        # do we have a node for this call target?
        if target in self.call_site_map:
            target_vertex = self.call_site_map[target]
            # do we have already an edge towards that vertex?
            for e in self.root.out_edges():
                if e.target() == target_vertex:
                    # just increment the call count
                    call_edge = e
                    break
            else:
                # create the edge towards the target
                call_edge = self.cgm.graph.add_edge(self.root, target_vertex)
        else:
            # found a new call target, so create a vertex for it
            target_vertex = self.cgm.graph.add_vertex()
            self.cgm.addr[target_vertex] = target
            self.call_site_map[target] = target_vertex
            call_edge = self.cgm.graph.add_edge(self.root, target_vertex)
        self.cgm.t_call[call_edge].append(time)

    def add_backtrace(self, target, time, pc):
        """
        Register a call in the backtrace.
        Create a new "root" vertex and create an edge for the call between
        the new vertex and the current "root".
        If the current "root" vertex address exists in the graph reroute
        all edges from the current root to the duplicate vertex. This is
        required to handle recursion.
        """
        logger.debug("[%d] Backtrace call to 0x%x", time, target)
        if target in self.call_site_map:
            # there is already a vertex for the current function
            # take all edges from the current "root" and make them
            # start at the existing vertex, the root is not changed because
            # it stays empty and can be reused
            target_vertex = self.call_site_map[target]
            for e in self.root.out_edges:
                new_e = self.cgm.graph.add_edge(target_vertex, e.target())
                self.cgm.t_call[new_e] = self.cgm.t_call[e]
                self.cgm.backtrace[new_e] = self.cgm.backtrace[e]
                self.cgm.graph.remove_edge(e)
        else:
            self.cgm.addr[self.root] = target
            target_vertex = self.root
            self.root = self.cgm.graph.add_vertex()
        # connect the current root with the call target
        e = self.cgm.graph.add_edge(self.root, target_vertex)
        self.cgm.t_call[e].append(time)
        self.cgm.backtrace[e] = time
        self._backtrace_num += 1

    def scan_cjalr(self, inst, entry, regs, last_regs, idx):
        # check that the call matches the last return instruction
        # that we have
        if not self.do_scan(inst, entry):
            return False

        call = inst.op1.value
        ret = inst.op0.value

        if len(self.return_stack) > 0:
            # if there was a return, that must match this call
            cjr_addr, cjr_cycles, is_cap = self.return_stack.pop()
            if not is_cap:
                logger.error("cjalr matches a non-capability return %s", inst)
                raise RuntimeError("cjalr matches a non-capability return")
            # check return value
            if ret.base + ret.offset != cjr_addr:
                logger.error("cjalr specifies different return addr "
                             "0x%x != 0x%x, inst %s",
                             ret.base + ret.offset, cjr_addr, inst)
                raise RuntimeError("cjalr specifies different return addr")
            self.add_call(call.base + call.offset, entry.cycles, entry.pc)
        else:
            self.add_backtrace(call.base + call.offset, entry.cycles, entry.pc)
        return self.check_depth()

    def scan_cjr(self, inst, entry, regs, last_regs, idx):
        if not self.do_scan(inst, entry):
            return False
        ret_cap = inst.op0.value
        # append (addr, cycles, is_cap)
        self.return_stack.append((ret_cap.base + ret_cap.offset, entry.cycles, True))
        return self.check_depth()

    # def scan_jalr(self, inst, entry, regs, last_regs, idx):
    #     return False

    # def scan_jr(self, inst, entry, regs, last_regs, idx):
    #     ret_addr = inst.op0.value
    #     self.return_stack.append(("gpr", ret_addr, entry.pc))


@interactive_tool(key=["scan", "backtrace", "callgraph"])
class CallGraphDriver(TaskDriver):
    """
    Run component for the call-graph and backtrace generator.
    The scan config element holds the interactive-mode arguments,
    other options are fixed at instantiation.
    """

    description = "Generate call graph and stack traces from cvtrace files"

    trace = Argument(help="Path to cvtrace file")
    sym = Option(
        nargs="*",
        help="Binaries providing symbols",
        default=None)
    vmmap = Option(
        "-m",
        help="Memory map file that specifies base addresses for "
        "the binaries in --sym",
        default=None)
    scan = NestedConfig(CallGraphTraceParser)
    backtrace = SubCommand(help="Plot the call graph")
    callgraph = SubCommand(CallGraphPlot, help="Show the backtrace")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.parser = CallGraphTraceParser(trace_path=self.config.trace,
                                           config=self.config.scan)

    def update_config(self, config):
        super().update_config(config)
        self.parser.update_config(config.scan)

    def run(self):
        self.parser.parse()
        # get the parsed model
        cgm = self.parser.cgm
        # if we have symbols and a vmmap, add symbols to the call graph
        if self.config.sym and self.config.vmmap:
            add_symbols = CallGraphAddSymbols(cgm, self.config.sym,
                                              self.config.vmmap)
            cgm.bfs_transform(add_symbols)
        with suppress(AttributeError):
            if self.config.backtrace:
                self.call_graph_backtrace(cgm)
        with suppress(AttributeError):
            if self.config.callgraph:
                self.plot = CallGraphPlot(config=self.config.callgraph)
                self.plot.plot(cgm)

    def call_graph_backtrace(self, cgm):
        """
        Dump the backtrace from the call graph parsed in the parser.
        """
        has_backtrace_info = cgm.graph.new_edge_property("bool")
        map_property_values(cgm.backtrace, has_backtrace_info,
                            lambda b: b != 0)
        cgm.graph.set_edge_filter(has_backtrace_info)

        bt = sorted(cgm.graph.edges(), key=lambda e: cgm.backtrace[e])
        for e in bt:
            fn_time = cgm.backtrace[e]
            fn_addr = cgm.addr[e.source()]
            fn_name = cgm.name[e.source()]
            print("[%d] 0x%x %s" % (fn_time, fn_addr, fn_name))
        cgm.graph.clear_filters()
