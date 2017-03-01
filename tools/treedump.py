#-
# Copyright (c) 2017 Alfredo Mazzinghi
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

import argparse
import logging

from cheriplot.dbg import ProvenanceGraphInspector
from cheriplot.core.tool import Tool

logger = logging.getLogger(__name__)

def base16_int(value):
    if (value):
        return int(value, base=16)
    return None

class TreeDump(Tool):
    """
    Pytracedump is similar to cheri-tracedump although
    it has some additional features.
    """

    description = """
    Dump tool for the provenance tree. This allows to inspect the provenance tree
    in a non-graphical way and to perform filtering operations on the nodes in the tree.
    """

    def make_range_arg(self, argname, argtype, helpmsg):
        self.parser.add_argument("--%s" % argname, type=argtype, help=helpmsg)
        self.parser.add_argument("--%s-after" % argname, type=argtype,
                                 help="%s >= the value provided" % helpmsg)
        self.parser.add_argument("--%s-before" % argname, type=argtype,
                                 help="%s <= the value provided" % helpmsg)

    def init_arguments(self):
        super().init_arguments()

        origin_help = """Find nodes with the given origin flag, valid values are:
        - root: root nodes, no parents
        - csetbounds: nodes created via csetbounds
        - cfromptr: nodes created via cfromptr
        - ptrbounds: merged adjacent cfromptr+csetbounds
        - andperm: nodes created via candperm
        - mmap: nodes created by sys_mmap return
        """

        self.parser.add_argument("graph", help="Path to graph-tool gt file")
        self.parser.add_argument("--origin", help=origin_help)
        self.make_range_arg("pc", base16_int,
                            "Find all nodes created at PC")
        self.make_range_arg("time", int, "Find all nodes created at given time")
        self.make_range_arg("mem", base16_int,
                            "Show all nodes stored at a memory address")
        self.make_range_arg("deref", base16_int,
                            "Show all nodes dereferenced at a memory address")
        self.make_range_arg("size", base16_int, "Show nodes with length SIZE")

        self.parser.add_argument("--syscall", type=int, help="Show all syscall nodes")
        self.parser.add_argument("--perms", type=base16_int,
                                 help="Find nodes with given permission bits set.")
        self.parser.add_argument("--otype", type=base16_int,
                                 help="Find nodes with given otype.")

        self.parser.add_argument("--match-any", action="store_true",
                                 help="Return a trace entry when matches any"
                                 " of the conditions, otherwise all conditions"
                                 " must be verified.", default=False)
        self.parser.add_argument("--show-predecessors", action="store_true",
                                 help="Show the predecessors of a "
                                 "matching capability")

    def _run(self, args):

        inspect = ProvenanceGraphInspector(
            args.graph,
            match_origin=args.origin,
            match_pc_start=args.pc if args.pc else args.pc_after,
            match_pc_end=args.pc if args.pc else args.pc_before,
            match_mem_start=args.mem if args.mem else args.mem_after,
            match_mem_end=args.mem if args.mem else args.mem_before,
            match_deref_start=args.deref if args.deref else args.deref_after,
            match_deref_end=args.deref if args.deref else args.deref_before,
            match_alloc_start=args.time if args.time else args.time_after,
            match_alloc_end=args.time if args.time else args.time_before,
            match_len_start=args.size if args.size else args.size_after,
            match_len_end=args.size if args.size else args.size_before,
            match_syscall=args.syscall,
            match_perms=args.perms,
            match_otype=args.otype,
            match_any=args.match_any,
            show_predecessors=args.show_predecessors
        )

        inspect.dump()


def main():
    tool = TreeDump()
    tool.run()

if __name__ == "__main__":
    main()
