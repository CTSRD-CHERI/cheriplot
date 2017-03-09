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

from cheriplot.core import run_driver_tool
from cheriplot.dbg import PytracedumpDriver

logger = logging.getLogger(__name__)

#         # trace backtrace arguments
#         sub_back.set_defaults(operation=self._backtrace)
#         sub_back.add_argument("-s", "--start", type=int,
#                               help="Backtrace starting from this cycle",
#                               required=True)
#         sub_back.add_argument("-e", "--end", type=int,
#                               help="stop backtrace at given cycle, note"
#                               "that [end] < [start] because we scan backwards")
#         sub_back.add_argument("-c", "--cache",
#                               help="save a copy of the call graph",
#                               action="store_true", default=False)
#         sub_back.add_argument("--depth", type=int,
#                               help="Stop backtracing after <depth> levels")
#         sub_back.add_argument("--call-graph", help="Plot the call graph",
#                               action="store_true")
#         sub_back.add_argument("--bt", help="Show the backtrace",
#                               action="store_true")
#         sub_back.add_argument("-o", "--outfile",
#                               help="Save plot to file, see matplotlib for "
#                               "supported formats (svg, png, pgf...)")
#         sub_back.add_argument("--sym", nargs="*", help="Binaries providing symbols")
#         sub_back.add_argument("-m", "--vmmap", help="Memory map file generated"
#                               " by vmmap_dump, required for --sym")


#     def _backtrace(self, args):

#         if args.sym != None and len(args.sym) > 0 and args.vmmap == None:
#             logger.error("--sym files can be specified only if the process "
#                          "memory map is given (-m)")
#             return

#         if args.call_graph:
#             call_graph = CallGraphPlot(args.trace, cache=args.cache)
#             call_graph.bt_start = args.start
#             call_graph.bt_end = args.end
#             call_graph.bt_depth = args.depth
#             call_graph.sym_files = args.sym
#             call_graph.sym_vmmap = args.vmmap
#             if args.outfile:
#                 call_graph.plot_file = args.outfile
#             call_graph.show()
#         else:
#             parser = CallGraphTraceParser(args.trace, args.cache,
#                                           depth=args.depth)
#             parser.parse(args.start, args.end)
#             if args.vmmap:
#                 add_symbols = CallGraphAddSymbols(parser.cgm, args.sym, args.vmmap)
#                 parser.cgm.bfs_transform(add_symbols)
#             if args.bt:
#                 call_graph_backtrace(parser)
#             else:
#                 parser.cgm.dump()

def main():
    run_driver_tool(PytracedumpDriver)

if __name__ == "__main__":
    main()
