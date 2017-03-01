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
Python version of cheritrace tracedump tool

This will probably be split in multiple tools or at least
change name to pycheridbg.
"""

import argparse
import logging

from cheriplot.dbg.parser import TraceDumpParser
from cheriplot.dbg.call_graph import CallGraphTraceParser, call_graph_backtrace
from cheriplot.plot.call_graph import CallGraphPlot
from cheriplot.graph.call_graph import CallGraphAddSymbols
from cheriplot.core.tool import Tool

logger = logging.getLogger(__name__)

def base16_int(value):
    if (value):
        return int(value, base=16)
    return None

class PyTraceDump(Tool):
    """
    Pytracedump is similar to cheri-tracedump although
    it has some additional features.
    """

    description = "CHERI trace debugger"

    scan_description = """Dump CHERI binary trace (python version of cheri-tracedump).
    Each instruction entry has the following format:
    {<ASID>:<instruction_cycle_number>} <PC> <instr_mnemonic> <operands>

    Memory accesses show the referenced address in the line below:
    <target_register> = [<hex_addr>] or [<hex_addr>] = <source_register>

    Capabilities as displayed in the following format:
    [b:<base> o:<offset> l:<length> p:<permission> t:<obj_type> v:<valid> s:<sealed>]
    t_alloc and t_free are only relevant in the provenance graph.

    When dumping the register set, the format of each entry is the following:
    [<register_value_valid>] <register> = <value>"""

    back_description = "Dump a backtrace from the cheri trace"

    def init_arguments(self):
        super(PyTraceDump, self).init_arguments()

        sub = self.parser.add_subparsers(help="pytracedump operations")
        sub_scan = sub.add_parser("scan", help=self.scan_description)
        sub_back = sub.add_parser("backtrace", help=self.back_description)
        self.parser.add_argument("trace", help="Path to trace file")

        # trace scan arguments
        sub_scan.set_defaults(operation=self._scan)
        sub_scan.add_argument("-s", "--start", type=int, default=None,
                              help="Start at given offset")
        sub_scan.add_argument("-e", "--end", type=int, default=None,
                              help="Stop at given offset")
        sub_scan.add_argument("-i", "--info",
                              help="Print trace info and exit",
                              action="store_true")
        sub_scan.add_argument("-r", "--show-regs", help="Dump register content",
                              action="store_true")
        sub_scan.add_argument("--instr",
                              help="Find instruction occurrences")
        sub_scan.add_argument("--pc", type=base16_int,
                              help="Find all instructions with of given PC")
        sub_scan.add_argument("--pc-after", type=base16_int,
                              help="Find all instructions with PC higher than the given one")
        sub_scan.add_argument("--pc-before", type=base16_int,
                              help="Find all instructions with PC lower than the given one")
        sub_scan.add_argument("--reg",
                              help="Show all the instructions that touch"
                              " a given register")
        sub_scan.add_argument("--mem", type=base16_int,
                              help="Show all the instructions that touch"
                              " a given memory address")
        sub_scan.add_argument("--mem-after", type=base16_int,
                              help="Find all instructions with access memory after this address")
        sub_scan.add_argument("--mem-before", type=base16_int,
                              help="Find all instructions with access memory before this address")
        sub_scan.add_argument("--exception", type=str,
                              help="Show all the instructions that raise"
                              " a given exception")
        sub_scan.add_argument("--syscall", type=int,
                              help="Show all the syscalls with given code")
        sub_scan.add_argument("--nop", type=base16_int,
                              help="Show all the canonical nops with"
                              " given code.")
        sub_scan.add_argument("--perms", type=base16_int,
                              help="Find instructions that touch capabilities"
                              " with the given permission bits set.")
        sub_scan.add_argument("--match-any", action="store_true",
                              help="Return a trace entry when matches any"
                              " of the conditions")
        sub_scan.add_argument("--match-all", action="store_true",
                              help="Return a trace entry when matches all"
                              " the conditions (default)")
        sub_scan.add_argument("-A", type=int, default=0,
                              help="Dump n instructions after a"
                              " matching one, default=0")
        sub_scan.add_argument("-B", type=int, default=0,
                              help="Dump n instructions before a"
                              " matching one, default=0")

        # trace backtrace arguments
        sub_back.set_defaults(operation=self._backtrace)
        sub_back.add_argument("-s", "--start", type=int,
                              help="Backtrace starting from this cycle",
                              required=True)
        sub_back.add_argument("-e", "--end", type=int,
                              help="stop backtrace at given cycle, note"
                              "that [end] < [start] because we scan backwards")
        sub_back.add_argument("-c", "--cache",
                              help="save a copy of the call graph",
                              action="store_true", default=False)
        sub_back.add_argument("--depth", type=int,
                              help="Stop backtracing after <depth> levels")
        sub_back.add_argument("--call-graph", help="Plot the call graph",
                              action="store_true")
        sub_back.add_argument("--bt", help="Show the backtrace",
                              action="store_true")
        sub_back.add_argument("-o", "--outfile",
                              help="Save plot to file, see matplotlib for "
                              "supported formats (svg, png, pgf...)")
        sub_back.add_argument("--sym", nargs="*", help="Binaries providing symbols")
        sub_back.add_argument("-m", "--vmmap", help="Memory map file generated"
                              " by vmmap_dump, required for --sym")

    def _scan(self, args):
        if args.match_any:
            match_mode = "or"
        else:
            # args.match_all
            match_mode = "and"

        if args.pc:
            pc_start = args.pc
            pc_end = args.pc
        else:
            pc_start = args.pc_after
            pc_end = args.pc_before

        if args.mem:
            mem_start = args.mem
            mem_end = args.mem
        else:
            mem_start = args.mem_after
            mem_end = args.mem_before

        dump_parser = TraceDumpParser(None, args.trace,
                                      dump_registers=args.show_regs,
                                      match_opcode=args.instr,
                                      match_pc_start=pc_start,
                                      match_pc_end=pc_end,
                                      match_reg=args.reg,
                                      match_addr_start=mem_start,
                                      match_addr_end=mem_end,
                                      match_exc=args.exception,
                                      match_nop=args.nop,
                                      match_syscall=args.syscall,
                                      match_perm=args.perms,
                                      match_mode=match_mode,
                                      before=args.B,
                                      after=args.A)
        if args.info:
            print("Trace size: %d" % len(dump_parser))
            exit()

        start = args.start if args.start is not None else 0
        end = args.end if args.end is not None else len(dump_parser)
        dump_parser.parse(start, end)

    def _backtrace(self, args):

        if args.sym != None and len(args.sym) > 0 and args.vmmap == None:
            logger.error("--sym files can be specified only if the process "
                         "memory map is given (-m)")
            return

        if args.call_graph:
            call_graph = CallGraphPlot(args.trace, cache=args.cache)
            call_graph.bt_start = args.start
            call_graph.bt_end = args.end
            call_graph.bt_depth = args.depth
            call_graph.sym_files = args.sym
            call_graph.sym_vmmap = args.vmmap
            if args.outfile:
                call_graph.plot_file = args.outfile
            call_graph.show()
        else:
            parser = CallGraphTraceParser(args.trace, args.cache,
                                          depth=args.depth)
            parser.parse(args.start, args.end)
            if args.vmmap:
                add_symbols = CallGraphAddSymbols(parser.cgm, args.sym, args.vmmap)
                parser.cgm.bfs_transform(add_symbols)
            if args.bt:
                call_graph_backtrace(parser)
            else:
                parser.cgm.dump()

    def _run(self, args):
        args.operation(args)

def main():
    tool = PyTraceDump()
    tool.run()

if __name__ == "__main__":
    main()
