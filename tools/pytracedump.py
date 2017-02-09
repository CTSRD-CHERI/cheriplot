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
Python version of cheritrace tracedump tool

This will probably be split in multiple tools or at least
change name to pycheridbg.
"""

import sys
import argparse
import logging

from cheriplot.dbg.parser import TraceDumpParser
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

    description = """
    Dump CHERI binary trace (python version of cheri-tracedump).
    Each instruction entry has the following format:
    {<ASID>:<instruction_cycle_number>} <PC> <instr_mnemonic> <operands>
    
    Memory accesses show the referenced address in the line below:
    <target_register> = [<hex_addr>] or [<hex_addr>] = <source_register>

    Capabilities as displayed in the following format:
    [b:<base> o:<offset> l:<length> p:<permission> t:<obj_type> v:<valid> s:<sealed>]
    t_alloc and t_free are only relevant in the provenance graph.

    When dumping the register set, the format of each entry is the following:
    [<register_value_valid>] <register> = <value>"""

    def init_arguments(self):
        super(PyTraceDump, self).init_arguments()
        self.parser.add_argument("-s", "--start", type=int, default=None,
                                 help="Start at given offset")
        self.parser.add_argument("-e", "--end", type=int, default=None,
                                 help="Stop at given offset")
        self.parser.add_argument("-i", "--info",
                                 help="Print trace info and exit",
                                 action="store_true")
        self.parser.add_argument("-r", "--show-regs", help="Dump register content",
                                 action="store_true")
        self.parser.add_argument("--instr",
                                 help="Find instruction occurrences")
        self.parser.add_argument("--pc", type=base16_int,
                                 help="Find all instructions with of given PC")
        self.parser.add_argument("--pc-after", type=base16_int,
                                 help="Find all instructions with PC higher than the given one")
        self.parser.add_argument("--pc-before", type=base16_int,
                                 help="Find all instructions with PC lower than the given one")
        self.parser.add_argument("--reg",
                                 help="Show all the instructions that touch"
                                 " a given register")
        self.parser.add_argument("--mem", type=base16_int,
                                 help="Show all the instructions that touch"
                                 " a given memory address")
        self.parser.add_argument("--exception", type=str,
                                 help="Show all the instructions that raise"
                                 " a given exception")
        self.parser.add_argument("--syscall", type=int,
                                 help="Show all the syscalls with given code")
        self.parser.add_argument("--nop", type=base16_int,
                                 help="Show all the canonical nops with"
                                 " given code.")
        self.parser.add_argument("--perms", type=base16_int,
                                 help="Find instructions that touch capabilities"
                                 " with the given permission bits set.")
        self.parser.add_argument("--match-any", action="store_true",
                                 help="Return a trace entry when matches any"
                                 " of the conditions")
        self.parser.add_argument("--match-all", action="store_true",
                                 help="Return a trace entry when matches all"
                                 " the conditions (default)")
        self.parser.add_argument("-A", type=int, default=0,
                                 help="Dump n instructions after a"
                                 " matching one, default=0")
        self.parser.add_argument("-B", type=int, default=0,
                                 help="Dump n instructions before a"
                                 " matching one, default=0")

    def _run(self, args):

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

        dump_parser = TraceDumpParser(None, args.trace,
                                      dump_registers=args.show_regs,
                                      match_opcode=args.instr,
                                      match_pc_start=pc_start,
                                      match_pc_end=pc_end,
                                      match_reg=args.reg,
                                      match_addr=args.mem,
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

def main():
    tool = PyTraceDump()
    tool.run()

if __name__ == "__main__":
    main()
