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

    description="Dump CHERI binary trace "\
                 "(python version of cheri-tracedump)."

    def init_arguments(self):
        super(PyTraceDump, self).init_arguments()
        self.parser.add_argument("-s", "--start", type=int, default=None,
                                 help="Start at given offset")
        self.parser.add_argument("-e", "--end", type=int, default=None,
                                 help="Stop at given offset")
        self.parser.add_argument("-i", "--info",
                                 help="Print trace info and exit",
                                 action="store_true")
        self.parser.add_argument("-r", "--regs", help="Dump register content",
                                 action="store_true")
        self.parser.add_argument("--raw",
                                 help="Show raw hex dump of the instruction",
                                 action="store_true")
        self.parser.add_argument("-f", "--find",
                                 help="Find instruction occurrences")
        self.parser.add_argument("-p", "--pc", type=base16_int,
                                 help="Find all hits of given PC")
        self.parser.add_argument("-A", type=int, default=0,
                                 help="Dump n instructions after a matching one")
        self.parser.add_argument("-B", type=int, default=0,
                                 help="Dump n instructions before a matching one")
        self.parser.add_argument("--follow",
                                 help="show all the instructions that touch"
                                 " a given register")

    def _run(self, args):

        dump_parser = TraceDumpParser(None, args.trace,
                                      dump_registers=args.regs,
                                      find=args.find,
                                      pc=args.pc,
                                      follow=args.follow,
                                      before=args.B,
                                      after=args.A,
                                      raw=args.raw)
        if args.info:
            print("Trace size: %d" % len(dump_parser))
            exit()

        start = args.start if args.start is not None else 0
        end = args.end if args.end is not None else len(dump_parser)
        dump_parser.parse(start, end)

if __name__ == "__main__":
    tool = PyTraceDump()
    tool.run()
