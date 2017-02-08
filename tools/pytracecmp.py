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

from cheriplot.dbg.txtrace_cmp import TxtTraceCmpParser
from cheriplot.core.tool import Tool

logger = logging.getLogger(__name__)

class PyTraceCmp(Tool):
    """
    Tool that compares two cheri traces and reports the first
    differing instruction
    """

    description = "Scan two traces and inspect differences"

    def init_arguments(self):
        super().init_arguments()
        # self.parser.add_argument("-s", "--start", type=int, default=None,
        #                          help="Start at given offset")
        # self.parser.add_argument("-e", "--end", type=int, default=None,
        #                          help="Stop at given offset")
        self.parser.add_argument("-t", "--txt", help="Text trace to compare",
                                 required=True)
        self.parser.add_argument("-p", "--pc-only", action="store_true",
                                 help="Only check instruction PC")
        self.parser.add_argument("-q", "--quiet", action="store_true",
                                 help="Suppress warning messages")

    def _run(self, args):

        if args.quiet:
            logging.basicConfig(level=logging.ERROR)

        dump_parser = TxtTraceCmpParser(args.txt, None, args.trace,
                                        pc_only=args.pc_only)

        # start = args.start if args.start is not None else 0
        # end = args.end if args.end is not None else len(dump_parser)
        start = 0
        end = len(dump_parser)
        dump_parser.parse(start, end)

def main():
    tool = PyTraceCmp()
    tool.run()

if __name__ == "__main__":
    main()
