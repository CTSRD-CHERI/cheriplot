#!/usr/bin/python

"""
Copyright 2016 Alfredo Mazzinghi

Copyright and related rights are licensed under the BERI Hardware-Software
License, Version 1.0 (the "License"); you may not use this file except
in compliance with the License.  You may obtain a copy of the License at:

http://www.beri-open-systems.org/legal/license-1-0.txt

Unless required by applicable law or agreed to in writing, software,
hardware and materials distributed under this License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
express or implied.  See the License for the specific language governing
permissions and limitations under the License.


This script produces a poiner provenance plot from a cheri trace file
"""

import argparse as ap
import sys
import logging
import cProfile
import pstats

from cheriplot.plot import PointerTreePlot, AddressMapPlot
from cheriplot.core.tool import PlotTool

logger = logging.getLogger(__name__)

class ProvenancePlotTool(PlotTool):

    description = "Plot pointer provenance from cheri trace"

    def init_arguments(self):
        super(ProvenancePlotTool, self).init_arguments()
        self.parser.add_argument("--tree", help="Draw a provenance tree plot",
                                 action="store_true")
        self.parser.add_argument("--asmap",
                                 help="Draw an address-map plot (default)",
                                 action="store_true")

    def _run(self, args):
        if args.tree:
            plot = PointerTreePlot(args.trace)
        else:
            plot = AddressMapPlot(args.trace)

        if args.outfile:
            plot.plot_file = args.outfile

        if args.cache:
            plot.set_caching(True)

        plot.show()

if __name__ == "__main__":
    tool = ProvenancePlotTool()
    tool.run()
