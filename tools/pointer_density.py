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

from cheriplot.plot import PointerDensityPlot
from cheriplot.core.tool import PlotTool

logger = logging.getLogger(__name__)

class DensityPlotTool(PlotTool):

    description = "Plot pointer density from cheri trace"

    def _run(self, args):
        plot = PointerDensityPlot(args.trace)

        if args.cache:
            plot.set_caching(True)

        if args.outfile:
            plot.save(args.outfile)
        else:
            plot.show()

if __name__ == "__main__":
    tool = DensityPlotTool()
    tool.run()
