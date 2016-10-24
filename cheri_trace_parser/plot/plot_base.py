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
"""

import logging

from matplotlib import pyplot as plt

from cheri_trace_parser.provenance_tree import (
    PointerProvenanceParser, CachedProvenanceTree)

logger = logging.getLogger(__name__)

class Plot:
    """
    Base class for plots that display cheritrace data
    """

    def __init__(self, tracefile):
        self.tracefile = tracefile
        """Tracefile path"""
        self.dataset = self.init_dataset()
        """Parsed dataset"""
        self.parser = self.init_parser()
        """Tracefile parser"""

        self._caching = False
        """dataset caching enable """

    def _get_cache_file(self):
        return self.tracefile + ".cache"

    def set_caching(self, state):
        self._caching = state

    def init_parser(self):
        """
        Initialise the trace parser object

        This method is meant to be overridden in subclasses

        :return: The parser for the current trace
        """
        return

    def init_dataset(self):
        """
        Initialise the dataset object

        This method is meant to be overridden in subclasses

        :return: The dataset where the parser will store the
        data extracted from the trace
        """
        return

    def build_dataset(self):
        """
        Build the plot dataset
        
        This is method meant to be overridden in subclasses
        """
        return

    def plot(self):
        """
        Build the plot

        This method is meant to be overridden in subclasses

        :return: The matplotlib figure for the plot
        """
        return

    def show(self):
        """
        Show plot in a new window
        """
        self.build_dataset()
        fig = self.plot()
        plt.show()

    def save(self, path):
        """
        Save plot to file
        """
        self.build_dataset()
        fig = self.plot()
        plt.savefig(path)

class ProvenanceTreePlot(Plot):

    def build_dataset(self):
        logger.debug("Generating provenance tree for %s", self.tracefile)
        if self._caching:
            fname = self._get_cache_file()
            try:
                self.dataset.load(fname)
            except IOError:
                self.parser.parse(self.dataset)
                self.dataset.save(self._get_cache_file())
        else:
            self.parser.parse(self.tree)

        errs = []
        self.dataset.check_consistency(errs)
        if len(errs) > 0:
            logger.warning("Inconsistent provenance tree: %s", errs)

    def init_dataset(self):
        return CachedProvenanceTree()

    def init_parser(self):
        return PointerProvenanceParser(self.tracefile)
        
