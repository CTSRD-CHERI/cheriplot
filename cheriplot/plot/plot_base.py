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

logger = logging.getLogger(__name__)

class Plot:
    """
    Base class for plots that display cheritrace data
    """

    def __init__(self, tracefile, cache=False):
        self.tracefile = tracefile
        """Tracefile path"""

        self.caching = cache
        """dataset caching enable """
        
        self.dataset = self.init_dataset()
        """Parsed dataset"""
        
        self.parser = self.init_parser(self.dataset, self.tracefile)
        """Tracefile parser"""

        self.plot_file = None
        """Path to the file where the plot should be saved"""

    def _get_cache_file(self):
        return self.tracefile + ".cache"

    def _get_plot_file(self):
        if self.plot_file:
            return self.plot_file
        classname = self.__class__.__name__.lower()
        return "%s_%s.pgf" % (self.tracefile, classname)

    def init_parser(self, dataset, tracefile):
        """
        Initialise the trace parser object

        This method is meant to be overridden in subclasses

        :param dataset: The dataset object to fill
        :type dataset: object
        :param tracefile: Trace file path
        :type tracefile: str
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
        
