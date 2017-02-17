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

import numpy as np
import logging
import pickle
import os

from matplotlib import pyplot as plt
from scipy import stats

from ..utils import ProgressPrinter
from ..core import CallbackTraceParser
from ..plot import Plot

logger = logging.getLogger(__name__)


class PointerParser(CallbackTraceParser):
    """
    Scan the trace and record all pointer bound setting operations
    """

    def scan_csetbounds(self, inst, entry, regs, last_regs, idx):
        try:
            register = inst.cd.value
            data_entry = np.array([register.base, register.length, register.offset, entry.cycles])
            self.dataset.append(data_entry)
        except IndexError as e:
            logger.error("Error in scan_csetbounds %s", e)
            return True
        return False

class PointerSizeCdfPlot(Plot):
    """
    Plot a Cumulative Distribution Function of the number of
    instantiations of capability pointer vs. the capability
    lengths.
    """
    
    def __init__(self, trace, *args, **kwargs):
        self.traces = [trace]
        """Store all the trace files"""
        super().__init__(trace, *args, **kwargs)

        self.parsers = [self.parser]
        """For each trace file there is a different parser"""
        self.datasets = [self.dataset]
        """For each trace file there is a different dataset"""

        # clear parser and dataset as they are replaced by the
        # list equivalents
        self.parser = None
        self.dataset = None
    
    def _get_cache_file(self):
        prefix = ""
        for trace in self.traces:
            full_name = os.path.basename(trace)
            name, ext = os.path.splitext(full_name)
            prefix += name
        return prefix + self.__class__.__name__ + ".cache"

    def _get_plot_file(self):
        classname = self.__class__.__name__.lower()
        return "%s_%s.png" % (self.tracefile, classname)

    def init_parser(self, dataset, tracefile):
        if self.caching and os.path.exists(self._get_cache_file()):
            return None
        return PointerParser(dataset, tracefile)

    def init_dataset(self):
        return []

    def add_traces(self, trace_files):
        """
        Set the additional traces for the plot
        """
        self.traces += trace_files
        for trace in trace_files:
            dataset = self.init_dataset()
            self.datasets.append(dataset)
            self.parsers.append(self.init_parser(dataset, trace))
    
    def build_dataset(self):
        if self.caching:
            fname = self._get_cache_file()
            try:
                with open(fname, "rb") as fd:
                    self.datasets = pickle.load(fd)
                    logger.info("Using cached dataset %s", fname)
            except OSError:
                for parser in self.parsers:
                    parser.parse()
                with open(fname, "wb") as fd:
                    pickle.dump(self.datasets, fd, pickle.HIGHEST_PROTOCOL)
                logger.info("Saving cached dataset %s", fname)
        else:
            for parser in self.parsers:
                parser.parse()
        for idx, dataset in enumerate(self.datasets):
            self.datasets[idx] = np.array(dataset)

    def plot(self):
        """
        Plot a CDF number-of-pointers vs size of pointers
        """
        
        fig = plt.figure(figsize=(15,10))
        ax = fig.add_axes([0.05, 0.15, 0.9, 0.8,])
        ax.set_ylabel("Proportion of total capability pointers")
        ax.set_xlabel("Capability size (bytes)")
        ax.set_title("CDF of the size of capability pointers")
        ax.set_xscale("log", basex=2)
        
        # build the plot for each dataset
        # since the plot is normalized on the y there is
        # no problem on the scale
        for dataset in self.datasets:
            sizes = dataset[:,1]
            logger.debug("[len, cycle] %s", np.dstack((dataset[:,1], dataset[:,3])))
            size_freq = stats.itemfreq(sizes)
            size_pdf = size_freq[:,1] / len(sizes)
            y = np.cumsum(size_pdf)
            ax.plot(size_freq[:,0], y)

        legend_keys = []
        for trace in self.traces:
            full_name = os.path.basename(trace)
            name, ext = os.path.splitext(full_name)
            legend_keys.append(name)
        ax.legend(legend_keys, loc="lower right")

        plt.savefig(self._get_plot_file())
        return fig
        
