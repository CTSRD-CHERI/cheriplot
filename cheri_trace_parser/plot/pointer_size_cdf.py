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

import numpy as np
import logging
import pickle

from matplotlib import pyplot as plt
from scipy import stats

from cheri_trace_parser.utils import ProgressPrinter
from cheri_trace_parser.core import CallbackTraceParser
from cheri_trace_parser.plot import Plot

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

    def __init__(self, trace):
        super(PointerSizeCdfPlot, self).__init__(trace)

    def _get_cache_file(self):
        return self.tracefile + self.__class__.__name__ + ".cache"

    def init_parser(self):
        return PointerParser(self.dataset, self.tracefile)

    def init_dataset(self):
        return []
    
    def build_dataset(self):
        if self._caching:
            fname = self._get_cache_file()
            try:
                with open(fname, "rb") as fd:
                    self.dataset = pickle.load(fd)
                    logger.info("Using cached dataset %s", fname)
            except OSError:
                self.parser.parse()
                with open(fname, "wb") as fd:
                    pickle.dump(self.dataset, fd, pickle.HIGHEST_PROTOCOL)
                logger.info("Saving cached dataset %s", fname)
        else:
            self.parser.parse()
        self.dataset = np.array(self.dataset)

    def plot(self):
        """
        Plot a CDF number-of-pointers vs size of pointers
        """
        
        fig = plt.figure(figsize=(15,10))
        ax = fig.add_axes([0.05, 0.15, 0.9, 0.8,])
        ax.set_ylabel("Proportion of total capability pointers")
        ax.set_xlabel("Capability size (bytes)")
        ax.set_title("CDF of the size of capability pointers")

        # mine
        sizes = self.dataset[:,1]
        logger.debug("[len, cycle] %s", np.dstack((self.dataset[:,1], self.dataset[:,3])))
        size_freq = stats.itemfreq(sizes)
        size_pdf = size_freq[:,1] / len(sizes)
        y = np.cumsum(size_pdf)
        ax.plot(size_freq[:,0], y)
        ax.axvline(2**12, linestyle="--")
        ax.set_xscale("log", basex=2)
        
        return fig
        
