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

import logging

from operator import attrgetter

from matplotlib import pyplot as plt
from matplotlib import lines, collections, transforms, patches, text
from matplotlib.colors import colorConverter

from cheriplot.utils import ProgressPrinter
from cheriplot.core.addrspace_axes import RangeSet, Range
from cheriplot.plot.patch import OmitRangeSetBuilder

from cheriplot.plot.provenance.provenance_plot import PointerProvenancePlot

logger = logging.getLogger(__name__)

class OmitRangeBuilder(OmitRangeSetBuilder):
    """
    Build the omit ranges for the pointer address frequency plot.
    :class:`.PointerAddressFreqencyPlot`
    """

    def __init__(self):
        super(OmitRangeBuilder, self).__init__()

        self.split_size = 2 * self.size_limit
        """
        Capability length threshold to trigger the omission of
        the middle portion of the capability range.
        """

    def inspect(self, keep_range):
        if keep_range.size > self.split_size:
            l_range = Range(keep_range.start, keep_range.start + self.size_limit,
                            Range.T_KEEP)
            r_range = Range(keep_range.end - self.size_limit, keep_range.end,
                            Range.T_KEEP)
            self._update_regions(l_range)
            self._update_regions(r_range)
        else:
            self._update_regions(keep_range)


class PointedAddressFrequencyPlot(PointerProvenancePlot):
    """
    For each range in the address-space we want an histogram-like plot
    that shows how many times it is referenced in csetbounds.
    The idea is to make a point that stack allocations are much more frequent.
    """

    class DataRange(Range):
        """
        Range with additional metadata
        """

        def __init__(self, *args, **kwargs):
            super(PointedAddressFrequencyPlot.DataRange, self).__init__(
                *args, **kwargs)

            self.num_references = 1
            """Number of times this range has been referenced"""

        def split(self, addr):
            """
            Split range in two subranges (start, addr) (addr, end)
            """
            r_start = self.__class__(self.start, addr)
            r_end = self.__class__(addr, self.end)
            r_start.num_references = self.num_references
            r_end.num_references = self.num_references
            return r_start, r_end


    def __init__(self, tracefile):
        super(PointedAddressFrequencyPlot, self).__init__(tracefile)

        self.range_set = None
        """
        List of DataRange objects holding the frequency of reference
        of all the regions in the address-space
        """

    def _get_regset_cache_file(self):
        return self.tracefile + "_addr_frequency.cache"

    def _extract_ranges(self):
        """
        Extract ranges from the provenance graph

        XXX for now do the prototype data manipulation here
        with a naive RangeSet object later we may want to
        move it somewhere else with more dedicated solution
        using interval trees
        """
        dataset_progress = ProgressPrinter(self.dataset.number_of_nodes(),
                                           desc="Extract frequency of reference")
        range_set = RangeSet()
        for node in self.dataset.nodes():
            logger.debug("Inspect node %s", node)
            r_node = self.DataRange(node.base, node.bound)
            node_set = RangeSet([r_node])
            # erode r_node until it is fully merged in the range_set
            # the node_set holds intermediate ranges remaining to merge
            while len(node_set):
                logger.debug("merging node")
                # pop first range from rangeset and try to merge it
                r_current = node_set.pop(0)
                # get first overlapping range
                r_overlap = range_set.pop_overlap_range(r_current)
                if r_overlap == None:
                    # no overlap occurred, just add it to the rangeset
                    range_set.append(r_current)
                    logger.debug("-> no overlap")
                    continue
                logger.debug("picked current %s", r_current)
                logger.debug("picked overlap %s", r_overlap)
                # merge r_current and r_overlap data and push any remaining
                # part of r_current back in node_set
                #
                # r_same: referenced count does not change
                # r_inc: referenced count incremented
                # r_rest: pushed back to node_set for later evaluation
                if r_overlap.start <= r_current.start:
                    logger.debug("overlap before current")
                    # 2 possible layouts:
                    #          |------ r_current -------|
                    # |------ r_overlap -----|
                    # |-r_same-|-- r_inc ----|- r_rest -|
                    #
                    # |--------------- r_overlap --------------|
                    # |-r_same-|-------- r_inc ---------|r_same|
                    r_same, other = r_overlap.split(r_current.start)
                    if r_same.size > 0:
                        range_set.append(r_same)

                    if r_current.end >= r_overlap.end:
                        # other is the remaining part of r_overlap
                        # which falls all in r_current, so
                        # r_inc = other
                        other.num_references += 1
                        range_set.append(other)
                        # r_rest must be computed from the end
                        # of r_overlap
                        _, r_rest = r_current.split(r_overlap.end)
                        if r_rest.size > 0:
                            node_set.append(r_rest)
                    else:
                        # other does not fall all in r_current so
                        # split other in r_inc and r_same
                        # r_current is not pushed back because it
                        # was fully covered by r_overlap
                        r_inc, r_same = other.split(r_current.end)
                        r_inc.num_references += 1
                        range_set.append(r_inc)
                        range_set.append(r_same)
                else:
                    logger.debug("current before overlap")
                    # 2 possible layouts:
                    # |------ r_current ---------|
                    #          |------ r_overlap ---------|
                    # |-r_rest-|-- r_inc --------| r_same |
                    #
                    # |------ r_current --------------|
                    #        |--- r_overlap ---|
                    # |r_rest|----- r_inc -----|r_rest|
                    r_rest, other = r_current.split(r_overlap.start)
                    if r_rest.size > 0:
                        node_set.append(r_rest)

                    if r_current.end >= r_overlap.end:
                        # other is the remaining part of r_current
                        # which completely covers r_overlap so
                        # split other in r_inc and r_rest
                        r_inc, r_rest = other.split(r_overlap.end)
                        r_inc.num_references += r_overlap.num_references
                        range_set.append(r_inc)
                        if r_rest.size > 0:
                            node_set.append(r_rest)
                    else:
                        # other does not cover all r_overlap
                        # so r_inc = other and the remaining
                        # part of r_overlap is r_same
                        other.num_references += r_overlap.num_references
                        range_set.append(other)
                        _, r_same = r_overlap.split(r_current.end)
                        range_set.append(r_same)
                logger.debug("merge loop out Range set step %s", range_set)
                logger.debug("merge loop out Node set step %s", node_set)
            logger.debug("Range set step %s", range_set)
            logger.debug("Node set step %s", node_set)
            dataset_progress.advance()
        dataset_progress.finish()
        logger.debug("Range set %s", range_set)
        self.range_set = range_set

    def build_dataset(self):
        try:
            if self._caching:
                fname = self._get_regset_cache_file()
                try:
                    with open(fname, "rb") as cache_fd:
                        self.range_set = pickle.load(cache_fd)
                except IOError:
                    super(PointedAddressFrequencyPlot, self).build_dataset()
                    self._extract_ranges()
                    with open(fname, "wb") as cache_fd:
                        pickle.dump(self.range_set, cache_fd)
            else:
                super(PointerProvenancePlot).build_dataset()
                self._extract_ranges()
        except Exception as e:
            logger.error("Error while generating provenance tree %s", e)
            raise

    def plot(self):
        fig = plt.figure(figsize=(15,10))
        ax = fig.add_axes([0.05, 0.15, 0.9, 0.80,],
                          projection="custom_addrspace")

        omit_builder = OmitRangeBuilder()
        for addr_range in self.range_set:
            omit_builder.inspect(addr_range)

        ax.set_omit_ranges(omit_builder.get_omit_ranges())

        self.range_set.sort(key=attrgetter("start"))
        x_coords = [r.start for r in self.range_set]
        freq = [r.num_references for r in self.range_set]

        ax.set_xlabel("Virtual Address")
        ax.set_ylabel("Number of references")

        ax.plot(x_coords, freq)

        logger.debug("Plot build completed")
        plt.savefig(self._get_plot_file())
        return fig
