#-
# Copyright (c) 2016-2018 Alfredo Mazzinghi
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
import pandas as pd
import logging

from itertools import repeat

from matplotlib.font_manager import FontProperties
from matplotlib.patches import Patch
from matplotlib.transforms import Bbox

from cheriplot.core import (
    ProgressTimer, ProgressPrinter, ExternalLegendTopPlotBuilder,
    BasePlotBuilder, PatchBuilder, LabelManager, AutoText, TaskDriver,
    Option, Argument)

from cheriplot.provenance.model import (
    CheriCapPerm, CheriNodeOrigin, ProvenanceVertexData, EventType)

logger = logging.getLogger(__name__)

class PtrHeadroom:
    """
    Pointer headroom extractor model
    """    

    def __init__(self, pgm):
        self._pgm = pgm
        self.heardroom_table = None
        """Pandas dataframe with N=vertices entries"""

        self.histogram = []
        """Histogram buckets"""

        exponents = np.arange(0, 33)
        self.bins = np.concatenate(
            ([0], np.power(2, exponents), [2**64 - 1]))
        """Histogram bin endpoints"""

        self.sizes_per_bucket = []
        """Capability size scatter for every histogram bucket"""

        self.vertices_per_bucket = []
        """List of graph vertex indices for every histogram bucket"""

        self.process()
        
    def process(self):
        table = {"head": [],
                 "tail": [],
                 # "size": [],
                 "vindex": []}
        logger.info("Vertices %d", self._pgm.prov_view().num_vertices())        
        for v in self._pgm.graph.vertices():
            if not self._pgm.layer_prov[v]:
                continue
            data = self._pgm.data[v]
            access = ((data.event_tbl["type"] == EventType.DEREF_LOAD) |
                      (data.event_tbl["type"] == EventType.DEREF_STORE))
            if not access.any():
                continue
            min_addr = data.event_tbl[access]["addr"].min()
            max_addr = data.event_tbl[access]["addr"].max()
            assert data.cap.base is not None, v
            assert data.cap.length is not None, v
            assert not np.isnan(min_addr), str(v)
            assert not np.isnan(max_addr), str(v)

            # Note that the max address here is the beginning of the load,
            # not the last address loaded. If we are loading a word, the real max address
            # will be max_addr + sizeof(word). Correct for this.
            access_max = data.event_tbl[data.event_tbl["addr"] == max_addr]
            if (access_max["type"] & EventType.DEREF_IS_CAP).any():
                # XXX-AM assume CHERI-256 here!
                max_addr += 32
            else:
                # are we accessing in a pattern? check if we accessed max_addr - 1,
                # max_addr - 4 or max_addr - 8
                byte_access = (data.event_tbl["addr"] == max_addr - 1).any()
                word_access = (data.event_tbl["addr"] == max_addr - 4).any()
                long_access = (data.event_tbl["addr"] == max_addr - 8).any()
                if long_access:
                    max_addr += 8
                elif word_access:
                    max_addr += 4
                elif byte_access:
                    max_addr += 1
                else:
                    # assume maximum possible access
                    max_addr += 8
                # cap to the maximum possible dereferenceable address
            max_addr = min(max_addr, data.cap.bound)
                
            headroom = min_addr - data.cap.base
            tailroom = data.cap.bound - max_addr
            table["head"].append(headroom)
            table["tail"].append(tailroom)
            # table["size"].append(data.cap.length)
            table["vindex"].append(self._pgm.graph.vertex_index[v])

        logger.info("Headroom entries %d", len(table["head"]))
        # make the hadroom data table
        self.headroom_table = pd.DataFrame(table)
        values = self.headroom_table["head"] + self.headroom_table["tail"]

        # build the histogram
        self.histogram, self.bins = np.histogram(values, bins=self.bins)

        # record capability sizes for each bucket
        bin_for_value = np.digitize(values, self.bins)        
        self.sizes_per_bucket = [[] for _ in self.histogram]
        self.vertices_per_bucket = [[] for _ in self.histogram]
        for bucket, vindex in zip(bin_for_value, self.headroom_table["vindex"]):
            data = self._pgm.data[vindex]
            size = data.cap.length
            if bucket > len(self.histogram):
                # value outside the range for buckets, account for in the last bucket
                self.sizes_per_bucket[-1].append(size)
                self.vertices_per_bucket[-1].append(vindex)
            else:
                self.vertices_per_bucket[bucket - 1].append(vindex)
                self.sizes_per_bucket[bucket - 1].append(size)
        logger.info("histogram %s", self.histogram)

    def get_cvertex_at(self, time):
        for cv in self._pgm.graph.vertices():
            if not self._pgm.layer_call[cv]:
                continue
            # find parent and call edge
            edge = None
            for parent in cv.in_neighbours():
                if self._pgm.layer_call[parent]:
                    edge = self._pgm.graph.edge(parent, cv)                    
            if edge is None:
                continue
            # check whether time falls within this call
            data = self._pgm.data[cv]
            if time >= self._pgm.edge_time[edge]:
                if data.t_return is None:
                    return None
                if time <= data.t_return:
                    # found the function call!
                    return cv
        return None

    def get_faddr_per_bucket(self, bucket):
        """
        For every capability in a bucket, find the address of the function where it
        was created.
        """
        faddrs = np.zeros(len(self.vertices_per_bucket[bucket]))
        for idx, vindex in enumerate(self.vertices_per_bucket[bucket]):
            v = self._pgm.graph.vertex(vindex)
            pdata = self._pgm.data[v]
            call = self.get_cvertex_at(pdata.cap.t_alloc)
            if call is None:
                faddrs[idx] = np.nan
            else:
                cdata = self._pgm.data[call]
                faddrs[idx] = cdata.address
        return faddrs


class HeadroomPatchBuilder(PatchBuilder):
    """
    Patch builder that creates an histogram of pointer headroom data.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.hr = None

    def inspect(self, headroom):
        """
        Prepare data from the headroom table
        """
        self.hr = headroom

    def get_xticks(self):
        return np.arange(len(self.hr.histogram)) + 0.4

    def get_xlabels(self):
        return range(len(self.hr.bins) - 1)

    def get_yticks(self):
        step = np.round(self.hr.histogram.max() / 20)
        return np.arange(0, self.hr.histogram.max() + step, step)

    def get_ylabels(self):
        return self.get_yticks()

    def get_bbox(self):
        """
        Leave some room around the bars
        """
        x = self.get_xticks()
        y = self.get_yticks()
        return Bbox.from_extents(-0.2, 0, x[-1] + 0.6, y[-1] + 1)

    def get_legend(self, handles):
        legend_handles = []
        bin_start = 0
        legend_handles.append(Patch(color="b", label="Headroom"))
        legend_handles.append(Patch(color="r", label="Capability size"))
        return legend_handles

    def get_patches(self, axes):
        axes.bar(self.get_xticks(), self.hr.histogram, color="b")
        # build the size points coordinates
        points = []
        for bucket_x, sizes in zip(self.get_xticks(), self.hr.sizes_per_bucket):
            coords = zip(repeat(bucket_x), sizes)
            coord_array = np.array(list(coords))
            if len(coord_array):
                points.append(coord_array)
        points = np.concatenate(points)
        twin = axes.twinx()
        twin.set_yscale("log", basey=2)
        twin.set_ylabel("Capability size")
        twin.scatter(points[:, 0], points[:, 1], color="r")
        # axes.plot([0, 2**63], [0, 2**63], color="k")


class FnPerBucketPatchBuilder(PatchBuilder):
    """
    Patch builder that shows function addresses vs capability
    creation time for a given histogram bucket.
    """

    def __init__(self, bucket, **kwargs):
        super().__init__(**kwargs)
        self.hr = None
        self.bucket = bucket

    def inspect(self, headroom):
        """
        Prepare data from the headroom table
        """
        self.hr = headroom
        self.fn = self.hr.get_faddr_per_bucket(self.bucket)
        self.times = np.zeros(len(self.fn))
        for idx, vindex in enumerate(self.hr.headroom_table["vindex"]):
            data = self.hr._pgm.data[vindex]
            self.times[idx] = data.t_alloc

    # def get_xticks(self):
    #     return np.arange(len(self.hr.histogram)) + 0.4

    # def get_xlabels(self):
    #     return range(len(self.hr.bins) - 1)

    # def get_yticks(self):        
    #     step = np.round(self.hr.histogram.max() / 20)
    #     return np.arange(0, self.hr.histogram.max() + step, step)

    # def get_ylabels(self):
    #     return self.get_yticks()

    def get_bbox(self):
        """
        Leave some room around the bars
        """
        max_fn = self.fn.max()
        min_fn = self.fn.min()
        max_time = self.time.max()
        min_time = self.time.min()
        return Bbox.from_extents(min_time, min_fn, max_time, max_fn)

    def get_legend(self, handles):
        legend_handles = []
        return legend_handles

    def get_patches(self, axes):
        axes.scatter(self.times, self.fn, color="b")


class PtrHeadroomPlotDriver(TaskDriver, ExternalLegendTopPlotBuilder):

    title = "Size of untouched head/tail space accessible by a capability"
    x_label = "Size (power of 2)"
    y_label = "Amount of capabilities"

    outfile = Option(help="Output file", default="ptrheadroom.pdf")
    publish = Option(help="Adjust the plot for publication", action="store_true")
    bucket_where = Option(help="Plot fn-address vs t-alloc of the capabilities"
                          " that end up in a given bucket", default=-1, type=int)
    # bucket_parent = Option(help="Plot parent vs capabilities in bucket for"
    #                        "the capabilities in the given bucket", default=-1)

    def __init__(self, pgm_list, vmmap, **kwargs):
        super().__init__(**kwargs)
        self.pgm_list = pgm_list
        """List of graph managers to plot"""

        self.vmmap = vmmap
        """VM map model of the process"""

        if self.config.publish:
            self._style["font"] = FontProperties(size=25)
    
    def _get_xlabels_kwargs(self):
        kw = super()._get_xlabels_kwargs()
        kw["rotation"] = "vertical"
        return kw

    def _get_axes_rect(self):
        if self.config.publish:
            return [0.1, 0.15, 0.85, 0.8]
        return super()._get_axes_rect()

    def run(self):
        headroom_datasets = []
        # for now use only the first graph that we are given
        pgm = self.pgm_list[0]
        headroom_datasets.append(PtrHeadroom(pgm))
        if self.config.bucket_where >= 0:
            # specific bucket information                        
            self.register_patch_builder(headroom_datasets,
                                        FnPerBucketPatchBuilder(self.config.bucket_where))
        else:
            # headroom plot
            self.register_patch_builder(headroom_datasets, HeadroomPatchBuilder())
        self.process(out_file=self.config.outfile)
        
