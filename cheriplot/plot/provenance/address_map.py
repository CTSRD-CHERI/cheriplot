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
import graph_tool as gt

from sortedcontainers import SortedDict

from matplotlib import pyplot as plt
from matplotlib import collections, transforms, patches
from matplotlib.colors import colorConverter

from cheriplot.utils import ProgressPrinter
from cheriplot.core.addrspace_axes import Range
from cheriplot.core.provenance import (
    CheriCapPerm, CheriNodeOrigin, NodeData, CheriCap)
from cheriplot.core.vmmap import VMMap
from cheriplot.plot.patch import (
    PickablePatchBuilder, PatchBuilder, OmitRangeSetBuilder)
from cheriplot.plot.provenance.provenance_plot import PointerProvenancePlot
from cheriplot.plot.provenance.vmmap import VMMapPatchBuilder

logger = logging.getLogger(__name__)

class ColorCodePatchBuilder(PickablePatchBuilder):
    """
    The patch generator build the matplotlib patches for each
    capability node.

    The nodes are rendered as lines with a different color depending
    on the permission bits of the capability. The builder produces
    a LineCollection for each combination of permission bits and
    creates the lines for the nodes.
    """

    def __init__(self, figure):
        super(ColorCodePatchBuilder, self).__init__(figure, None)

        self.y_unit = 10**-6
        """Unit on the y-axis"""

        # permission composition shorthands
        load_store = CheriCapPerm.LOAD | CheriCapPerm.STORE
        load_exec = CheriCapPerm.LOAD | CheriCapPerm.EXEC
        store_exec = CheriCapPerm.STORE | CheriCapPerm.EXEC
        load_store_exec = (CheriCapPerm.STORE |
                           CheriCapPerm.LOAD |
                           CheriCapPerm.EXEC)

        self._collection_map = {
            0: [],
            CheriCapPerm.LOAD: [],
            CheriCapPerm.STORE: [],
            CheriCapPerm.EXEC: [],
            load_store: [],
            load_exec: [],
            store_exec: [],
            load_store_exec: [],
            "call": [],
        }
        """Map capability permission to the set where the line should go"""

        self._colors = {
            0: colorConverter.to_rgb("#bcbcbc"),
            CheriCapPerm.LOAD: colorConverter.to_rgb("k"),
            CheriCapPerm.STORE: colorConverter.to_rgb("y"),
            CheriCapPerm.EXEC: colorConverter.to_rgb("m"),
            load_store: colorConverter.to_rgb("c"),
            load_exec: colorConverter.to_rgb("b"),
            store_exec: colorConverter.to_rgb("g"),
            load_store_exec: colorConverter.to_rgb("r"),
            "call": colorConverter.to_rgb("#31c648"),
        }
        """Map capability permission to line colors"""

        self._patches = None
        """List of enerated patches"""

        self._node_map = SortedDict()
        """Maps the Y axis coordinate to the graph node at that position"""

    def _build_patch(self, node_range, y, perms):
        """
        Build patch for the given range and type and add it
        to the patch collection for drawing
        """
        line = [(node_range.start, y), (node_range.end, y)]

        if perms is None:
            perms = 0
        rwx_perm = perms & (CheriCapPerm.LOAD |
                            CheriCapPerm.STORE |
                            CheriCapPerm.EXEC)
        self._collection_map[rwx_perm].append(line)

    def _build_call_patch(self, node_range, y, origin):
        """
        Build patch for a node representing a system call
        This is added to a different collection so it can be
        colored differently.
        """
        line = [(node_range.start, y), (node_range.end, y)]
        self._collection_map["call"].append(line)

    def inspect(self, node):
        """
        Inspect a graph vertex and create the patches for it.
        """
        if node.cap.bound < node.cap.base:
            logger.warning("Skip overflowed node %s", node)
            return
        node_y = node.cap.t_alloc * self.y_unit
        node_box = transforms.Bbox.from_extents(node.cap.base, node_y,
                                                node.cap.bound, node_y)

        self._bbox = transforms.Bbox.union([self._bbox, node_box])
        keep_range = Range(node.cap.base, node.cap.bound, Range.T_KEEP)
        if node.origin == CheriNodeOrigin.SYS_MMAP:
            self._build_call_patch(keep_range, node_y, node.origin)
        else:
            self._build_patch(keep_range, node_y, node.cap.permissions)

        self._node_map[node.cap.t_alloc] = node

        #invalidate collections
        self._patches = None

    def get_patches(self):
        if self._patches:
            return self._patches
        self._patches = []
        for key, collection in self._collection_map.items():
            coll = collections.LineCollection(collection,
                                              colors=[self._colors[key]],
                                              linestyle="solid")
            self._patches.append(coll)
        return self._patches

    def get_legend(self):
        if not self._patches:
            self.get_patches()
        legend = ([], [])
        for patch, key in zip(self._patches, self._collection_map.keys()):
            legend[0].append(patch)
            if key == "call":
                legend[1].append("mmap")
            else:
                perm_string = ""
                if key & CheriCapPerm.LOAD:
                    perm_string += "R"
                if key & CheriCapPerm.STORE:
                    perm_string += "W"
                if key & CheriCapPerm.EXEC:
                    perm_string += "X"
                if perm_string == "":
                    perm_string = "None"
                legend[1].append(perm_string)
        return legend

    def on_click(self, event):
        """
        Attempt to retreive the data in less than O(n) for better
        interactivity at the expense of having to hold a dictionary of
        references to nodes for each t_alloc.
        Note that t_alloc is unique for each capability node as it
        is the cycle count, so it can be used as the key.
        """
        ax = event.inaxes
        if ax is None:
            return

        # back to data coords without scaling
        y_coord = int(event.ydata / self.y_unit)
        y_max = self._bbox.ymax / self.y_unit
        # tolerance for y distance, 0.25 units
        epsilon = 0.25 / self.y_unit

        # try to get the node closer to the y_coord
        # in the fast way
        # For now fall-back to a reduced linear search but would be
        # useful to be able to index lines with an R-tree?
        idx_min = self._node_map.bisect_left(max(0, y_coord - epsilon))
        idx_max = self._node_map.bisect_right(min(y_max , y_coord + epsilon))
        iter_keys = self._node_map.islice(idx_min, idx_max)
        # the closest node to the click position
        # initialize it with the first node in the search range
        try:
            pick_target = self._node_map[next(iter_keys)]
        except StopIteration:
            # no match found
            ax.set_status_message("")
            return

        for key in iter_keys:
            node = self._node_map[key]
            if (node.cap.base <= event.xdata and
                node.cap.bound >= event.xdata and
                abs(y_coord - key) < abs(y_coord - pick_target.cap.t_alloc)):
                # the click event is within the node bounds and
                # the node Y is closer to the click event than
                # the previous pick_target
                pick_target = node
        ax.set_status_message(pick_target)


class AddressMapOmitBuilder(OmitRangeSetBuilder):
    """
    The omit builder generates the ranges of address-space in
    which we are not interested.

    Generate address ranges that are displayed as shortened in the
    address-space plot based on the size of each capability.
    If the allocations are spaced out more than a given number of pages,
    the space in between is "omitted" in the plot, if no other
    capability should be rendered into such range. The effect is to
    shrink portions of the address-space where there are no interesting
    features.
    """

    def __init__(self):
        super(AddressMapOmitBuilder, self).__init__()

        self.split_size = 2 * self.size_limit
        """
        Capability length threshold to trigger the omission of
        the middle portion of the capability range.
        """

    def inspect(self, node):
        if node.cap.bound < node.cap.base:
            logger.warning("Skip overflowed node %s", node)
            return
        keep_range = Range(node.cap.base, node.cap.bound, Range.T_KEEP)
        self.inspect_range(keep_range)

    def inspect_range(self, node_range):
        if node_range.size > self.split_size:
            l_range = Range(node_range.start,
                            node_range.start + self.size_limit,
                            Range.T_KEEP)
            r_range = Range(node_range.end - self.size_limit,
                            node_range.end,
                            Range.T_KEEP)
            self._update_regions(l_range)
            self._update_regions(r_range)
        else:
            self._update_regions(node_range)


class AddressMapPlot(PointerProvenancePlot):
    """
    Plot the provenance tree showing the time of allocation vs
    base and bound of each node.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.patch_builder = ColorCodePatchBuilder(self.fig)
        """
        Helper object that builds the plot components.
        See :class:`.ColorCodePatchBuilder`
        """

        self.range_builder = AddressMapOmitBuilder()
        """
        Helper objects that detects the interesting
        parts of the address-space.
        See :class:`.AddressMapOmitBuilder`
        """

        self.vmmap_patch_builder = VMMapPatchBuilder(self.ax)
        """
        Helper object that builds patches to display VM map regions.
        """

        self.vmmap = None
        """VMMap object representing the process memory map"""

        self.viewport_padding = 0.02
        """Padding added to the bounding box of the viewport (% units)"""

    def init_axes(self):
        """
        Build the figure and axes for the plot
        :return: tuple containing the figure and the axes
        """
        fig = plt.figure(figsize=(15,10))
        ax = fig.add_axes([0.05, 0.15, 0.9, 0.80,],
                          projection="custom_addrspace")
        return (fig, ax)

    def set_vmmap(self, mapfile):
        """
        Set the vmmap CSV file containing the VM mapping for the process
        that generated the trace, as obtained from procstat or libprocstat
        """
        self.vmmap = VMMap(mapfile)

    def _prepare_patches(self):
        """
        Prepare the patches and address ranges in the patch_builder
        and range_builder.
        """

        dataset_progress = ProgressPrinter(self.dataset.num_vertices(),
                                           desc="Adding nodes")
        for item in self.dataset.vertices():
            data = self.dataset.vp.data[item]
            self.patch_builder.inspect(data)
            self.range_builder.inspect(data)
            dataset_progress.advance()
        dataset_progress.finish()

        if self.vmmap:
            logger.debug("Generate mmap regions")
            for vme in self.vmmap:
                self.vmmap_patch_builder.inspect(vme)
                self.range_builder.inspect_range(Range(vme.start, vme.end))

    def plot(self):
        """
        Create the address-map plot
        """

        self._prepare_patches()

        # add some padding to the viewport
        view_box = self.patch_builder.get_bbox()
        xmin = view_box.xmin * (1 - self.viewport_padding)
        xmax = view_box.xmax * (1 + self.viewport_padding)
        ymin = view_box.ymin * (1 - self.viewport_padding)
        ymax = view_box.ymax * (1 + self.viewport_padding)

        logger.debug("Nodes %d, ranges %d", self.dataset.num_vertices(),
                     len(self.range_builder.ranges))

        # add all the patches to the axes and set the omit
        # ranges
        for collection in self.patch_builder.get_patches():
            self.ax.add_collection(collection)
        self.ax.set_omit_ranges(self.range_builder.get_omit_ranges())

        if self.vmmap:
            for collection in self.vmmap_patch_builder.get_patches():
                self.ax.add_collection(collection)
            for label in self.vmmap_patch_builder.get_annotations():
                self.ax.add_artist(label)

        self.ax.set_xlim(xmin, xmax)
        self.ax.set_ylim(ymin, ymax)
        # manually set xticks based on the vmmap if we can
        if self.vmmap:
            start_ticks = [vme.start for vme in self.vmmap]
            end_ticks = [vme.end for vme in self.vmmap]
            ticks = sorted(set(start_ticks + end_ticks))
            # current_ticks = ax.get_ticks()
            logger.debug("address map ticks %s", ["0x%x" % t for t in ticks])
            self.ax.set_xticks(ticks)

        self.ax.invert_yaxis()
        self.ax.set_xlabel("Virtual Address")
        self.ax.set_ylabel("Time (millions of cycles)")

        # build the legend and place it above the plot axes # loc = "best"
        self.ax.legend(*self.patch_builder.get_legend(),
                       bbox_to_anchor=(0., 1.02, 1., 0.102), loc=3,
                       ncol=9, mode="expand", borderaxespad=0.)

        logger.debug("Plot build completed")
        plt.savefig(self._get_plot_file())
        logger.debug("Plot written to file")


class SyscallPatchBuilder(PatchBuilder):
    """
    The patch generator build the matplotlib patches for each
    syscall node

    The nodes are rendered as lines with a different color depending
    on the system call type.
    """

    def __init__(self):
        super(SyscallPatchBuilder, self).__init__()

        self.y_unit = 10**-6
        """Unit on the y-axis"""

        self._patches = None
        """Cached list of generated patches"""

        self._mmap_rects = []
        """Rectangles representing mmap-munmap pairs"""

    def inspect(self, node):
        if node.cap.bound < node.cap.base:
            raise RuntimeError("Invalid capability range %s", node)
        bottom_y = node.cap.t_alloc * self.y_unit
        top_y = node.cap.t_free * self.y_unit

        if top_y < 0:
            # t_free is not valid
            top_y = bottom_y # for now don't bother looking for the max y
        rect = patches.Rectangle((node.cap.base, bottom_y),
                                 node.cap.length, top_y - bottom_y)
        self._mmap_rects.append(rect)

        #invalidate collections
        self._patches = None

    def get_patches(self):
        if self._patches:
            return self._patches
        self._patches = []

        coll = collections.PatchCollection(self._mmap_rects)
        self._patches = [coll]
        return self._patches

    def get_legend(self):
        if not self._patches:
            self.get_patches()
        legend = (self._patches, ["mmap"])
        return legend


class SyscallAddressMapPlot(AddressMapPlot):
    """
    Address map plot that only shows system calls
    """

    def __init__(self, *args, **kwargs):
        self.syscall_graph = None
        """Graph of syscall nodes"""

        super(SyscallAddressMapPlot, self).__init__(*args, **kwargs)

        self.patch_builder = SyscallPatchBuilder()
        """Patch builder for syscall nodes"""

    def init_dataset(self):
        dataset = super(SyscallAddressMapPlot, self).init_dataset()
        self.syscall_graph = gt.Graph(directed=True)
        vdata = self.syscall_graph.new_vertex_property("object")
        self.syscall_graph.vp["data"] = vdata
        return dataset

    def build_dataset(self):
        """
        Load the provenance graph and only retain SYS_* nodes with
        relevant alloc and free times.

        XXX This is a PoC, the actual transformation should be done
        on the provenance graph directly
        XXX Make a generic graph transformation module based on visitors
        """
        super(SyscallAddressMapPlot, self).build_dataset()
        logger.info("Filter syscall nodes and merge mmap/munmap")

        class _Visitor(gt.BFSVisitor):
            pass

        for node in self.dataset.vertices():
            data = self.dataset.vp.data[node]
            if data.origin == CheriNodeOrigin.SYS_MMAP:
                # look for munmap in the subtree, if none
                # is found the map survives until the process
                # exits
                syscall_node = self.syscall_graph.add_vertex()
                sys_node_data = NodeData()
                sys_node_data.cap = CheriCap()
                sys_node_data.cap.base = data.cap.base
                sys_node_data.cap.length = data.cap.length
                sys_node_data.cap.offset = data.cap.offset
                sys_node_data.cap.permissions = data.cap.permissions
                sys_node_data.cap.objtype = data.cap.objtype
                sys_node_data.cap.valid = data.cap.valid
                sys_node_data.cap.sealed = data.cap.sealed
                sys_node_data.cap.t_alloc = data.cap.t_alloc
                sys_node_data.origin = data.origin
                sys_node_data.pc = data.pc
                sys_node_data.is_kernel = data.is_kernel
                self.syscall_graph.vp.data[syscall_node] = sys_node_data

                _visitor = _Visitor()
                for descendant in gt.search.bfs_search(self.dataset, node, _visitor):
                    descendant_data = self.dataset.vp.data[descendant]
                    if descendant_data.origin == CheriNodeOrigin.SYS_MUNMAP:
                        if sys_node_data.cap.t_free != -1:
                            logger.error("Multiple MUNMAP for a single mapped block")
                            raise RuntimeError("Multiple MUNMAP for a single mapped block")
                        sys_node_data.cap.t_free = descendant_data.cap.t_alloc

    def _prepare_patches(self):
        """
        Prepare the patches and address ranges in the patch_builder
        and range_builder.
        """
        dataset_progress = ProgressPrinter(self.dataset.num_vertices(),
                                           desc="Adding nodes")
        for item in self.syscall_graph.vertices():
            data = self.syscall_graph.vp.data[item]
            self.patch_builder.inspect(data)
            self.range_builder.inspect(data)
            dataset_progress.advance()
        dataset_progress.finish()

        if self.vmmap:
            logger.debug("Generate mmap regions")
            view_box = self.patch_builder.get_bbox()
            ymax = view_box.ymax * (1 + self.viewport_padding)
            for vme in self.vmmap:
                self.vmmap_patch_builder.inspect(vme)
                self.range_builder.inspect_range(Range(vme.start, vme.end))
