#-
# Copyright (c) 2016-2017 Alfredo Mazzinghi
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

from sortedcontainers import SortedDict
from collections import defaultdict
from operator import itemgetter

from matplotlib.collections import LineCollection, PatchCollection
from matplotlib.transforms import Bbox, blended_transform_factory
from matplotlib.patches import Patch, Rectangle
from matplotlib.text import Text
from matplotlib.colors import colorConverter
from matplotlib.font_manager import FontProperties

from cheriplot.core import (
    ASAxesPlotBuilderNoTitle, ASAxesPatchBuilder, PickablePatchBuilder,
    Option)
from cheriplot.provenance.model import (
    CheriCapPerm, CheriNodeOrigin, ProvenanceVertexData)
from cheriplot.provenance.plot import VMMapPlotDriver

logger = logging.getLogger(__name__)

class BaseColorCodePatchBuilder(ASAxesPatchBuilder, PickablePatchBuilder):
    """
    The patch generator build the matplotlib patches for each
    capability node.

    The nodes are rendered as lines with a different color depending
    on the permission bits of the capability. The builder produces
    a LineCollection for each combination of permission bits and
    creates the lines for the nodes.
    """

    def __init__(self, figure, pgm):
        """
        Constructor

        :param figure: the figure to attache the click callback
        :param pgm: the provenance graph model
        """
        super().__init__(figure=figure)

        self._pgm = pgm
        """The provenance graph model"""

        self._collection_map = defaultdict(lambda: [])
        """
        Map capability permission to the set where the line should go.
        Any combination of capability permissions is used as key for
        a list of (start, end) values that are used to build LineCollections.
        The key "call" is used for system call nodes, the int(0) key is used
        for no permission.
        """

        self._colors = {}
        """
        Map capability permission to line colors.
        XXX: keep this for now, move to a colormap
        """

        self._bbox = [np.inf, np.inf, 0, 0]
        """Bounding box of the patches as (xmin, ymin, xmax, ymax)."""

        self._node_map = SortedDict()
        """Maps the Y axis coordinate to the graph node at that position"""

    def _clickable_element(self, vertex, y):
        """remember the node at the given Y for faster indexing."""
        data = self._pgm.vp.data[vertex]
        self._node_map[y] = data

    def _add_bbox(self, xmin, xmax, y):
        """Update the view bbox."""
        if self._bbox[0] > xmin:
            self._bbox[0] = xmin
        if self._bbox[1] > y:
            self._bbox[1] = y
        if self._bbox[2] < xmax:
            self._bbox[2] = xmax
        if self._bbox[3] < y:
            self._bbox[3] = y

    def get_patches(self, axes):
        """
        XXX once we are done with the coordinates in the
        collections we can throw them away instead of keeping
        memory used for nothing! (this may have an inpact
        """
        super().get_patches(axes)
        for key, collection in self._collection_map.items():
            coll = LineCollection(collection,
                                  colors=[self._colors[key]],
                                  linestyle="solid")
            axes.add_collection(coll)

    def get_bbox(self):
        return Bbox.from_extents(*self._bbox)

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
        y_coord = int(event.ydata)
        y_max = self._bbox[3]
        # tolerance for y distance, 0.1 * 10^6 cycles
        epsilon = 0.1 * 10**6

        # try to get the node closer to the y_coord
        # in the fast way
        # For now fall-back to a reduced linear search but would be
        # useful to be able to index lines with an R-tree?
        idx_min = self._node_map.bisect_left(max(0, y_coord - epsilon))
        idx_max = self._node_map.bisect_right(min(y_max , y_coord + epsilon))
        iter_keys = self._node_map.islice(idx_min, idx_max)
        # find the closest node to the click position
        pick_target = None
        for key in iter_keys:
            node = self._node_map[key]
            if (node.cap.base <= event.xdata and node.cap.bound >= event.xdata):
                # the click event is within the node bounds and
                # the node Y is closer to the click event than
                # the previous pick_target
                if (pick_target is None or
                    abs(y_coord - key) < abs(y_coord - pick_target.cap.t_alloc)):
                    pick_target = node
        if pick_target is not None:
            ax.set_status_message(pick_target)
        else:
            ax.set_status_message("")

class ColorCodePatchBuilder(BaseColorCodePatchBuilder):
    """
    The patch generator build the matplotlib patches for each
    capability node.

    The nodes are rendered as lines with a different color depending
    on the permission bits of the capability. The builder produces
    a LineCollection for each combination of permission bits and
    creates the lines for the nodes.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # permission composition shorthands
        load_store = CheriCapPerm.LOAD | CheriCapPerm.STORE
        load_exec = CheriCapPerm.LOAD | CheriCapPerm.EXEC
        store_exec = CheriCapPerm.STORE | CheriCapPerm.EXEC
        load_store_exec = (CheriCapPerm.STORE |
                           CheriCapPerm.LOAD |
                           CheriCapPerm.EXEC)

        self._colors = {
            0: colorConverter.to_rgb("#bcbcbc"),
            CheriCapPerm.LOAD: colorConverter.to_rgb("k"),
            CheriCapPerm.STORE: colorConverter.to_rgb("y"),
            CheriCapPerm.EXEC: colorConverter.to_rgb("m"),
            load_store: colorConverter.to_rgb("c"),
            load_exec: colorConverter.to_rgb("b"),
            store_exec: colorConverter.to_rgb("g"),
            load_store_exec: colorConverter.to_rgb("r"),
        }

    def inspect(self, vertex):
        """Inspect a graph vertex and create the patches for it."""
        data = self._pgm.vp.data[vertex]
        assert data.cap.bound >= data.cap.base # XXX should be in the parsers
        self._add_bbox(data.cap.base, data.cap.bound, data.cap.t_alloc)

        coords = ((data.cap.base, data.cap.t_alloc),
                  (data.cap.bound, data.cap.t_alloc))
        perms = data.cap.permissions or 0
        rwx_perm = perms & (CheriCapPerm.LOAD |
                            CheriCapPerm.STORE |
                            CheriCapPerm.EXEC)
        self._collection_map[rwx_perm].append(coords)
        # mark this address range as interesting
        self._add_range(data.cap.base, data.cap.bound)
        self._clickable_element(vertex, data.cap.t_alloc)

    def load(self, dataset):
        """XXX experimental"""
        for vertex in dataset.vertices():
            data = self._pgm.vp.data[vertex]
            assert data.cap.bound >= data.cap.base # XXX should be in the parsers
            self._add_bbox(data.cap.base, data.cap.bound, data.cap.t_alloc)

            coords = ((data.cap.base, data.cap.t_alloc),
                      (data.cap.bound, data.cap.t_alloc))
            perms = data.cap.permissions or 0
            rwx_perm = perms & (CheriCapPerm.LOAD |
                                CheriCapPerm.STORE |
                                CheriCapPerm.EXEC)
            self._collection_map[rwx_perm].append(coords)
            # mark this address range as interesting
            self._add_range(data.cap.base, data.cap.bound)
            self._clickable_element(vertex, data.cap.t_alloc)

    def get_legend(self):
        legend = super().get_legend()
        for key in self._collection_map.keys():
            label = ""
            if key & CheriCapPerm.LOAD:
                label += "R"
            if key & CheriCapPerm.STORE:
                label += "W"
            if key & CheriCapPerm.EXEC:
                label += "X"
            if label == "":
                label = "None"
            legend.append(Patch(color=self._colors[key], label=label))
        return legend


class DerefPatchBuilder(BaseColorCodePatchBuilder):
    """
    The patch generator build the matplotlib patches for each
    capability node.

    The nodes are rendered as lines with a different color depending
    on the permission bits of the capability dereferenced. The builder produces
    a LineCollection for each combination of permission bits and
    creates the lines for the nodes.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # register the colors we use
        self._colors["load"] = colorConverter.to_rgb("#687a99")
        self._colors["store"] = colorConverter.to_rgb("#895106")

    def inspect(self, vertex):
        """Create a patch for every dereference in the node.
        XXX this is both slow and fairly memory intensive,
        may get around it by preallocating a numpy array for
        the values?
        """
        data = self._pgm.vp.data[vertex]
        # mark this address range as interesting
        self._add_range(data.cap.base, data.cap.bound)

        min_time = np.inf
        max_time = 0
        assert False, "XXX this is broken, refactor me!!"
        columns = itemgetter("time", "addr", "type")(data.deref)
        for time, addr, type_ in zip(*columns):
            min_time = min(min_time, time)
            max_time = max(max_time, time)
            coords = ((data.cap.base, time), (data.cap.bound, time))
            if type_ == data.DerefType.DEREF_LOAD:
                self._collection_map["load"].append(coords)
                # off = patches.Circle((addr, data_y))
                # self._deref_load.append(off)
                pass
            elif type_ == data.DerefType.DEREF_STORE:
                self._collection_map["store"].append(coords)
                # off = patches.Circle((addr, data_y))
                # self._deref_store.append(off)
                pass
            elif type_ == data.DerefType.DEREF_CALL:
                logger.warning("Plot call dereferences not yet supported")
            self._clickable_element(vertex, time)

        if len(columns[0]):
            self._add_bbox(data.cap.base, data.cap.bound, min_time)
            self._add_bbox(data.cap.base, data.cap.bound, max_time)

    def load(self, dataset):
        """XXX experimental"""
        n_deref = 0
        for v in dataset.vertices():
            data = dataset.vp.data[v]
            n_deref += len(data.deref["time"])
        # preallocate dereferences
        # [xmin, xmax, y, type]
        derefs = np.empty((n_deref, 4), dtype=int)
        idx = 0
        coords = (data.cap.base, data.cap.bound)
        for v in dataset.vertices():
            data = dataset.vp.data[v]
            if len(data.deref["time"]):
                min_time = np.inf
                max_time = 0
                # mark this address range as interesting
                self._add_range(data.cap.base, data.cap.bound)
                end_idx = idx + len(data.deref["time"])
                derefs[idx:end_idx,0:2] = coords
                derefs[idx:end_idx,2] = data.deref["time"]
                derefs[idx:end_idx,3] = data.deref["type"]
                for t in data.deref["time"]:
                    min_time = min(min_time, t)
                    max_time = max(max_time, t)
                    self._clickable_element(v, t)
                self._add_bbox(data.cap.base, data.cap.bound, min_time)
                self._add_bbox(data.cap.base, data.cap.bound, max_time)
        # can probably avoid this mess by duplicating the y coordinate
        # above, we have to do that anyway below.
        load_idx = np.where(
            derefs[:,3] == ProvenanceVertexData.DerefType.DEREF_LOAD.value)
        load = derefs[load_idx][:,:3]
        dst = np.empty((len(load),2,2))
        dst[:,:,0] = load[:,:2]
        dst[:,:,1] = np.repeat(load[:,2], 2).reshape((len(load),2))
        self._collection_map["load"] = dst
        store_idx = np.where(
            derefs[:,3] == ProvenanceVertexData.DerefType.DEREF_LOAD.value)
        store = derefs[store_idx][:,:3]
        dst = np.empty((len(store),2,2))
        dst[:,:,0] = store[:,:2]
        dst[:,:,1] = np.repeat(store[:,2], 2).reshape((len(store),2))
        self._collection_map["store"] = dst

    def get_legend(self):
        handles = [
            Patch(color=self._colors["load"], label="load"),
            Patch(color=self._colors["store"], label="store"),
        ]
        return handles


class VMMapPatchBuilder(ASAxesPatchBuilder):
    """
    Build the patches that highlight the vmmap boundaries in and
    address-space plot
    """

    def __init__(self, axes):
        super().__init__()

        self.patches = []
        """List of rectangles"""

        self.patch_colors = []
        """List of colors for the patches"""

        self.annotations = []
        """Text labels"""

        self.label_y = 0.5
        """ Y position of the label in Axes coordinates (in [0,1])"""

        self._colors = {
            "": colorConverter.to_rgb("#bcbcbc"),
            "r": colorConverter.to_rgb("k"),
            "w": colorConverter.to_rgb("y"),
            "x": colorConverter.to_rgb("m"),
            "rw": colorConverter.to_rgb("c"),
            "rx": colorConverter.to_rgb("b"),
            "wx": colorConverter.to_rgb("g"),
            "rwx": colorConverter.to_rgb("r")
        }
        """Map section permission to line colors"""

        self.transform = blended_transform_factory(axes.transData,
                                                   axes.transAxes)
        """Transform used by the patches"""

        self._ticks = set()
        """X axis ticks"""

    def inspect(self, vmentry):
        # the patches use axes transform on the y coordinate to
        # set the height position of the label independently of
        # the Y scale
        rect = Rectangle((vmentry.start, 0.01),
                         vmentry.end - vmentry.start, 0.98,
                         edgecolor="k")
        self.patches.append(rect)
        self.patch_colors.append(self._colors[vmentry.perms])
        self._ticks.add(vmentry.start)
        self._ticks.add(vmentry.end)

        # the label position is centered based on the axes transform
        label_position = ((vmentry.start + vmentry.end) / 2, self.label_y)
        vme_path = str(vmentry.path).split("/")[-1] if str(vmentry.path) else ""
        if not vme_path and vmentry.grows_down:
            vme_path = "stack"
        vme_label = "%s %s" % (vmentry.perms, vme_path)
        label = Text(text=vme_label, rotation="vertical",
                     position=label_position,
                     horizontalalignment="center",
                     verticalalignment="center",
                     transform=self.transform)
        self.annotations.append(label)
        self._add_range(vmentry.start, vmentry.end)

    def load(self, dataset):
        """XXX experimental"""
        # dataset is a vmmap
        for vme in dataset:
            self.inspect(vme)

    def get_patches(self, axes):
        super().get_patches(axes)
        coll = PatchCollection(self.patches, alpha=0.1,
                               facecolors=self.patch_colors,
                               transform=self.transform)
        axes.add_collection(coll)
        for a in self.annotations:
            axes.add_artist(a)

    def get_xticks(self):
        return self._ticks

    def get_xlabels(self):
        return ["0x%x" % t for t in self._ticks]


class BaseAddressMapPlotDriver(VMMapPlotDriver, ASAxesPlotBuilderNoTitle):
    """
    Plot that shows the capability size in the address space
    vs the time of allocation (i.e. when the capability is created).
    """

    title = "Capabilities derivation time vs capability position"
    x_label = "Virtual Address"
    y_label = "Time (million of cycles)"

    publish = Option(help="Adjust plot for publication", action="store_true")

    patch_builder_class = None

    def _get_axes_rect(self):
        if self.config.publish:
            return [0.1, 0.25, 0.85, 0.65]
        return super()._get_axes_rect()

    def make_axes(self):
        """
        Set the y-axis scale to display millions of cycles instead of
        the number of cyles.
        """
        fig, ax = super().make_axes()
        ax.set_yscale("linear_unit", unit=10**-6)
        return (fig, ax)

    def make_plot(self):
        """Create the address-map plot."""
        super().make_plot()
        self.ax.invert_yaxis()

    def run(self):
        self._vmmap_parser.parse()
        vmmap = self._vmmap_parser.get_model()
        if self.config.publish:
            # set the style
            self._style["font"] = FontProperties(size=20)
        cap_builder = self.patch_builder_class(figure=self.fig,
                                               pgm=self._provenance_graph)
        self.register_patch_builder(self._provenance_graph.vertices(), cap_builder)
        # self.register_patch_builder(self._provenance_graph, cap_builder)
        self.register_patch_builder(vmmap, VMMapPatchBuilder(self.ax))
        self.process(out_file=self.config.outfile)


class AddressMapPlotDriver(BaseAddressMapPlotDriver):
    """
    Plot that shows the capability size in the address space
    vs the time of allocation (i.e. when the capability is created).
    """
    description = """
    Generate address-map plot.

    The address-map plot shows the location and size of capabilities in
    the address-space over time.
    The Y axis shows elapsed time in cycles or committed instructions.
    The X axis is a non-linear representation of the address space.
    Capabilities are color coded according to the permission bits.
    """
    title = "Capabilities derivation time vs capability position"
    patch_builder_class = ColorCodePatchBuilder


class AddressMapDerefPlotDriver(BaseAddressMapPlotDriver):
    """
    Plot that shows the capability size in the address space
    vs the time of dereference (i.e. when the capability is dereferenced
    for a load or a store).
    """
    description = """
    Generate address-map plot with dereference information.

    The address-map plot shows the location and size of capabilities in
    the address-space at the time of dereference.
    The Y axis shows elapsed time in cycles or committed instructions.
    The X axis is a non-linear representation of the address space.
    Capabilities are color coded according to the permission bits.
    """
    title = "Capabilities deallocation time vs capability position"
    patch_builder_class = DerefPatchBuilder

# class SyscallPatchBuilder(PatchBuilder):
#     """
#     The patch generator build the matplotlib patches for each
#     syscall data

#     The nodes are rendered as lines with a different color depending
#     on the system call type.
#     """

#     def __init__(self):
#         super(SyscallPatchBuilder, self).__init__()

#         self.y_unit = 10**-6
#         """Unit on the y-axis"""

#         self._patches = None
#         """Cached list of generated patches"""

#         self._mmap_rects = []
#         """Rectangles representing mmap-munmap pairs"""

#     def inspect(self, node):
#         if node.cap.bound < node.cap.base:
#             raise RuntimeError("Invalid capability range %s", node)
#         bottom_y = node.cap.t_alloc * self.y_unit
#         top_y = node.cap.t_free * self.y_unit

#         if top_y < 0:
#             # t_free is not valid
#             top_y = bottom_y # for now don't bother looking for the max y
#         rect = patches.Rectangle((node.cap.base, bottom_y),
#                                  node.cap.length, top_y - bottom_y)
#         self._mmap_rects.append(rect)

#         #invalidate collections
#         self._patches = None

#     def get_patches(self):
#         if self._patches:
#             return self._patches
#         self._patches = []

#         coll = collections.PatchCollection(self._mmap_rects)
#         self._patches = [coll]
#         return self._patches

#     def get_legend(self):
#         if not self._patches:
#             self.get_patches()
#         legend = (self._patches, ["mmap"])
#         return legend


# class SyscallAddressMapPlot(AddressMapPlot):
#     """
#     Address map plot that only shows system calls
#     """

#     def __init__(self, *args, **kwargs):
#         self.syscall_graph = None
#         """Graph of syscall nodes"""

#         super(SyscallAddressMapPlot, self).__init__(*args, **kwargs)

#         self.patch_builder = SyscallPatchBuilder()
#         """Patch builder for syscall nodes"""

#     def init_dataset(self):
#         dataset = super(SyscallAddressMapPlot, self).init_dataset()
#         self.syscall_graph = gt.Graph(directed=True)
#         vdata = self.syscall_graph.new_vertex_property("object")
#         self.syscall_graph.vp["data"] = vdata
#         return dataset

#     def build_dataset(self):
#         """
#         Load the provenance graph and only retain SYS_* nodes with
#         relevant alloc and free times.

#         XXX This is a PoC, the actual transformation should be done
#         on the provenance graph directly
#         XXX Make a generic graph transformation module based on visitors
#         """
#         super(SyscallAddressMapPlot, self).build_dataset()
#         logger.info("Filter syscall nodes and merge mmap/munmap")

#         class _Visitor(gt.BFSVisitor):
#             pass

#         for node in self.dataset.vertices():
#             data = self.dataset.vp.data[node]
#             if data.origin == CheriNodeOrigin.SYS_MMAP:
#                 # look for munmap in the subtree, if none
#                 # is found the map survives until the process
#                 # exits
#                 syscall_node = self.syscall_graph.add_vertex()
#                 sys_node_data = ProvenanceVertexData()
#                 sys_node_data.cap = CheriCap()
#                 sys_node_data.cap.base = data.cap.base
#                 sys_node_data.cap.length = data.cap.length
#                 sys_node_data.cap.offset = data.cap.offset
#                 sys_node_data.cap.permissions = data.cap.permissions
#                 sys_node_data.cap.objtype = data.cap.objtype
#                 sys_node_data.cap.valid = data.cap.valid
#                 sys_node_data.cap.sealed = data.cap.sealed
#                 sys_node_data.cap.t_alloc = data.cap.t_alloc
#                 sys_node_data.origin = data.origin
#                 sys_node_data.pc = data.pc
#                 sys_node_data.is_kernel = data.is_kernel
#                 self.syscall_graph.vp.data[syscall_node] = sys_node_data

#                 _visitor = _Visitor()
#                 for descendant in gt.search.bfs_search(self.dataset, node, _visitor):
#                     descendant_data = self.dataset.vp.data[descendant]
#                     if descendant_data.origin == CheriNodeOrigin.SYS_MUNMAP:
#                         if sys_node_data.cap.t_free != -1:
#                             logger.error("Multiple MUNMAP for a single mapped block")
#                             raise RuntimeError("Multiple MUNMAP for a single mapped block")
#                         sys_node_data.cap.t_free = descendant_data.cap.t_alloc

#     def _prepare_patches(self):
#         """
#         Prepare the patches and address ranges in the patch_builder
#         and range_builder.
#         """
#         dataset_progress = ProgressPrinter(self.dataset.num_vertices(),
#                                            desc="Adding nodes")
#         for item in self.syscall_graph.vertices():
#             data = self.syscall_graph.vp.data[item]
#             self.patch_builder.inspect(data)
#             self.range_builder.inspect(data)
#             dataset_progress.advance()
#         dataset_progress.finish()

#         if self.vmmap:
#             logger.debug("Generate mmap regions")
#             view_box = self.patch_builder.get_bbox()
#             ymax = view_box.ymax * (1 + self.viewport_padding)
#             for vme in self.vmmap:
#                 self.vmmap_patch_builder.inspect(vme)
#                 self.range_builder.inspect_range(Range(vme.start, vme.end))
