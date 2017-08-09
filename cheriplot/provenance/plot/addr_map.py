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
from collections import defaultdict
from functools import partial
from itertools import repeat
from operator import itemgetter

from sortedcontainers import SortedDict

from matplotlib.collections import LineCollection, PatchCollection, PathCollection
from matplotlib.colors import colorConverter
from matplotlib.font_manager import FontProperties
from matplotlib.markers import MarkerStyle
from matplotlib.patches import Patch, Rectangle, PathPatch
from matplotlib.text import Text
from matplotlib.transforms import Bbox, blended_transform_factory

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
        data = self._pgm.data[vertex]
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

    def _get_patch_collections(self, axes):
        """Return a generator of collections of patches to add to the axes."""
        pass

    def get_patches(self, axes):
        """
        Return a collection of lines from the collection_map.
        """
        super().get_patches(axes)
        for coll in self._get_patch_collections(axes):
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
        data = self._pgm.data[vertex]
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

    def _get_patch_collections(self, axes):
        for key, collection in self._collection_map.items():
            coll = LineCollection(collection,
                                  colors=[self._colors[key]],
                                  linestyle="solid")
            yield coll

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
        self._colors["load"] = colorConverter.to_rgba("#687a99", 0.4)
        self._colors["store"] = colorConverter.to_rgba("#895106", 0.4)

    def inspect(self, vertex):
        """Create a patch for every dereference in the node."""
        data = self._pgm.data[vertex]
        load = data.event_tbl["type"] == ProvenanceVertexData.EventType.DEREF_LOAD
        store = data.event_tbl["type"] == ProvenanceVertexData.EventType.DEREF_STORE
        deref = load | store
        if not deref.any():
            # no dereferences, skip
            return
        # mark this address range as interesting
        base = data.cap.base
        bound = data.cap.bound
        self._add_range(base, bound)
        register_clickable = partial(self._clickable_element, vertex)
        data.event_tbl[deref]["time"].apply(register_clickable)

        # extract Y limits and set the bounding box
        min_time = data.event_tbl[deref]["time"].min()
        max_time = data.event_tbl[deref]["time"].max()
        self._add_bbox(base, bound, min_time)
        self._add_bbox(base, bound, max_time)

        # create all the line coordinates
        self._collection_map["load"].extend(
            zip(zip(repeat(base), data.event_tbl[load]["time"]),
                zip(repeat(bound), data.event_tbl[load]["time"])))
        self._collection_map["store"].extend(
            zip(zip(repeat(base), data.event_tbl[store]["time"]),
                zip(repeat(bound), data.event_tbl[store]["time"])))

    def _get_patch_collections(self, axes):
        for key, collection in self._collection_map.items():
            coll = LineCollection(collection,
                                  colors=[self._colors[key]],
                                  linestyle="solid")
            yield coll

    def get_legend(self):
        handles = [
            Patch(color=self._colors["load"], label="load"),
            Patch(color=self._colors["store"], label="store"),
        ]
        return handles


class AccessLocationPatchBuilder(BaseColorCodePatchBuilder):
    """
    Plot offsets of load/store accesses where a capability is stored in memory.
    Only the accessed address is shown in the plot, the capability
    bounds are omitted.
    The points are color coded with respect to the mapped memory regions.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # register the colors we use
        self._colors["load"] = colorConverter.to_rgba("#687a99", 1)
        self._colors["store"] = colorConverter.to_rgba("#895106", 1)
        self._markers = {
            "load": MarkerStyle(","),
            "store": MarkerStyle(","),
        }

    def inspect(self, vertex):
        """Create a point for every load/store in the vertex."""
        data = self._pgm.data[vertex]
        load = data.event_tbl["type"] == ProvenanceVertexData.EventType.LOAD
        store = data.event_tbl["type"] == ProvenanceVertexData.EventType.STORE
        access = load | store
        if not access.any():
            # no dereferences, skip
            return
        # make a point at the load/store location
        self._collection_map["load"].extend(data.event_tbl[load]["addr"])
        self._collection_map["store"].extend(data.event_tbl[store]["addr"])
        # mark this address range as interesting
        low = data.event_tbl[access]["addr"].min()
        high = data.event_tbl[access]["addr"].max()
        self._add_range(low, high)
        register_clickable = partial(self._clickable_element, vertex)
        data.event_tbl[access]["time"].apply(register_clickable)

        # extract Y limits and set the bounding box
        min_time = data.event_tbl[access]["time"].min()
        max_time = data.event_tbl[access]["time"].max()
        self._add_bbox(low, high, min_time)
        self._add_bbox(low, high, max_time)

        # create all the line coordinates
        self._collection_map["load"].extend(
            data.event_tbl[load][["addr", "time"]])
        self._collection_map["store"].extend(
            data.event_tbl[store][["addr", "time"]])

    def _get_patch_collections(self, axes):
        for key, collection in self._collection_map.items():
            marker = self._markers[key]
            coll = PathCollection([marker.get_path()],
                                  offsets=collection,
                                  transOffset=axes.transAxes,
                                  facecolors=[self._colors[key]])
            yield coll

    def get_legend(self):
        handles = [
            PathPatch(self._markers["load"], color=self._colors["load"],
                      label="load"),
            PathPatch(self._markers["store"], color=self._colors["store"],
                      label="store"),
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
                         linestyle="solid",
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
                     fontproperties=self.style["font-small"],
                     transform=self.transform)
        self.annotations.append(label)
        self._add_range(vmentry.start, vmentry.end)

    def get_patches(self, axes):
        super().get_patches(axes)
        coll = PatchCollection(self.patches, alpha=0.1,
                               facecolors=self.patch_colors,
                               edgecolors="k",
                               linestyle="solid",
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

    Note this only builds a plot for the first graph in
    :prop:`VMMapPlotDriver._pgm_list`.
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
        if self.config.publish:
            # set the style
            self._style["font"] = FontProperties(size=20)
            self._style["font-small"] = FontProperties(size=15)
        pgm = self._pgm_list[0]
        graph = pgm.prov_view()
        cap_builder = self.patch_builder_class(figure=self.fig, pgm=pgm)
        self.register_patch_builder(graph.vertices(), cap_builder)
        self.register_patch_builder(self._vmmap, VMMapPatchBuilder(self.ax))
        self.process(out_file=self._outfile)


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

class AddressMapAccessPlotDriver(BaseAddressMapPlotDriver):
    """
    Plot that shows the locations where capabilities are stored and loaded
    from vs the time of access (i.e. when a capability is dereferenced
    for a load or a store).
    """
    description = """
    Generate address-map plot with memory access information.

    The address-map plot shows the location and size of capabilities in
    the address-space at the time of dereference.
    The Y axis shows elapsed time in cycles or committed instructions.
    The X axis is a non-linear representation of the address space.
    """
    title = "Capabilities store/load time vs memory location"
    patch_builder_class = AccessLocationPatchBuilder
