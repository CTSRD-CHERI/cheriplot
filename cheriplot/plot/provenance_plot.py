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


Plot representation of a CHERI pointer provenance tree
"""

import numpy as np
import logging

from io import StringIO

from matplotlib import pyplot as plt
from matplotlib import lines, collections, transforms, patches
from matplotlib.colors import colorConverter

from ..utils import ProgressPrinter
from ..core import RangeSet, Range

from ..core import CallbackTraceParser, Instruction
from ..plot import Plot, PatchBuilder
from ..provenance_tree import CheriCapPerm, CheriCapNodeNX

import networkx as nx

logger = logging.getLogger(__name__)

class PointerProvenanceParser(CallbackTraceParser):

    class RegisterSet:
        """
        Extended register set that keeps track of memory
        operations on capabilities.

        We need to know where a register value has been read from
        and where it is stored to. The first is used to infer
        the correct CapNode to add as parent for a new node,
        the latter allows us to set the CapNode.address for
        a newly allocated capability.
        """
        def __init__(self):
            self.reg_nodes = np.empty(32, dtype=object)
            """CheriCapNode associated with each register."""
            self.memory_map = {}
            """CheriCapNodes stored in memory."""

        def __getitem__(self, idx):
            return self.reg_nodes[idx]

        def __setitem__(self, idx, val):
            self.load(idx, val)

        def load(self, idx, node):
            """
            Associate a CheriCapNode to a register that
            contains the capability associated with it.
            """
            self.reg_nodes[idx] = node

        def move(self, from_idx, to_idx):
            """
            When a capability is moved or modified without changing
            bounds the node is propagated to the destination register.
            """
            self.reg_nodes[to_idx] = self.reg_nodes[from_idx]

        def __repr__(self):
            dump = StringIO()
            dump.write("RegisterSet snapshot:\n")
            for idx, node in enumerate(self.reg_nodes):
                if node:
                    dump.write("$c%d = b:0x%x l:0x%x o:0x%x t:%d\n" % (
                        idx, node.base, node.length, node.offset, node.t_alloc))
                else:
                    dump.write("$c%d = Not mapped\n" % idx)


    def __init__(self, dataset, trace):
        super(PointerProvenanceParser, self).__init__(dataset, trace)
        self.regs_valid = False
        """
        Flag used to disable parsing until the registerset 
        is completely initialised.
        """

        self.regset = self.RegisterSet()
        """
        Register set that maps capability registers
        to nodes in the provenance tree.
        """

    def scan_eret(self, inst, entry, regs, last_regs, idx):
        """
        Detect the first eret that enters the process code
        and initialise the register set and the roots of the tree.
        """
        if self.regs_valid:
            return False
        self.regs_valid = True
        logger.debug("Scan initial register set")
        for idx in range(0, 32):
            cap = regs.cap_reg[idx]
            valid = regs.valid_caps[idx]
            if valid:
                node = self.make_root_node(idx, cap)
            else:
                logger.warning("c%d not in initial set", idx)
                if idx == 30:
                    node = self.make_root_node(idx, None)
                    node.base = 0
                    node.offset = 0
                    node.length = 0xffffffffffffffff
                    logger.warning("Guessing KDC %s", node)
        # XXX we should see here the EPCC being moved to PCC
        # but it is probably not stored in the trace so we take
        # csetoffset to $c31 (EPCC) update in the instruction
        # before this.
        # logger.debug("EPCC b:%x l:%x o:%x", regs.cap_reg[31].base,
        #              regs.cap_reg[31].length, regs.cap_reg[31].offset)
        return False

    def scan_csetbounds(self, inst, entry, regs, last_regs, idx):
        """
        Each csetbounds is a new pointer allocation
        and is recorded as a new node in the provenance tree.
        """
        if not self.regs_valid:
            return False
        node = self.make_node(entry, inst)
        node.origin = CheriCapNodeNX.C_SETBOUNDS
        self.regset.load(inst.cd.cap_index, node) # XXX scan_cap
        return False

    def scan_cfromptr(self, inst, entry, regs, last_regs, idx):
        """
        Each cfromptr is a new pointer allocation and is
        recodred as a new node in the provenance tree.
        """
        if not self.regs_valid:
            return False
        node = self.make_node(entry, inst)
        node.origin = CheriCapNodeNX.C_FROMPTR
        self.regset.load(inst.cd.cap_index, node) # XXX scan_cap
        return False

    def scan_cap(self, inst, entry, regs, last_regs, idx):
        """
        Whenever a capability instruction is found, update
        the mapping from capability register to the provenance
        tree node associated to the capability in it.

        XXX track ccall and creturn properly, also skip csX and clX
        as we don't care
        """
        if not self.regs_valid:
            return False
        self.update_regs(inst, entry, regs, last_regs)
        return False

    def scan_clc(self, inst, entry, regs, last_regs, idx):
        """
        If a capability is loaded in a register we need to find
        a node for it or create one. The address map is used to
        lookup nodes that have been stored at the load memory
        address.
        """
        if not self.regs_valid:
            return False

        cd = entry.capreg_number()
        try:
            node = self.regset.memory_map[entry.memory_address]
        except KeyError:
            logger.debug("Load c%s from new location 0x%x",
                         cd, entry.memory_address)
            if not inst.cd.value.valid:
                # can not create a node from the instruction value so finish
                return False
            node = None

        if node is None:
            # add a node as a root node because we have never
            # seen the content of this register yet
            node = self.make_root_node(cd, inst.cd.value, time=entry.cycles)
            logger.debug("Found %s value (missing in initial set) %s",
                         inst.cd.name, node)
        self.regset[cd] = node
        return False

    def scan_csc(self, inst, entry, regs, last_regs, idx):
        """
        Record the locations where a capability node is stored
        """
        if not self.regs_valid:
            return False
        cd = entry.capreg_number()
        node = self.regset[cd]
        if node is None and not last_regs.valid_caps[cd]:
            # add a node as a root node because we have never
            # seen the content of this register yet
            node = self.make_root_node(cd, inst.cd.value)
            logger.debug("Found %s value (missing in initial set)",
                         inst.cd.name, node)

            # XXX for now return but the correct behaviour would
            # be to recover the capability missing in the initial set
            # from the current entry and create a new root node for it
            return False
        self.regset.memory_map[entry.memory_address] = node
        node.address[entry.cycles] = entry.memory_address
        return False

    def make_root_node(self, idx, cap, time=0):
        """
        Create a root node of the provenance tree.
        The node is added to the tree and associated
        with the destination register of the current instruction.

        :param idx: index of the destination capability register for
        the current instruction
        :type idx: int
        :param cap: capability register value
        :type cap: :class:`pycheritrace.capability_register`
        :return: the newly created node
        :rtype: :class:`cheriplot.provenance_tree.CheriCapNode`
        """
        node = CheriCapNodeNX(cap)
        node.t_alloc = time
        # self.dataset.append(node)
        self.dataset.add_node(node)
        self.regset.load(idx, node)
        return node

    def make_node(self, entry, inst):
        """
        Create a node in the provenance tree.
        The parent is fetched from the register set depending on the source
        registers of the current instruction.
        """
        node = CheriCapNodeNX(inst.cd.value)
        node.t_alloc = entry.cycles
        node.pc = entry.pc
        node.is_kernel = entry.is_kernel()
        # find parent node, if no match then the tree is returned
        try:
            parent = self.regset[inst.cb.cap_index]
        except:
            logger.error("Error searching for parent node of %s", node)
            raise

        if parent == None:
            logger.error("Missing parent c%d [%x, %x]",
                         entry.capreg_number(), src.base, src.length)
            raise Exception("Missing parent for %s [%x, %x]" %
                            (node, src.base, src.length))
        self.dataset.add_node(node)
        self.dataset.add_edge(parent, node)
        # parent.append(node)
        return node

    def update_regs(self, inst, entry, regs, last_regs):
        cd = inst.cd
        cb = inst.cb
        if (cd is None or cd.cap_index == -1):
            return
        if (cb is None or cb.cap_index == -1):
            return
        self.regset.move(cb.cap_index, cd.cap_index)


class ColorCodePatchBuilder(PatchBuilder):
    """
    The patch generator build the matplotlib patches for each
    capability node and generates the ranges of address-space in
    which we are not interested.


    Generate address ranges that are displayed as shortened in the
    address-space plot based on leaf capabilities found in the
    provenance tree.
    We only care about zones where capabilities without children
    are allocated. If the allocations are spaced out more than
    a given number of pages, the space in between is omitted
    in the plot.
    """

    def __init__(self):
        super(ColorCodePatchBuilder, self).__init__()

        self.split_size = 2 * self.size_limit
        """
        Capability length threshold to trigger the omission of
        the middle portion of the capability range.
        """

        self.y_unit = 10**-6
        """Unit on the y-axis"""

        self._omit_collection = np.empty((1,2,2))
        """Collection of elements in omit ranges"""

        self._keep_collection = np.empty((1,2,2))
        """Collection of elements in keep ranges"""

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
            load_store_exec: []
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
            load_store_exec: colorConverter.to_rgb("r")
        }
        """Map capability permission to line colors"""

        self._patches = None
        """List of enerated patches"""

        self._arrow_collection = []
        """Collection of arrow coordinates"""

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

    def _build_provenance_arrow(self, src_node, dst_node):
        """
        Build an arrow that shows the source capability for a node
        The arrow goes from the source to the child
        """
        return
        # src_x = (src_node.base + src_node.bound) / 2
        # src_y = src_node.t_alloc * self.y_unit
        # dst_x = (dst_node.base + dst_node.bound) / 2
        # dst_y = dst_node.t_alloc * self.y_unit
        # dx = dst_x - src_x
        # dy = dst_y - src_y
        # arrow = patches.FancyArrow(src_x, src_y, dx, dy,
        #                            fc="k",
        #                            ec="k",
        #                            head_length=0.0001,
        #                            head_width=0.0001,
        #                            width=0.00001)
        # self._arrow_collection.append(arrow)

    def inspect(self, node):
        # if len(node) != 0:
        #     # not a leaf in the provenance tree
        #     return
        if node.bound < node.base:
            logger.warning("Skip overflowed node %s", node)
            return
        node_y = node.t_alloc * self.y_unit
        node_box = transforms.Bbox.from_extents(node.base, node_y,
                                                node.bound, node_y)

        self._bbox = transforms.Bbox.union([self._bbox, node_box])
        keep_range = Range(node.base, node.bound, Range.T_KEEP)

        if node.length > self.split_size:
            l_range = Range(node.base, node.base + self.size_limit,
                            Range.T_KEEP)
            r_range = Range(node.bound - self.size_limit, node.bound,
                            Range.T_KEEP)
            self._update_regions(l_range)
            self._update_regions(r_range)
        else:
            self._update_regions(keep_range)

        self._build_patch(keep_range, node_y, node.permissions)

        #invalidate collections
        self._patches = None

        # # build arrows
        # for child in node:
        #     self._build_provenance_arrow(node, child)

    def get_patches(self):
        if self._patches:
            return self._patches
        self._patches = []
        for perm, collection in self._collection_map.items():
            coll = collections.LineCollection(collection,
                                              colors=[self._colors[perm]],
                                              linestyle="solid")
            self._patches.append(coll)
        return self._patches

    def get_legend(self):
        if not self._patches:
            self.get_patches()
        legend = ([], [])
        for patch, perm in zip(self._patches, self._collection_map.keys()):
            legend[0].append(patch)
            perm_string = ""
            if perm & CheriCapPerm.LOAD:
                perm_string += "R"
            if perm & CheriCapPerm.STORE:
                perm_string += "W"
            if perm & CheriCapPerm.EXEC:
                perm_string += "X"
            if perm_string == "":
                perm_string = "None"
            legend[1].append(perm_string)
        return legend


class PointerProvenancePlot(Plot):
    """
    Base class for plots using the pointer provenance graph
    """

    def __init__(self, tracefile):
        super(PointerProvenancePlot, self).__init__(tracefile)

        self.patch_builder = ColorCodePatchBuilder()
        """Strategy object that builds the plot components"""

    def init_parser(self, dataset, tracefile):
        return PointerProvenanceParser(dataset, tracefile)

    def init_dataset(self):
        return nx.DiGraph()

    def _get_cache_file(self):
        return self.tracefile + "_provenance_plot.cache"

    def build_dataset(self):
        """
        Build the provenance tree
        """
        logger.debug("Generating provenance tree for %s", self.tracefile)
        try:
            if self._caching:
                fname = self._get_cache_file()
                try:
                    self.dataset = nx.read_gpickle(fname)
                    # self.dataset.load(fname)
                except IOError:
                    self.parser.parse()
                    nx.write_gpickle(self.dataset, self._get_cache_file())
                    # self.dataset.save(self._get_cache_file())
            else:
                self.parser.parse()
        except Exception as e:
            logger.error("Error while generating provenance tree %s", e)
            raise

        # errs = []
        # self.dataset.check_consistency(errs)
        # if len(errs) > 0:
        #     logger.warning("Inconsistent provenance tree: %s", errs)
        num_nodes = self.dataset.number_of_nodes()
        logger.debug("Total nodes %d", num_nodes)
        progress = ProgressPrinter(num_nodes, desc="Remove kernel nodes")

        for node in self.dataset.nodes():
            # remove null capabilities
            # remove operations in kernel mode
            if (node.offset >= 0xFFFFFFFF0000000 or
                (node.length == 0 and node.base == 0)):
                # XXX should we remove the whole subtree?
                self.dataset.remove_node(node)
            progress.advance()
        progress.finish()

        num_nodes = self.dataset.number_of_nodes()
        logger.debug("Filtered kernel nodes, remaining %d", num_nodes)
        progress = ProgressPrinter(num_nodes, desc="Merge (cfromptr + csetbounds) sequences")

        for node in self.dataset.nodes():
            # merge cfromptr -> csetbounds subtrees
            if not self.dataset.has_node(node):
                # node removed
                continue
            if len(self.dataset.predecessors(node)) == 0:
                continue
            parent = self.dataset.predecessors(node)[0]
            if (parent.origin == CheriCapNodeNX.C_FROMPTR and
                node.origin == CheriCapNodeNX.C_SETBOUNDS and
                len(self.dataset.successors(parent)) == 1):
                # the child must be unique to avoid complex logic
                # when merging, it may be desirable to do so with
                # more complex traces
                node.origin = CheriCapNodeNX.C_PTR_SETBOUNDS
                if len(self.dataset.predecessors(parent)) > 0:
                    new_parent = self.dataset.predecessors(parent)[0]
                    self.dataset.remove_node(parent)
                    self.dataset.add_edge(new_parent, node)
                else:
                    self.dataset.remove_node(parent)
            progress.advance()
        progress.finish()

        # # suppress cfromptr
        # for node in self.dataset.nodes():
        #     if node.origin == CheriCapNodeNX.C_FROMPTR:
        #         self.dataset.remove_node(node)

        for node in self.dataset.nodes():
            if node.length > 2**20:
                logger.debug("Large node %s", node)

        assert len(self.dataset.nodes()) == len(set(self.dataset.nodes())), "Duplicate nodes"


class AddressMapPlot(PointerProvenancePlot):
    """
    Plot the provenance tree showing the time of allocation vs 
    base and bound of each node.
    """

    def __init__(self, tracefile):
        super(AddressMapPlot, self).__init__(tracefile)

        self.patch_builder = ColorCodePatchBuilder()
        """Strategy object that builds the plot components"""

    def plot(self):
        """
        Create the provenance plot and return the figure
        """

        fig = plt.figure(figsize=(15,10))
        ax = fig.add_axes([0.05, 0.15, 0.9, 0.80,],
                          projection="custom_addrspace")

        dataset_progress = ProgressPrinter(self.dataset.number_of_nodes(),
                                           desc="Adding nodes")
        for item in self.dataset.nodes():
            self.patch_builder.inspect(item)
            dataset_progress.advance()
        dataset_progress.finish()
        logger.debug("Nodes %d, ranges %d", self.dataset.number_of_nodes(),
                     len(self.patch_builder.ranges))

        for collection in self.patch_builder.get_patches():
            ax.add_collection(collection)
        ax.set_omit_ranges(self.patch_builder.get_omit_ranges())

        view_box = self.patch_builder.get_bbox()
        xmin = view_box.xmin * 0.98
        xmax = view_box.xmax * 1.02
        ymin = view_box.ymin * 0.98
        ymax = view_box.ymax * 1.02
        logger.debug("X limits: (%d, %d)", xmin, xmax)
        ax.set_xlim(xmin, xmax)
        logger.debug("Y limits: (%d, %d)", ymin, ymax)
        ax.set_ylim(ymin, ymax * 1.02)
        ax.invert_yaxis()
        ax.legend(*self.patch_builder.get_legend(), loc="best")
        ax.set_xlabel("Virtual Address")
        ax.set_ylabel("Time (millions of cycles)")

        logger.debug("Plot build completed")
        plt.savefig(self._get_plot_file())
        return fig


class PointerTreePlot(PointerProvenancePlot):
    """
    Plot the pointer tree
    """

    # def _plot_subtree(self, nodes):
    #     pos = nx.spring_layout(nodes)
    #     nx.draw_networkx_nodes(self.dataset, pos)
    #     nx.draw_networkx_edges(self.dataset, pos)

    #     labels = {}
    #     for node in self.dataset.nodes():
    #         labels[node] = "0x%x" % node.length
    #     nx.draw_networkx_labels(self.dataset, pos, labels, font_size=5)

    #     plt.axis("off")
    #     plt.savefig(self._get_plot_file())

    def plot(self):

        # roots = []

        # for node in self.dataset.nodes():
        #     if self.dataset.in_degree(node) == 0:
        #         roots.append(node)

        # max_root = roots[0]
        # for root in roots:
        #     if len(self.dataset.successors)

        pos = nx.spring_layout(self.dataset)

        node_sizes = np.array([n.length for n in self.dataset.nodes()])
        # normalize in the range min_size, max_size
        min_size = 100
        max_size = 300
        node_min = np.min(node_sizes) or 1
        node_max = np.max(node_sizes)
        b = (node_min * max_size - min_size * node_max) / (node_min - node_max)
        a = (min_size - b) / node_min
        node_sizes = a * node_sizes + b

        logger.warning(node_sizes)

        nx.draw_networkx_nodes(self.dataset, pos,
                               node_size=400,
                               node_color="lightblue")
        nx.draw_networkx_edges(self.dataset, pos)

        # labels = {}
        # for node in self.dataset.nodes():
        #     labels[node] = "0x%x" % node.length
        # nx.draw_networkx_labels(self.dataset, pos, labels, font_size=5)

        plt.axis("off")
        plt.savefig(self._get_plot_file())
