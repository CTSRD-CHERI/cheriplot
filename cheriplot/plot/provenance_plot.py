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
import pickle

from io import StringIO
from operator import attrgetter

from matplotlib import pyplot as plt
from matplotlib import lines, collections, transforms, patches, text
from matplotlib.colors import colorConverter

from ..utils import ProgressPrinter
from ..core import RangeSet, Range

from ..core import CallbackTraceParser, Instruction, VMMap
from ..plot import Plot, PatchBuilder, OmitRangeSetBuilder
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

    class SyscallTracker:
        """
        Keeps the current syscall context information so that
        the correct return point can be detected
        """

        def __init__(self):
            self.in_syscall = False
            """Flag indicates whether we are tracking a systemcall"""

            self.pc_syscall = None
            """syscall instruction PC"""

            self.pc_eret = None
            """related eret instruction PC"""

            self.code = None
            """syscall code"""

        def make_node(self):
            """
            Generate a node in the capability tree
            if the system call returns a capability
            """
            node = CheriCapNodeNX()
            node.origin = CheriCapNodeNX.SYS_MMAP
            # need to grab the node associated with the return value
            # and create a new one or mark it with SYS_MMAP
            # with t_alloc = entry.cycles

        def scan_syscall(self, inst, entry, regs):
            """
            Scan a syscall instruction and detect the syscall type
            and arguments
            """
            # syscall code in $v0
            # syscall arguments in $a0-$a7/$c3-$c10
            code = regs.gpr[1] # $v0
            indirect_code = regs.gpr[3] # $a0
            is_indirect = (code == 0 or code == 198)
            if ((is_indirect and indirect_code == 477) or
                (not is_indirect and code == 477)):
                # mmap syscall
                self.in_syscall = True
                self.pc_syscall = entry.pc
                self.pc_eret = entry.pc + 4
                self.code = indirect_code if is_indirect else code


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

        self.syscall_tracker = self.SyscallTracker()
        """Keep state related to system calls entry end return"""

    def scan_all(self, inst, entry, regs, last_regs, idx):
        """
        Detect end of syscalls by checking the expected return PC
        after an eret
        """
        if not self.regs_valid:
            return False

        if (self.syscall_tracker.in_syscall and
            entry.pc == self.syscall_tracker.pc_eret):
            node = self.syscall_tracker.make_node()
            logger.debug("Built syscall node %s", node)
        return False

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

    def scan_syscall(self, inst, entry, regs, last_regs, idx):
        """
        Record entering mmap system calls so that we can grab the return
        value at the end
        """
        self.syscall_tracker.scan_syscall(inst, entry, regs)
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
        self.regset.load(inst.cd.cap_index, node)
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
        self.regset.load(inst.cd.cap_index, node)
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
        if (inst.opcode == "ccall" or inst.opcode == "creturn" or
            inst.opcode == "cjalr"):
            logger.warning("cap flow control not yet handled, skipping")
            return False
        if entry.is_store or entry.is_load:
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
            logger.debug("Found %s value %s from memory load",
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
            logger.debug("Found %s value %s from memory store",
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
        if node.bound < node.base:
            logger.warning("Skip overflowed node %s", node)
            return
        keep_range = Range(node.base, node.bound, Range.T_KEEP)
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


class ColorCodePatchBuilder(PatchBuilder):
    """
    The patch generator build the matplotlib patches for each
    capability node.

    The nodes are rendered as lines with a different color depending
    on the permission bits of the capability. The builder produces
    a LineCollection for each combination of permission bits and
    creates the lines for the nodes.
    """

    def __init__(self):
        super(ColorCodePatchBuilder, self).__init__()

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
        if node.bound < node.base:
            logger.warning("Skip overflowed node %s", node)
            return
        node_y = node.t_alloc * self.y_unit
        node_box = transforms.Bbox.from_extents(node.base, node_y,
                                                node.bound, node_y)

        self._bbox = transforms.Bbox.union([self._bbox, node_box])
        keep_range = Range(node.base, node.bound, Range.T_KEEP)
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
            if ((node.pc and node.pc >= 0xFFFFFFFF0000000) or
                (node.length == 0 and node.base == 0)):
                # XXX should we remove the whole subtree?
                self.dataset.remove_node(node)
            progress.advance()
        progress.finish()

        num_nodes = self.dataset.number_of_nodes()
        logger.debug("Filtered kernel nodes, remaining %d", num_nodes)
        progress = ProgressPrinter(num_nodes, desc="Merge (cfromptr + csetbounds) sequences")

        for node in self.dataset.nodes():
            progress.advance()
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
        progress.finish()

        # this will hopefully go away changing graph library
        assert len(self.dataset.nodes()) == len(set(self.dataset.nodes())), "Duplicate nodes"


class VMMapPatchBuilder(PatchBuilder):
    """
    Build the patches that highlight the vmmap boundaries in the
    AddressMapPlot
    """

    def __init__(self):
        super(VMMapPatchBuilder, self).__init__()

        self.y_max = np.inf
        """Max value on the y-axis computed by the AddressMapPlot"""

        self.patches = []
        """List of rectangles"""

        self.patch_colors = []
        """List of colors for the patches"""

        self.annotations = []
        """Text labels"""

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

    def inspect(self, vmentry):
        rect = patches.Rectangle((vmentry.start, 0),
                                 vmentry.end - vmentry.start, self.y_max)
        self.patches.append(rect)
        self.patch_colors.append(self._colors[vmentry.perms])

        label_position = ((vmentry.start + vmentry.end) / 2, self.y_max / 2)
        vme_path = str(vmentry.path).split("/")[-1] if str(vmentry.path) else ""
        if not vme_path and vmentry.grows_down:
            vme_path = "stack"
        vme_label = "%s %s" % (vmentry.perms, vme_path)
        label = text.Text(text=vme_label, rotation="vertical",
                          position=label_position,
                          horizontalalignment="center",
                          verticalalignment="center")
        self.annotations.append(label)


    def params(self, **kwargs):
        self.y_max = kwargs.get("y_max", self.y_max)

    def get_patches(self):
        coll = collections.PatchCollection(self.patches, alpha=0.1,
                                           facecolors=self.patch_colors)
        return [coll]

    def get_annotations(self):
        return self.annotations


class AddressMapPlot(PointerProvenancePlot):
    """
    Plot the provenance tree showing the time of allocation vs
    base and bound of each node.
    """

    def __init__(self, tracefile):
        super(AddressMapPlot, self).__init__(tracefile)

        self.patch_builder = ColorCodePatchBuilder()
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

        self.vmmap_patch_builder = VMMapPatchBuilder()
        """
        Helper object that builds patches to display VM map regions.
        See :class:`.VMMapPatchBuilder`
        """

        self.vmmap = None
        """VMMap object representing the process memory map"""

    def set_vmmap(self, mapfile):
        """
        Set the vmmap CSV file containing the VM mapping for the process
        that generated the trace, as obtained from procstat or libprocstat
        """
        self.vmmap = VMMap(mapfile)

    def build_dataset(self):
        super(AddressMapPlot, self).build_dataset()

        highmap = {}
        logger.debug("Search for capability manipulations in high userspace memory")
        for node in self.dataset.nodes():
            if node.base > 0x120001341:
                if node.pc not in highmap:
                    highmap[node.pc] = node
                    logger.debug("found high userspace entry %s, pc:0x%x", node, node.pc)

    def plot(self):
        """
        Create the address-map plot
        """

        fig = plt.figure(figsize=(15,10))
        ax = fig.add_axes([0.05, 0.15, 0.9, 0.80,],
                          projection="custom_addrspace")

        dataset_progress = ProgressPrinter(self.dataset.number_of_nodes(),
                                           desc="Adding nodes")
        for item in self.dataset.nodes():
            self.patch_builder.inspect(item)
            self.range_builder.inspect(item)
            dataset_progress.advance()
        dataset_progress.finish()

        view_box = self.patch_builder.get_bbox()
        xmin = view_box.xmin * 0.98
        xmax = view_box.xmax * 1.02
        ymin = view_box.ymin * 0.98
        ymax = view_box.ymax * 1.02

        if self.vmmap:
            self.vmmap_patch_builder.params(y_max=ymax)
            for vme in self.vmmap:
                self.vmmap_patch_builder.inspect(vme)
                self.range_builder.inspect_range(Range(vme.start, vme.end))

        logger.debug("Nodes %d, ranges %d", self.dataset.number_of_nodes(),
                     len(self.range_builder.ranges))

        for collection in self.patch_builder.get_patches():
            ax.add_collection(collection)
        ax.set_omit_ranges(self.range_builder.get_omit_ranges())
        if self.vmmap:
            for collection in self.vmmap_patch_builder.get_patches():
                ax.add_collection(collection)
            for label in self.vmmap_patch_builder.get_annotations():
                ax.add_artist(label)

        logger.debug("X limits: (%d, %d)", xmin, xmax)
        ax.set_xlim(xmin, xmax)
        logger.debug("Y limits: (%d, %d)", ymin, ymax)
        ax.set_ylim(ymin, ymax * 1.02)
        # manually set xticks based on the vmmap if we can
        if self.vmmap:
            start_ticks = [vme.start for vme in self.vmmap]
            end_ticks = [vme.end for vme in self.vmmap]
            ticks = sorted(start_ticks + end_ticks)
            # current_ticks = ax.get_ticks()
            logger.debug("address map ticks %s", ["0x%x" % t for t in ticks])
            ax.set_xticks(ticks)

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
                               node_size=100,
                               node_color="lightblue")
        nx.draw_networkx_edges(self.dataset, pos)

        # labels = {}
        # for node in self.dataset.nodes():
        #     labels[node] = "0x%x" % node.length
        # nx.draw_networkx_labels(self.dataset, pos, labels, font_size=5)

        plt.axis("off")
        plt.savefig(self._get_plot_file())


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


class OmitRangeBuilder(PatchBuilder):
    """
    XXX split the omit-range generation logic from the patch builder logic
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
