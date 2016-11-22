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

from io import StringIO

from cheriplot.core.parser import CallbackTraceParser, Instruction
from cheriplot.core.provenance import (GraphManager, GraphNode, CheriCapPerm,
                                       CheriNodeOrigin, NodeData, CheriCap)

logger = logging.getLogger(__name__)

class PointerProvenanceParser(CallbackTraceParser):
    """
    Parsing logic that builds the provenange graph used in
    all the provenance-based plots.
    """

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
            """
            Fetch the :class:`cheriplot.core.provenance.GraphNode`
            currently associated to a capability register with the
            given register number.
            """
            return self.reg_nodes[idx]

        def __setitem__(self, idx, val):
            """
            Fetch the :class:`cheriplot.core.provenance.GraphNode`
            currently associated to a capability register with the
            given register number.
            """
            self.reg_nodes[idx] = val

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
            # node = CheriCapNodeNX()
            # node.origin = CheriCapNodeNX.SYS_MMAP
            pass
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
            # node = self.syscall_tracker.make_node()
            # XXX TO DO
            node = None
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
                node = self.make_root_node(entry, cap)
                self.regset[idx] = node
            else:
                logger.warning("c%d not in initial set", idx)
                if idx == 30:
                    node = self.make_root_node(entry, None)
                    self.regset[idx] = node
                    cap = CheriCap()
                    cap.base = 0
                    cap.offset = 0
                    cap.length = 0xffffffffffffffff
                    cap.permission = (
                        CheriCapPerm.LOAD | CheriCapPerm.STORE |
                        CheriCapPerm.EXEC | CheriCapPerm.GLOBAL |
                        CheriCapPerm.CAP_LOAD | CheriCapPerm.CAP_STORE |
                        CheriCapPerm.CAP_STORE_LOCAL | CheriCapPerm.SEAL |
                        CheriCapPerm.SYSTEM_REGISTERS)
                    # set the guessed capability value to the vertex data
                    # property
                    self.dataset.vp.data[node].cap = cap
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
        # self.syscall_tracker.scan_syscall(inst, entry, regs) XXX disabled
        return False

    def scan_csetbounds(self, inst, entry, regs, last_regs, idx):
        """
        Each csetbounds is a new pointer allocation
        and is recorded as a new node in the provenance tree.
        The destination register is associated to the new node
        in the register set.

        csetbounds:
        Operand 0 is the register with the new node
        Operand 1 is the register with the parent node
        """
        if not self.regs_valid:
            return False
        node = self.make_node(entry, inst, origin=CheriNodeOrigin.SETBOUNDS)
        self.regset[inst.op0.cap_index] = node
        return False

    def scan_cfromptr(self, inst, entry, regs, last_regs, idx):
        """
        Each cfromptr is a new pointer allocation and is
        recodred as a new node in the provenance tree.
        The destination register is associated to the new node
        in the register set.

        cfromptr:
        Operand 0 is the register with the new node
        Operand 1 is the register with the parent node
        """
        if not self.regs_valid:
            return False
        node = self.make_node(entry, inst, origin=CheriNodeOrigin.FROMPTR)
        self.regset[inst.op0.cap_index] = node
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

        clc:
        Operand 0 is the register with the new node
        The parent is looked up in memory or a root node is created
        """
        if not self.regs_valid:
            return False

        cd = inst.op0.cap_index
        try:
            node = self.regset.memory_map[entry.memory_address]
        except KeyError:
            logger.debug("Load c%d from new location 0x%x",
                         cd, entry.memory_address)
            if not inst.op0.value.valid:
                # can not create a node from the instruction value
                # this is ok, using clc for generic data
                return False
            node = None

        if node is None:
            # add a node as a root node because we have never
            # seen the content of this register yet.
            node = self.make_root_node(entry, inst.op0.value, time=entry.cycles)
            logger.debug("Found %s value %s from memory load",
                         inst.op0.name, node)
        self.regset[cd] = node
        return False

    def scan_csc(self, inst, entry, regs, last_regs, idx):
        """
        Record the locations where a capability node is stored.
        This is later used if the capability is loaded again with
        a clc.
        The locations where a capability is stored are also saved in
        the graph.
        It may happen that a previously unseen register is stored,
        the value of the register is now known to be valid because it
        is stored in the trace entry, a root node is created.

        csc:
        Operand 0 is the capability being stored, the node already exists
        """
        if not self.regs_valid:
            return False
        cd = inst.op0.cap_index
        node = self.regset[cd]
        if node is None and not last_regs.valid_caps[cd]:
            # add a node as a root node because we have never
            # seen the content of this register yet
            node = self.make_root_node(entry, inst.op0.value)
            self.regset[cd] = node
            logger.debug("Found %s value %s from memory store",
                         inst.op0.name, node)
            return False
        self.regset.memory_map[entry.memory_address] = node
        # set the address attribute of the node vertex data property
        self.dataset.vp.data[node].address[entry.cycles] = entry.memory_address
        return False

    def make_root_node(self, entry, cap, time=0, pc=0):
        """
        Create a root node of the provenance graph and add it to the dataset.

        :param entry: trace entry of the current instruction
        :type entry: `pycheritrace.trace_entry`
        :param cap: capability register value
        :type cap: :class:`pycheritrace.capability_register`
        :param time: optional allocation time
        :type time: int
        :param: pc: optional PC value for the root node
        :type pc: int
        :return: the newly created node
        :rtype: :class:`graph_tool.Vertex`
        """
        data = NodeData()
        data.cap = CheriCap(cap)
        # if pc is 0 indicate that we do not have a specific
        # instruction for this
        data.cap.t_alloc = time
        data.pc = pc
        data.origin = CheriNodeOrigin.ROOT
        data.is_kernel = bool(entry.is_kernel)

        # create graph vertex and assign the data to it
        vertex = self.dataset.add_vertex()
        self.dataset.vp.data[vertex] = data
        return vertex

    def make_node(self, entry, inst, origin=None, src_op_index=1, dst_op_index=0):
        """
        Create a node in the provenance tree.
        The parent is fetched from the register set depending on the source
        registers of the current instruction.

        :param entry: trace entry info object
        :type entry: :class:`pycheritrace.trace_entry`
        :param inst: instruction parsed
        :type inst: :class:`cheriplot.core.parser.Instruction`
        :param origin: the instruction/construction that originated the node
        :type origin: :class:`cheriplot.core.provenance.CheriNodeOrigin`
        :param src_op_index: index of the instruction operand that
        associated with the parent node
        :type src_op_index: int
        :param dst_op_index: index of the instruction operand with
        the node data
        :type dst_op_index: int
        :return: the new node
        :rtype: :class:`graph_tool.Vertex`
        """
        data = NodeData.from_operand(inst.operands[dst_op_index])
        data.origin = origin
        # try to get a parent node
        try:
            op = inst.operands[src_op_index]
            parent = self.regset[op.cap_index]
        except:
            logger.error("Error searching for parent node of %s", node)
            raise

        # there must be a parent if the root nodes for the initial register
        # set have been created
        # Note that we may chose to add a root node when no parent is
        # available, this may be the case of replacing the guess of KDC
        if parent == None:
            logger.error("Missing parent for %s, src_operand=%d %s, "
                         "dst_operand=%d %s", node,
                         src_op_index, inst.operands[src_op_index],
                         dst_op_index, inst.operands[dst_op_index])
            raise RuntimeError("Missing parent for %s" % node)

        # create the vertex in the graph and assign the data to it
        vertex = self.dataset.add_vertex()
        self.dataset.add_edge(parent, vertex)
        self.dataset.vp.data[vertex] = data
        return vertex

    def update_regs(self, inst, entry, regs, last_regs):
        """
        Try to update the registers-node mapping when a capability
        instruction is executed so that nodes are propagated in
        the registers when their bounds do not change.
        """        
        cd = inst.op0
        cb = inst.op1
        if not cd or not cb:
            return
        if (cb.is_capability and cd.is_capability):
            self.regset[cd.cap_index] = self.regset[cb.cap_index]
