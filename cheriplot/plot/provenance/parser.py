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

from enum import IntEnum
from functools import reduce

from cheriplot.core.parser import CallbackTraceParser, Instruction
from cheriplot.core.provenance import (
    CheriCapPerm, CheriNodeOrigin, NodeData, CheriCap)

logger = logging.getLogger(__name__)

class PointerProvenanceParser(CallbackTraceParser):
    """
    Parsing logic that builds the provenance graph used in
    all the provenance-based plots.

    XXX may want to pull out all the nested classes in case they
    can be reused.
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
        def __init__(self, graph):
            self.reg_nodes = np.empty(32, dtype=object)
            """Graph node associated with each register."""

            self.memory_map = {}
            """CheriCapNodes stored in memory."""

            self.pcc = None
            """Current pcc node"""

            self.graph = graph
            """The provenance graph"""

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
            # if the current value of the register set is short-lived
            # (never stored anywhere and not in any other regset node)
            # then it is effectively lost and "deallocated"
            # if self.reg_nodes[idx] is not None:
            #     n_refs = np.count_nonzero(self.reg_nodes == self.reg_nodes[idx])
            #     node_data = self.graph.vp.data[self.reg_nodes[idx]]
            #     # XXX may refine this by checking the memory_map to see if the
            #     # node is still there
            #     n_refs += len(node_data.address)
            #     if n_refs == 1:
            #         # can safely set the t_free
            #         disable because we need a way to actually get the current cycle
            self.reg_nodes[idx] = val


    class SyscallContext:
        """
        Keeps the current syscall context information so that
        the correct return point can be detected.

        This class contains all the methods that manipulate
        registers and values that depend on the ABI and constants
        in CheriBSD.
        """
        class SyscallCode(IntEnum):
            """
            Enumerate system call numbers that are recognised by the
            parser and are used to add information to the provenance
            graph.
            """
            SYS_MMAP = 477
            SYS_MUNMAP = 73
            # also interesting mprotect and shm* stuff


        def __init__(self, *args, **kwargs):
            self.in_syscall = False
            """Flag indicates whether we are tracking a systemcall."""

            self.pc_syscall = None
            """Syscall instruction PC."""

            self.t_syscall = None
            """Syscall instruction cycle number."""

            self.pc_eret = None
            """Expected eret instruction PC."""

            self.code = None
            """Current syscall code."""

        def _get_syscall_code(self, regs):
            """Get the syscall code for direct and indirect syscalls."""
            # syscall code in $v0
            # syscall arguments in $a0-$a7/$c3-$c10
            code = regs.gpr[1] # $v0
            indirect_code = regs.gpr[3] # $a0
            is_indirect = (code == 0 or code == 198)
            return indirect_code if is_indirect else code

        def scan_syscall_start(self, inst, entry, regs, dataset, regset):
            """
            Scan a syscall instruction and detect the syscall type
            and arguments.
            """
            code = self._get_syscall_code(regs)
            try:
                self.code = self.SyscallCode(code)
            except ValueError:
                # we are not interested in this syscall
                return
            self.in_syscall = True
            self.pc_syscall = entry.pc
            self.t_syscall = entry.cycles
            self.pc_eret = entry.pc + 4

            # create a node at syscall start for those system calls for
            # which we care about the arguments
            if self.code.value == self.SyscallCode.SYS_MUNMAP:
                src_reg = 3 # argument in $c3
                origin = CheriNodeOrigin.SYS_MUNMAP
            else:
                # we do not do anything for other syscalls
                return None

            data = NodeData()
            data.cap = CheriCap(regs.cap_reg[src_reg])
            data.cap.t_alloc = entry.cycles
            # XXX may want a way to store call pc and return pc
            data.pc = entry.pc
            data.origin = origin
            data.is_kernel = False
            node = dataset.add_vertex()
            dataset.vp.data[node] = data
            # attach the new node to the capability node in src_reg
            # and replace it in the register set
            parent = regset[src_reg]
            dataset.add_edge(parent, node)
            regset[src_reg] = node
            return node

        def scan_syscall_end(self, inst, entry, regs, dataset, regset):
            """
            Scan registers to produce a syscall end node.
            """
            self.in_syscall = False

            # create a node for the syscall start
            if self.code.value == self.SyscallCode.SYS_MMAP:
                ret_reg = 3 # return in $c3
                origin = CheriNodeOrigin.SYS_MMAP
            else:
                # we do not do anything for other syscalls
                return None

            data = NodeData()
            data.cap = CheriCap(regs.cap_reg[ret_reg])
            data.cap.t_alloc = entry.cycles
            # XXX may want a way to store call pc and return pc
            data.pc = entry.pc
            data.origin = origin
            data.is_kernel = False
            node = dataset.add_vertex()
            dataset.vp.data[node] = data
            # attach the new node to the capability node in ret_reg
            # and replace it in the register set
            parent = regset[ret_reg]
            dataset.add_edge(parent, node)
            regset[ret_reg] = node
            return node

    class CallContext:
        pass


    def __init__(self, dataset, trace):
        super(PointerProvenanceParser, self).__init__(dataset, trace)
        self.regs_valid = False
        """
        Flag used to disable parsing until the registerset
        is completely initialised.
        """

        self.regset = self.RegisterSet(dataset)
        """
        Register set that maps capability registers
        to nodes in the provenance tree.
        """

        self.syscall_context = self.SyscallContext()
        """Keep state related to system calls entry end return"""

        self.call_context = self.CallContext()
        """Keep state related to function calls and call stack"""

    def _set_initial_regset(self, inst, entry, regs):
        """
        Setup the registers after the first eret
        """
        self.regs_valid = True
        logger.debug("Scan initial register set cycle: %d", entry.cycles)
        for idx in range(0, 32):
            cap = regs.cap_reg[idx]
            valid = regs.valid_caps[idx]
            if valid:
                node = self.make_root_node(entry, cap, pc=0)
                self.regset[idx] = node
            else:
                logger.warning("c%d not in initial set", idx)
                if idx == 29:
                    node = self.make_root_node(entry, None, pc=0)
                    cap = CheriCap()
                    cap.base = 0
                    cap.offset = 0
                    cap.length = 0xffffffffffffffff
                    cap.permissions = 0xffff # all XXX should we only have EXEC and few other?
                    cap.valid = True
                    # set the guessed capability value to the vertex data
                    # property
                    self.dataset.vp.data[node].cap = cap
                    self.regset[idx] = node
                    logger.warning("Guessing KCC %s", self.dataset.vp.data[node])
                if idx == 30:
                    # guess the value of KDC and use this in the initial register set
                    node = self.make_root_node(entry, None, pc=0)
                    self.regset[idx] = node
                    cap = CheriCap()
                    cap.base = 0
                    cap.offset = 0
                    cap.length = 0xffffffffffffffff
                    # cap.permissions = (
                    #     CheriCapPerm.LOAD | CheriCapPerm.STORE |
                    #     CheriCapPerm.EXEC | CheriCapPerm.GLOBAL |
                    #     CheriCapPerm.CAP_LOAD | CheriCapPerm.CAP_STORE |
                    #     CheriCapPerm.CAP_STORE_LOCAL | CheriCapPerm.SEAL |
                    #     CheriCapPerm.SYSTEM_REGISTERS)
                    cap.permissions = 0xffff # all
                    cap.valid = True
                    self.dataset.vp.data[node].cap = cap
                    self.regset[idx] = node
                    logger.warning("Guessing KDC %s", self.dataset.vp.data[node])

    def _has_exception(self, entry, code=None):
        """
        Check if an exception occurred in the given trace entry
        """
        if code is not None:
            return entry.exception == code
        else:
            return entry.exception != 31

    def _instr_committed(self, inst, entry, regs, last_regs):
        """
        Check if an instruction has been committed and will
        not be replayed.

        """
        # XXX disable it because things break when the exception does
        # not roll-back the instruction, there is no way of detecting
        # this so we just assume that it can happen.
        # if self._has_exception(entry) and entry.exception != 0:
        #     return False
        return True

    def _do_scan(self, entry):
        """
        Check if the scan of an instruction can proceed.
        This disables scanning until the regiser set is initialized
        after the first eret and do not scan instructions that did
        not commit due to exceptions being raised.
        """
        # if self.regs_valid and self._instr_committed(entry):
        if self.regs_valid:
            return True
        return False

    def scan_all(self, inst, entry, regs, last_regs, idx):
        """
        Detect end of syscalls by checking the expected return PC
        after an eret
        """
        if not self.regs_valid:
            return False

        if self._has_exception(entry):
            # if an exception occurred adjust EPCC node from PCC,
            # this also handles syscall exceptions.
            # if the instruction is an eret that is causing an exception
            # EPCC and PCC do not change and we end up in an handler again
            logger.debug("except {%d}: update epcc %s, update pcc %s",
                         entry.cycles,
                         self.dataset.vp.data[self.regset.pcc],
                         self.dataset.vp.data[self.regset[29]])
            self.regset[31] = self.regset.pcc # saved pcc
            self.regset.pcc = self.regset[29] # pcc <- kcc

        if (self.syscall_context.in_syscall and
            entry.pc == self.syscall_context.pc_eret):
            node = self.syscall_context.scan_syscall_end(
                    inst, entry, regs, self.dataset, self.regset)
            logger.debug("Built syscall node %s", node)
        return False

    def scan_eret(self, inst, entry, regs, last_regs, idx):
        """
        Detect the first eret that enters the process code
        and initialise the register set and the roots of the tree.
        """
        if not self.regs_valid:
            self._set_initial_regset(inst, entry, regs)

        # eret may throw an exception, in which case the nodes
        # are handled again in scan_all (which is always executed
        # after per-opcode scan_* methods)
        logger.debug("eret {%d}: update pcc %s", entry.cycles,
                     self.dataset.vp.data[self.regset[31]])
        self.regset.pcc = self.regset[31] # restore saved pcc
        return False

    def scan_syscall(self, inst, entry, regs, last_regs, idx):
        """
        Record entering mmap system calls so that we can grab the return
        value at the end
        """
        if not self.regs_valid:
            return False

        self.syscall_context.scan_syscall_start(inst, entry, regs,
                                                self.dataset, self.regset)
        return False

    def scan_cclearregs(self, inst, entry, regs, last_regs, idx):
        """
        Clear the register set according to the mask.
        The result can not be immediately found in the trace, it
        is otherwise spread among all the uses of the registers.
        """
        raise NotImplementedError("cclearregs not yet supported")
        return False

    def _handle_cpreg_get(self, regnum, inst, entry):
        """
        When a cgetXXX is found, propagate the node from the special
        register XXX (i.e. kcc, kdc, ...) to the destination or create a
        new node if nothing was there.

        :param regnum: the index of the special register in the register set
        :type regnum: int

        :param inst: parsed instruction
        :type inst: :class:`cheriplot.core.parser.Instruction`

        :parm entry: trace entry
        :type entry: :class:`pycheritrace.trace_entry`
        """
        if not self._do_scan(entry):
            return False
        if self.regset[regnum] is None:
            # no node was ever created for the register, it contained something
            # invalid
            node = self.make_root_node(entry, inst.op0.value,
                                       time=entry.cycles)
            self.regset[regnum] = node
            logger.debug("cpreg_get: new node from $c%d %s",
                         regnum, self.dataset.vp.data[node])
        self.regset[inst.op0.cap_index] = self.regset[regnum]

    def _handle_cpreg_set(self, regnum, inst, entry):
        """
        When a csetXXX is found, propagate the node to the special
        register XXX (i.e. kcc, kdc, ...) or create a new node.

        :param regnum: the index of the special register in the register set
        :type regnum: int

        :param inst: parsed instruction
        :type inst: :class:`cheriplot.core.parser.Instruction`

        :parm entry: trace entry
        :type entry: :class:`pycheritrace.trace_entry`
        """
        if not self._do_scan(entry):
            return False
        if self.regset[inst.op0.cap_index] is None:
            node = self.make_root_node(entry, inst.op0.value,
                                       time=entry.cycles)
            self.regset[inst.op0.cap_index] = node
            logger.debug("cpreg_set: new node from c<%d> %s",
                         regnum, self.dataset.vp.data[node])
        self.regset[regnum] = self.regset[inst.op0.cap_index]

    def scan_cgetepcc(self, inst, entry, regs, last_regs, idx):
        self._handle_cpreg_get(31, inst, entry)
        return False

    def scan_csetepcc(self, inst, entry, regs, last_regs, idx):
        self._handle_cpreg_set(31, inst, entry)
        return False

    def scan_cgetkcc(self, inst, entry, regs, last_regs, idx):
        self._handle_cpreg_get(29, inst, entry)
        return False

    def scan_csetkcc(self, inst, entry, regs, last_regs, idx):
        self._handle_cpreg_set(29, inst, entry)
        return False

    def scan_cgetkdc(self, inst, entry, regs, last_regs, idx):
        self._handle_cpreg_get(30, inst, entry)
        return False

    def scan_csetkdc(self, inst, entry, regs, last_regs, idx):
        self._handle_cpreg_set(30, inst, entry)
        return False

    def scan_cgetdefault(self, inst, entry, regs, last_regs, idx):
        self._handle_cpreg_get(0, inst, entry)
        return False

    def scan_csetdefault(self, inst, entry, regs, last_regs, idx):
        self._handle_cpreg_set(0, inst, entry)
        return False

    def scan_cgetpcc(self, inst, entry, regs, last_regs, idx):
        if not self._do_scan(entry):
            return False
        if self.regset.pcc is None:
            # never seen anything in pcc so we create a new node
            node = self.make_root_node(entry, inst.op0.value,
                                       time=entry.cycles)
            self.regset.pcc = node
            logger.debug("cgetpcc: new node from pcc %s",
                         regnum, self.dataset.vp.data[node])
        self.regset[inst.op0.cap_index] = self.regset.pcc
        return False

    def scan_cgetpccsetoffset(self, inst, entry, regs, last_regs, idx):
        return self.scan_cgetpcc(inst, entry, regs, last_regs, idx)

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
        if not self._do_scan(entry):
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
        if not self._do_scan(entry):
            return False
        node = self.make_node(entry, inst, origin=CheriNodeOrigin.FROMPTR)
        self.regset[inst.op0.cap_index] = node
        return False

    def scan_candperm(self, inst, entry, regs, last_regs, idx):
        """
        Each candperm is a new pointer allocation and is recorded
        as a new node in the provenance tree.

        candperm:
        Operand 0 is the register with the new node
        Operand 1 is the register with the parent node
        """
        if not self._do_scan(entry):
            return False
        node = self.make_node(entry, inst, origin=CheriNodeOrigin.ANDPERM)
        self.regset[inst.op0.cap_index] = node
        return False

    def scan_cap(self, inst, entry, regs, last_regs, idx):
        """
        Whenever a capability instruction is found, update
        the mapping from capability register to the provenance
        tree node associated to the capability in it.
        """
        if not self._do_scan(entry):
            return False

        if inst.opcode == "cjr":
            # discard current pcc and replace it
            if self.regset[inst.op0.cap_index] is not None:
                # we already have a node for the new PCC
                self.regset.pcc = self.regset[inst.op0.cap_index]
                pcc_data = self.dataset.vp.data[self.regset.pcc]
                if not pcc_data.cap.has_perm(CheriCapPerm.EXEC):
                    logger.error("Loading PCC without exec permissions? %s %s",
                                 inst, pcc_data)
                    raise RuntimeError("Loading PCC without exec permissions")
            else:
                # we should create a node here but this should really
                # not be happening, the node is None only when the
                # register content has never been seen before.
                logger.error("Found cjr with unexpected "
                             "target capability %s", inst)
                raise RuntimeError("cjr to unknown capability")
        elif inst.opcode == "cjalr":
            # save current pcc
            cd_idx = inst.op0.cap_index
            if self.regset.pcc is None:
                # create a root node for PCC that is in cd
                old_pcc_node = self.make_root_node(entry, inst.op0.value,
                                                   time=entry.cycles)
            else:
                old_pcc_node = self.regset.pcc
            self.regset[cd_idx] = old_pcc_node

            # discard current pcc and replace it
            if self.regset[inst.op1.cap_index] is not None:
                # we already have a node for the new PCC
                self.regset.pcc = self.regset[inst.op1.cap_index]
                pcc_data = self.dataset.vp.data[self.regset.pcc]
                if not pcc_data.cap.has_perm(CheriCapPerm.EXEC):
                    logger.error("Loading PCC without exec permissions? %s %s",
                                 inst, pcc_data)
                    raise RuntimeError("Loading PCC without exec permissions")
            else:
                # we should create a node here but this should really
                # not be happening, the node is None only when the
                # register content has never been seen before.
                logger.error("Found cjalr with unexpected "
                             "target capability %s", inst)
                raise RuntimeError("cjalr to unknown capability")
        elif inst.opcode == "ccall" or inst.opcode == "creturn":
            # these are handled by software so all register assignments
            # are already parsed there
            return False
        elif entry.is_store or entry.is_load:
            return False
        else:
            self.update_regs(inst, entry, regs, last_regs)
        return False

    def _handle_dereference(self, inst, entry, ptr_reg):
        """
        Store offset at time of dereference of a given capability.
        """
        try:
            node = self.regset[ptr_reg]
        except KeyError:
            logger.error("{%d} Dereference unknown capability %s",
                         entry.cycles, inst)
            raise RuntimeError("Dereference unknown capability")
        if node is None:
            logger.error("{%d} Dereference unknown capability %s",
                         entry.cycles, inst)
            raise RuntimeError("Dereference unknown capability")
        node_data = self.dataset.vp.data[node]
        # instead of the capability register offset we use the
        # entry memory_address so we capture any extra offset in
        # the instruction as well
        is_cap = inst.opcode.startswith("clc") or inst.opcode.startswith("csc")
        if entry.is_load:
            node_data.add_load(entry.cycles, entry.memory_address, is_cap)
        elif entry.is_store:
            node_data.add_store(entry.cycles, entry.memory_address, is_cap)
        else:
            if not self._has_exception(entry):
                logger.error("Dereference is neither a load or a store %s", inst)
                raise RuntimeError("Dereference is neither a load nor a store")

    def scan_cap_load(self, inst, entry, regs, last_regs, idx):
        """
        Store all offsets at time of dereference of a given capability.

        clX[u] have pointer argument in op3
        clXr and clXi have pointer argument in op2
        cllX have pointer argument in op1
        """
        if not self._do_scan(entry):
            return False

        # get the register with the address capability
        # this may be a normal capability load or a linked-load
        if inst.opcode.startswith("cll"):
            ptr_reg = inst.op1.cap_index
        else:
            if inst.opcode[-1] == "r" or inst.opcode[-1] == "i":
                ptr_reg = inst.op2.cap_index
            else:
                ptr_reg = inst.op3.cap_index
        self._handle_dereference(inst, entry, ptr_reg)
        return False

    def scan_cap_store(self, inst, entry, regs, last_regs, idx):
        """
        Store all offsets at time of dereference of a given capability.

        csX have pointer argument in op3
        csXr and csXi have pointer argument in op2
        cscX conditionals use op2
        """
        if not self._do_scan(entry):
            return False
        # get the register with the address capability
        # this may be a normal capability store or an atomic-store
        if inst.opcode != "csc" and inst.opcode.startswith("csc"):
            # atomic
            ptr_reg = inst.op2.cap_index
        else:
            if inst.opcode[-1] == "r" or inst.opcode[-1] == "i":
                ptr_reg = inst.op2.cap_index
            else:
                ptr_reg = inst.op3.cap_index
        self._handle_dereference(inst, entry, ptr_reg)
        return False

    def scan_clc(self, inst, entry, regs, last_regs, idx):
        """
        clc:
        Operand 0 is the register with the new node
        The parent is looked up in memory or a root node is created
        """
        if not self._do_scan(entry):
            return False

        cd = inst.op0.cap_index
        try:
            node = self.regset.memory_map[entry.memory_address]
        except KeyError:
            logger.debug("Load c%d from new location 0x%x",
                         cd, entry.memory_address)
            node = None

        # if the capability loaded from memory is valid, it
        # can be safely assumed that it corresponds to the node
        # stored in the memory_map for that location, if there is
        # one. If there is no node in the memory_map then a
        # new node can be created from the valid capability.
        # Otherwise something has changed the memory location so we
        # clear the memory_map and the regset entry.
        if not inst.op0.value.valid:
            self.regset[cd] = None
            if node is not None:
                del self.regset.memory_map[entry.memory_address]
        else:
            # check if the load instruction has committed
            old_cd = CheriCap(last_regs.cap_reg[cd])
            curr_cd = CheriCap(regs.cap_reg[cd])
            if old_cd != curr_cd:
                # the destination register was updated so the
                # instruction did commit

                if node is None:
                    # add a node as a root node because we have never
                    # seen the content of this register yet.
                    node = self.make_root_node(entry, inst.op0.value,
                                               time=entry.cycles)
                    logger.debug("Found %s value %s from memory load",
                                 inst.op0.name, self.dataset.vp.data[node])
                    self.regset.memory_map[entry.memory_address] = node
                self.regset[cd] = node
        return False

    scan_clcr = scan_clc
    scan_clci = scan_clc

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
        if not self._do_scan(entry):
            return False

        cd = inst.op0.cap_index
        node = self.regset[cd]

        if inst.op0.value.valid:
            # if this is not a data access

            if node is None:
                # need to create one
                node = self.make_root_node(entry, inst.op0.value,
                                           time=entry.cycles)
                self.regset[cd] = node
                logger.debug("Found %s value %s from memory store",
                             inst.op0.name, node)

            # if there is a node associated with the register that is
            # being stored, save it in the memory_map for the memory location
            # written by csc
            self.regset.memory_map[entry.memory_address] = node
            # set the address attribute of the node vertex data property
            node_data = self.dataset.vp.data[node]
            node_data.address[entry.cycles] = entry.memory_address

        return False

    scan_cscr = scan_csc
    scan_csci = scan_csc

    def make_root_node(self, entry, cap, time=0, pc=None):
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
        data.pc = entry.pc if pc is None else pc
        data.origin = CheriNodeOrigin.ROOT
        data.is_kernel = entry.is_kernel()

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
