"""
Parse a cheri trace to a pointer provenance tree
"""

import sys
import os
import logging
import re
import pycheritrace as pct
import numpy as np

from functools import reduce

from cheri_trace_parser.core.parser import TraceParser
from cheri_trace_parser.utils import ProgressPrinter
from .cheri_provenance import CheriCapNode

logger = logging.getLogger(__name__)

class PointerProvenanceParser(TraceParser):

    def __init__(self, *args, **kwargs):
        super(PointerProvenanceParser, self).__init__(*args, **kwargs)
        # context
        self.parser_context = None
        self.dis = pct.disassembler()
        self.progress = ProgressPrinter(len(self), desc="Scanning trace")
        self.last_regs = None
        self.regs_valid = False

    def parse(self, tree, start=None, end=None):

        self.parser_context = ProvenanceParserContext(tree)

        def _scan(entry, regs, idx):

            self.progress.advance()
            inst = self.dis.disassemble(entry.inst)
            parts = inst.name.split("\t")
            opcode = parts[1]

            if self.regs_valid:
                if opcode == "csetbounds":
                    self.parser_context.csetbounds(entry, regs, self.last_regs, inst)
                elif opcode == "cfromptr":                    
                    self.parser_context.cfromptr(entry, regs, self.last_regs, inst)
                elif opcode == "csc":
                    self.parser_context.csc(entry, regs, self.last_regs, inst)
                elif opcode == "clc":
                    self.parser_context.clc(entry, regs, self.last_regs, inst)
                elif (opcode[0] == "c" and opcode != "cache"):
                    # the matching here may be unreliable..
                    self.parser_context.update_regs(entry, regs, self.last_regs, inst)
            elif opcode == "eret":
                if not self.regs_valid:
                    self.parser_context.scan_root_cap(regs)
                    self.regs_valid = True

            self.last_regs = regs
            return False

        self.trace.scan(_scan, 0, len(self))
        self.progress.finish()

class ProvenanceParserContext(object):

    class RegisterSet:
        """
        Extended register set that keeps track of memory
        operations on capabilities.

        We need to know where a register value has been read from
        and where it is stored to. The first is used to infer
        the correct CapNode to add as parent for a new node,
        the latter allows us to set the CapNode.address for
        a newly allocated capability
        """
        def __init__(self):
            self.reg_nodes = np.empty(32, dtype=object)
            """CheriCapNode associated with each register"""
            self.memory_map = {}
            """CheriCapNodes stored in memory"""

        def __getitem__(self, idx):
            return self.reg_nodes[idx]

        def load(self, idx, node):
            """
            Associate a CheriCapNode to a register that
            contains the capability associated with it
            """
            self.reg_nodes[idx] = node

        def move(self, from_idx, to_idx):
            """
            When a capability is moved or modified without changing
            bounds the node is propagated to the destination register            
            """
            self.reg_nodes[to_idx] = self.reg_nodes[from_idx]

    class CapInstr:
        """
        Parse all arguments of a capability instructions
        """

        class Argument:

            def __init__(self, name, regset, reg_nodes, is_immediate):
                self.is_immediate = is_immediate
                """is the argument an immediate?"""
                self.name = name
                """matched argument string, e.g. c4 for the register $c4"""
                if self.cap_index != -1:
                    if (regset.valid_caps[self.cap_index] or
                        reg_nodes[self.cap_index] is not None):
                        self.value = regset.cap_reg[self.cap_index]
                    else:
                        logger.warning("Taking value of %s from "\
                                       "invalid cap register", name)
                        self.value = None
                elif self.reg_index != -1:
                    if regset.valid_gprs[self.reg_index]:
                        self.value = regset.gpr[self.reg_index]
                    else:
                        logger.warning("Taking value of %s from "\
                                       "invalid gpr register", name)
                        self.value = None
                else:
                    self.value = None

            @property
            def cap_index(self):
                if (self.is_immediate or self.name is None):
                    return -1
                if (self.name and str(self.name)[0] == "c"):
                    return int(self.name[1:])
                return -1

            @property
            def reg_index(self):
                if (self.is_immediate or self.name is None):
                    return -1
                # logger.debug("reg_index %s", self.name)
                strval = str(self.name)
                if self.name and strval[0] == "c":
                    return -1
                if self.name == "sp":
                    return 29
                if self.name == "fp":
                    return 30
                if strval[0] != "f":
                    # do not support floating point registers for now
                    return int(self.name)
                return -1
                

        def __init__(self, entry, regs, reg_nodes, inst):
            self.entry = entry
            self.inst = inst
            self.regs = regs

            match = re.match("^\s*([a-z]+)\s*(\$?)(c?[sfp0-9]{1,2})?\s*,?"\
                             "\s*(\$?)(c?[sfp0-9]{1,2})?\s*,?"\
                             "\s*(\$?)([0-9csfpx\$\(\)]+)?", inst.name)
            if match == None:
                logger.error("Malformed disassembly %s", inst.name)
                raise ValueError("Malformed disassembly %s", inst.name)
            self.opcode = match.group(1)
            self.cd = self.Argument(match.group(3), regs, reg_nodes,
                                    match.group(2) == "")
            self.cb = self.Argument(match.group(5), regs, reg_nodes,
                                    match.group(4) == "")
            self.rt = self.Argument(match.group(7), regs, reg_nodes,
                                    match.group(6) == "")

        @property
        def is_load(self):
            return self.entry.is_load

        @property
        def is_store(self):
            return self.entry.is_store

    
    def __init__(self, tree):
        self.tree = tree
        self.regset = self.RegisterSet()

    def make_root_node(self, idx, cap):
        node = CheriCapNode(cap)
        node.t_alloc = 0
        node.address = None
        self.tree.append(node)
        self.regset.load(idx, node)
        return node

    def scan_root_cap(self, regs):
        # initialize root capability registers
        logger.debug("Scan initial register set")
        for idx in range(0, 32):
            cap = regs.cap_reg[idx]
            valid = regs.valid_caps[idx]
            if valid:
                node = self.make_root_node(idx, cap)
                logger.debug("c%d %s", idx, node)
            else:
                logger.warning("c%d not in initial set", idx)
                if idx == 30:
                    node = self.make_root_node(idx, None)
                    node.base = 0
                    node.offset = 0
                    node.length = 0xffffffffffffffff
                    logger.warning("Guessing KDC %s", node)

    def make_node(self, entry, cap_inst, src, dst):
        node = CheriCapNode(dst)
        # need to work more on the address..
        # we need to catch csc mappings
        # entry.memory_address # XXX not quite the address I need here
        node.address = None
        node.t_alloc = entry.cycles
        node.pc = entry.pc
        node.is_kernel = entry.is_kernel()
        # find parent node, if no match then the tree is returned
        try:
            parent = self.regset[cap_inst.cb.cap_index]
            # parent = self.tree.find_node(src.base, src.length)
        except:
            logger.error("Error searching for parent node of %s", node)
            raise

        if parent == None:
            logger.error("Missing parent c%d [%x, %x]",
                         entry.capreg_number(), src.base, src.length)
            raise Exception("Missing parent for %s [%x, %x]" %
                            (node, src.base, src.length))
        parent.append(node)
        return node

    def parse_cap3_instr(self, entry, regs, last_regs, inst):
        """
        Generic parsing function for 3-operand capability instructions.
        This is used both for csetbounds and cfromptr.
        Returns the parsed node
        """
        if last_regs is None:
            last_regs = regs

        cap_inst_current = self.CapInstr(entry, regs, self.regset, inst)
        cap_inst_prev = self.CapInstr(entry, last_regs, self.regset, inst)
        # src is taken from the previous instruction's register set
        # because if the destination reg is the same as the source
        # the value has been overwritten at this point
        src_val = cap_inst_prev.cb.value
        dst_val = cap_inst_current.cd.value
        if src_val == None or dst_val == None:
            logger.error("Unexpected value src:%s, dst:%s, instr:%s", src_val, dst_val, inst.name)
            raise ValueError("Invalid parsed instruction register values.")

        node = self.make_node(entry, cap_inst_current, src_val, dst_val)
        self.regset.load(cap_inst_current.cd.cap_index, node)
        return node

    def update_regs(self, entry, regs, last_regs, disasm_inst):

        inst = self.CapInstr(entry, regs, self.regset, disasm_inst)
        cd = inst.cd.cap_index
        if cd == -1:
            return
        cb = inst.cb.cap_index
        if cb == -1:
            return
        self.regset.move(cb, cd)

    def csetbounds(self, entry, regs, last_regs, inst):
        node = self.parse_cap3_instr(entry, regs, last_regs, inst)
        node.origin = CheriCapNode.C_SETBOUNDS

    def cfromptr(self, entry, regs, last_regs, inst):
        node = self.parse_cap3_instr(entry, regs, last_regs, inst)
        node.origin = CheriCapNode.C_FROMPTR

    def csc(self, entry, regs, last_regs, instr):
        cd = entry.capreg_number()
        node = self.regset[cd]
        if node is None and not last_regs.valid_caps[cd]:
            # add a node as a root node because we have never
            # seen the content of this register yet
            cap_instr = self.CapInstr(entry, regs, self.regset, instr)
            logger.warning("Found %s value (missing in initial set)", cap_instr.cd.name)
            pass
        # node.address = entry.memory_address # node.address should really be a list

    def clc(self, entry, regs, last_regs, instr):
        # first look for clc c0, sth
        # or csetdefault
        # the load() in the registerset should be used but we
        # need to find a node for it.
        # the address map may be used to see if we stored something at
        # this location (NOT YET)
        cd = entry.capreg_number()
        node = self.regset[cd]
        if node is None and not last_regs.valid_caps[cd]:
            # add a node as a root node because we have never
            # seen the content of this register yet
            cap_instr = self.CapInstr(entry, regs, self.regset, instr)
            node = self.make_root_node(cd, cap_instr.cd.value)
            logger.warning("Found %s value (missing in initial set) %s",
                           cap_instr.cd.name, node)
            
