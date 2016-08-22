"""
Parse a cheri trace to a pointer provenance tree
"""

import sys
import os
import logging
import pycheritrace as pct

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

            if opcode == "csetbounds":
                try:
                    self.parser_context.csetbounds(entry, regs, self.last_regs, inst)
                except Exception as ex:
                    logger.error("Error parsing csetbounds: %s", ex)
                    return True
            elif (opcode == "cfromptr" and self.regs_valid):
                try:
                    self.parser_context.cfromptr(entry, regs, self.last_regs, inst)
                except Exception as ex:
                    logger.error("Error parsing cfromptr: %s", ex)
                    return True
            elif opcode == "csc":
                self.parser_context.csc(entry, regs, inst)
            elif opcode == "clc":
                self.parser_context.clc(entry, regs, inst)
            elif (opcode == "eret" and not self.regs_valid):
                if not self.regs_valid:
                    self.parser_context.scan_root_cap(regs)
                self.regs_valid = True

            self.last_regs = regs
            return False

        self.trace.scan(_scan, 0, len(self))
        self.progress.finish()

class ProvenanceParserContext(object):

    class RegisterSet(object):
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
            self.reg_nodes = np.array(32, dtype=object)
            """CheriCapNode associated with each register"""
            self.memory_map = None
            """CheriCapNodes stored in memory"""

        def __getitem__(self, idx):
            return self.reg_nodes[idx]

        def load(self, idx, node):
            self.reg_nodes[idx] = node

        def move(self, from_idx, to_idx):
            pass

    def __init__(self, tree):
        self.tree = tree
        self.regset = self.RegisterSet()

    def scan_root_cap(self, regs):
        # initialize root capability registers
        logger.debug("Scan initial register set")
        for idx in range(0, 32):
            cap = regs.cap_reg[idx]
            valid = regs.valid_caps[idx]
            if valid:
                node = CheriCapNode(cap)
                node.t_alloc = 0
                node.address = None
                self.tree.append(node)
                self.load(idx, node)
                logger.debug("c%d %s", idx, node)
            else:
                logger.warning("c%d not in initial set", idx)

    def get_args3(self, inst):
        try:
            args = inst.name.split("\t")[2]
            cd = args.split(",")[0].strip().strip("$")
            cb = args.split(",")[1].strip().strip("$")
            rt = args.split(",")[2].strip().strip("$")
        except IndexError:
            logger.error("Malformed disassembly %s", inst.name)
            raise
        return (cd, cb, rt)

    def get_reg_value(self, regset, regname):
        """
        Get register value
        """
        try:
            if regname[0] == "c":
                idx = int(regname[1:])
                if not regset.valid_caps[idx]:
                    logger.warning("Taking value of %s from "\
                                   "invalid cap register", regname)
                return regset.cap_reg[idx]
            else:
                idx = int(regname)
                if not regset.valid_gprs[idx]:
                    logger.warning("Taking value of %s from "\
                                   "invalid gpr register", regname)
                return regset.gpr[idx]
        except IndexError:
            logger.error("Register index out of bounds for %s", regname)
            raise

    def get_cap_index(self, regname):
        if regname[0] != "c":
            return -1
        return int(regname[1:])

    def make_node(self, entry, inst, src, dst):
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
            cd, cb, rt = self.get_args3(inst)
            idx = self.get_cap_index(cb)
            parent = self.regset[idx]
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

        cd, cb, rt = self.get_args3(inst)

        # src is taken from the previous instruction's register set
        # because if the destination reg is the same as the source
        # the value has been overwritten at this point
        src_val = self.get_reg_value(last_regs, cb)
        dst_val = self.get_reg_value(regs, cd)

        node = self.make_node(entry, inst, src_val, dst_val)
        return node

    def update_regs(self, entry, regs, last_regs, inst):

        pass

    def csetbounds(self, entry, regs, last_regs, inst):
        node = self.parse_cap3_instr(entry, regs, last_regs, inst)
        node.origin = CheriCapNode.C_SETBOUNDS

    def cfromptr(self, entry, regs, last_regs, inst):
        node = self.parse_cap3_instr(entry, regs, last_regs, inst)
        node.origin = CheriCapNode.C_FROMPTR

    def csc(self, entry, regs, instr):
        pass

    def clc(self, entry, regs, instr):
        # first look for clc c0, sth
        # or csetdefault
        pass
