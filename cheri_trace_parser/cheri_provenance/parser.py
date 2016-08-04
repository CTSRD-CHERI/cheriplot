"""
Parse a cheri trace to a pointer provenance tree
"""

import sys
import logging
import pycheritrace.pycheritrace as pct

from cheri_trace_parser.core.parser import TraceParser
from .cheri_provenance import CheriCapNode

logger = logging.getLogger(__name__)

class PointerProvenanceParser(TraceParser):

    VERBOSE = True

    def parse(self, tree, start=None, end=None):

        context = {
            "ctx": ProvenanceParserContext(tree),
            "dis": pct.disassembler(),
            "last_regs": None,
            "totalsize": len(self),
            "current": 0,
            "progress": 0,
        }

        def _scan(ctx, entry, regs, idx):
            parser_ctx = ctx["ctx"]
            dis = ctx["dis"]
            
            if PointerProvenanceParser.VERBOSE:
                ctx["current"] += 1
                progress = int(ctx["current"] * 100 / ctx["totalsize"])
                if (progress != ctx["progress"]):
                    ctx["progress"] = progress
                    sys.stdout.write("\rScanning trace [%d%%]" % progress)
                    sys.stdout.flush()

            inst = dis.disassemble(entry.inst)
            parts = inst.name.split("\t")
            opcode = parts[1]

            # XXX it would be useful if the first register set contained the full
            # snapshot of the initial registers, we are missing stuff otherwise
            # in particular the root capability set
            # if idx == 0:
            #     parser_ctx.scan_root_cap(regs)
            
            if opcode == "csetbounds":
                try:
                    parser_ctx.csetbounds(entry, regs, ctx["last_regs"], inst)
                except Exception as ex:
                    logger.error("Error parsing csetbounds: %s" % ex)
                    return True
            elif opcode == "cfromptr":
                try:
                    parser_ctx.cfromptr(entry, regs, ctx["last_regs"], inst)
                except Exception as ex:
                    logger.error("Error parsing cfromptr: %s" % ex)
                    return True
            elif opcode == "csc":
                parser_ctx.csc(entry, regs, inst)
            elif opcode == "clc":
                parser_ctx.clc(entry, regs, inst)
            ctx["last_regs"] = regs
            return False
        
        self.scan_detail(_scan, context=context)
        
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

        XXX: before this experiment with just base and bound matching
        """
        pass

    def __init__(self, tree):
        self.tree = tree

    def scan_root_cap(self, regs):
        # initialize root capability registers
        for cap,idx in enumerate(regs.cap_reg):
            if regs.valid_caps[idx] and cap.valid:
                node = CheriCapNode()
                node.t_alloc = 0
                node.addr = None
                node.base = cap.base
                node.offset = cap.offset
                node.length = cap.length
                self.tree.append(node)

    def get_args3(self, inst):
        try:
            args = inst.name.split("\t")[2]
            cd = args.split(",")[0].strip().strip("$")
            cb = args.split(",")[1].strip().strip("$")
            rt = args.split(",")[2].strip().strip("$")
        except IndexError:
            logger.error("Malformed disassembly %s" % inst.name)
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
                                   "invalid cap register" % regname)
                return regset.cap_reg[idx]
            else:
                idx = int(regname)
                if not regset.valid_gprs[idx]:
                    logger.warning("Taking value of %s from "\
                                   "invalid gpr register" % regname)
                return regset.gpr[idx]
        except IndexError:
            logger.error("Register index out of bounds for %s" % regname)
            raise

    def make_node(self, entry, src, dst):
        node = CheriCapNode(dst)
        # need to work more on the address..
        # we need to catch csc mappings
        # entry.memory_address # XXX not quite the address I need here
        node.address = None
        node.t_alloc = entry.cycles
        # find parent node, if no match then the tree is returned
        try:
            parent = self.tree.find_node(src.base, src.length)
        except:
            logger.error("Error searching for parent node of %s" % node)
            raise
        
        if parent == None:
            # append source node first
            srcnode = CheriCapNode(src)
            srcnode.addr = 0
            srcnode.origin = "inferred"
            srcnode.t_alloc = -2 # unknown
            self.tree.append(srcnode)
            parent = srcnode
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

        node = self.make_node(entry, src_val, dst_val)
        return node

    def csetbounds(self, entry, regs, last_regs, inst):
        node = self.parse_cap3_instr(entry, regs, last_regs, inst)
        node.origin = "csetbounds"

    def cfromptr(self, entry, regs, last_regs, inst):
        return
        node = self.parse_cap3_instr(entry, regs, last_regs, inst)
        node.origin = "cfromptr"

    def csc(self, entry, regs, instr):
        pass

    def clc(self, entry, regs, instr):
        pass
