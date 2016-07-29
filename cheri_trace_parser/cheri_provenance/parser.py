"""
Parse a cheri trace to a pointer provenance tree
"""

from cheri_trace_parser.core.parser import TraceParser
from .cheri_provenance import CheriCapNode

import sys
import pycheritrace.pycheritrace as pct

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

            # it would be useful if the first register set contained the full
            # snapshot of the initial registers, we are missing stuff otherwise
            # in particular the root capability set
            # if idx == 0:
            #     parser_ctx.scan_root_cap(regs)
            
            if opcode == "csetbounds":
                try:
                    parser_ctx.csetbounds(entry, regs, ctx["last_regs"], inst)
                except Exception as ex:
                    print("[csetbounds] Error", ex)
                    return True
            elif opcode == "cfromptr":
                parser_ctx.cfromptr(entry, regs, ctx["last_regs"], inst)
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

    def csetbounds(self, entry, regs, last_regs, inst):

        if last_regs is None:
            last_regs = regs
        try:
            args = inst.name.split("\t")[2]
            cd = args.split(",")[0].strip().strip("$")
            cb = args.split(",")[1].strip().strip("$")
            rt = args.split(",")[2].strip().strip("$")
        except IndexError:
            print("[csetbounds] Malformed disassebly", inst.name)
            raise

        try:
            dst_reg = inst.destination_register
            # XXX do we need to -1 because $zero is not stored?
            # destination_register seems not to be doing it
            src_reg = int(cb[1:]) + 64
            bound_reg = int(rt)
        except:
            print("[csetbounds] Error computing register indexes")
            raise

        try:
            # src is taken from the previous instruction's register set
            # because if the destination reg is the same as the source
            # the value has been overwritten at this point
            if not last_regs.valid_caps[src_reg - 64]:
                print("[csetbounds] src from invalid cap %d" % src_reg)
            src_val = last_regs.cap_reg[src_reg - 64]
            if not regs.valid_gprs[bound_reg]:
                print("[csetbounds] bound from invalid rt %d" % bound_reg)
            bound_val = regs.gpr[bound_reg]
            if not regs.valid_caps[dst_reg - 64]:
                print("[csetbounds] dst from invalid rt %d" % bound_reg)
            dst_val = regs.cap_reg[dst_reg - 64]
        except IndexError:
            print("[csetbounds] Malformed register index: "\
                  "src(%d) bound(%d) val(%d)" % (src_reg - 64,
                                                 bound_reg - 64,
                                                 dst_reg - 64))
            raise
        
        node = CheriCapNode(dst_val)
        # need to work more on the address.. we need to catch csc
        node.address = None # entry.memory_address # XXX not quite the address I need here
        node.t_alloc = entry.cycles
        node.origin = "csetbounds"
        # find parent node, if no match then the tree is returned
        try:
            parent = self.tree.find_node(src_val.base, src_val.length)
        except:
            print("[csetbounds] Error in find_node")
            raise
        
        if parent == None:
            # append source node first
            srcnode = CheriCapNode(src_val)
            srcnode.addr = 0
            srcnode.origin = "inferred"
            srcnode.t_alloc = -2 # unknown
            self.tree.append(srcnode)
            parent = srcnode

        try:
            parent.append(node)
        except:
            print("[csetbounds] Error appending node")
            raise

    def cfromptr(self, entry, regs, last_regs, instr):
        pass

    def csc(self, entry, regs, instr):
        pass

    def clc(self, entry, regs, instr):
        pass
