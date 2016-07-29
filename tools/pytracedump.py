
import sys

from cheri_trace_parser.core.parser import TraceParser

import pycheritrace.pycheritrace as pct
import argparse

class PyDumpParser(TraceParser):

    def parse(self, start, end):

        context = {
            "dis": pct.disassembler(),
        }

        def _scan(ctx, entry, regs, idx):
            dis = ctx["dis"]                
            inst = dis.disassemble(entry.inst)

            # dump instr
            print(inst.name, "[l:%d s:%d]" % (entry.is_load, entry.is_store))
            # dump read/write
            print("$%d = [%x]" % (entry.register_number(),
                                  entry.memory_address))
            #dump regs
            if (entry.gpr_number() != -1):
                print("$%d = %x" % (entry.gpr_number(), entry.reg_value.gp))
            elif (entry.capreg_number() != -1):
                print("$c%d = b:%x o:%x l:%x" % (entry.capreg_number(),
                                                 entry.reg_value.cap.base,
                                                 entry.reg_value.cap.offset,
                                                 entry.reg_value.cap.length))
            for idx in range(0,31):
                print("[%d] $%d = %x" % (regs.valid_gprs[idx],
                                         idx,
                                         regs.gpr[idx]))
            for idx in range(0,31):
                print("[%d] $%d = b:%x o:%x l:%x" % (regs.valid_caps[idx],
                                                     idx,
                                                     regs.cap_reg[idx].base,
                                                     regs.cap_reg[idx].offset,
                                                     regs.cap_reg[idx].length))
            return False
        
        self.scan_detail(_scan, start, end, context=context)

if __name__ == "__main__":

    ap = argparse.ArgumentParser(description="Dump CHERI binary trace "\
                                 "(python version of cheri-tracedump).")
    ap.add_argument("trace", help="Path to trace file")
    ap.add_argument("-s", type=int, default=None, help="Start at given offset")
    ap.add_argument("-e", type=int, default=None, help="Stop at given offset")
    ap.add_argument("-i", help="Print trace info and exit", action="store_true")
    args = ap.parse_args()
    
    pdp = PyDumpParser(args.trace)
    if (args.i):
        print("Trace size: %d" % len(pdp))
        exit()
    start = args.s if args.s is not None else 0
    end = args.e if args.e is not None else len(pdp)
    pdp.parse(start, end)
