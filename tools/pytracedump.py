
import sys

from cheri_trace_parser.core.parser import TraceParser

import pycheritrace as pct
import argparse

class PyDumpParser(TraceParser):

    def __init__(self, find, *args):
        super(PyDumpParser, self).__init__(*args)
        self.dump_registers = False
        self.find_instr = find

    def enable_regdump(self, enable):
        self.dump_registers = enable

    def parse(self, start, end):

        ctx = {
            "dis": pct.disassembler(),
            "kernel_mode": False,
            "find": self.find_instr,
        }

        def _scan(entry, regs, idx):
            dis = ctx["dis"]
            inst = dis.disassemble(entry.inst)
            if (ctx["find"] is not None and
                ctx["find"] != inst.name.strip().split("\t")[0]):
                return False
            
            if ctx["kernel_mode"] != entry.is_kernel():
                if entry.is_kernel():
                    print("Enter kernel mode {%d}" % (entry.cycles))
                else:
                    print("Enter user mode {%d}" % (entry.cycles))
                ctx["kernel_mode"] = entry.is_kernel()
            
            # dump instr
            print("{%d} 0x%x" % (entry.cycles, entry.pc),
                  inst.name,
                  "[l:%d s:%d]" % (entry.is_load, entry.is_store))
            # dump read/write
            print("$%d = [%x]" % (entry.register_number(),
                                  entry.memory_address))
            if self.dump_registers:
                #dump regs
                if (entry.gpr_number() != -1):
                    print("$%d = %x" % (entry.gpr_number(), entry.reg_value.gp))
                elif (entry.capreg_number() != -1):
                    print("$c%d = b:%x o:%x l:%x" %
                          (entry.capreg_number(),
                           entry.reg_value.cap.base,
                           entry.reg_value.cap.offset,
                           entry.reg_value.cap.length))
                for idx in range(0,31):
                    print("[%d] $%d = %x" %
                          (regs.valid_gprs[idx],
                           idx,
                           regs.gpr[idx]))
                for idx in range(0,32):
                    print("[%d] $%d = b:%x o:%x l:%x" %
                          (regs.valid_caps[idx],
                           idx,
                           regs.cap_reg[idx].base,
                           regs.cap_reg[idx].offset,
                           regs.cap_reg[idx].length))
            return False
        
        self.trace.scan(_scan, start, end)

if __name__ == "__main__":

    ap = argparse.ArgumentParser(description="Dump CHERI binary trace "\
                                 "(python version of cheri-tracedump).")
    ap.add_argument("trace", help="Path to trace file")
    ap.add_argument("-s", "--start", type=int, default=None,
                    help="Start at given offset")
    ap.add_argument("-e", "--end", type=int, default=None,
                    help="Stop at given offset")
    ap.add_argument("-i", "--info", help="Print trace info and exit",
                    action="store_true")
    ap.add_argument("-r", "--regs", help="Dump register content",
                    action="store_true")
    ap.add_argument("-f", "--find", help="Find instruction occurrences")
    args = ap.parse_args()

    pdp = PyDumpParser(args.find, args.trace)

    pdp.enable_regdump(args.regs)
    if (args.info):
        print("Trace size: %d" % len(pdp))
        exit()
    start = args.start if args.start is not None else 0
    end = args.end if args.end is not None else len(pdp)
    pdp.parse(start, end)
