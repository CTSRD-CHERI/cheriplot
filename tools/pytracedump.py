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


Python version of cheritrace tracedump tool
"""

import sys

from cheri_trace_parser.core.parser import TraceParser

import pycheritrace as pct
import argparse

class PyDumpParser(TraceParser):

    def __init__(self, find, *args):
        super(PyDumpParser, self).__init__(*args)
        self.dump_registers = False
        self.find_instr = find
        self.dis = pct.disassembler()
        self.kernel_mode = False

    def enable_regdump(self, enable):
        self.dump_registers = enable

    def repr_register(self, entry):
        if (entry.gpr_number() != -1):
            return "$%d" % entry.gpr_number()
        elif (entry.capreg_number() != -1):
            return "$c%d" % entry.capreg_number()

    def dump_regs(self, entry, regs):
        if not self.dump_registers:
            return

        for idx in range(0,31):
            print("[%d] $%d = %x" %
                  (regs.valid_gprs[idx],
                   idx,
                   regs.gpr[idx]))
        for idx in range(0,32):
            print("[%d] $c%d = b:%x o:%x l:%x" %
                  (regs.valid_caps[idx],
                   idx,
                   regs.cap_reg[idx].base,
                   regs.cap_reg[idx].offset,
                   regs.cap_reg[idx].length))

    def dump_instr(self, entry, regs, idx):
        inst = self.dis.disassemble(entry.inst)

        print("{%d} 0x%x" % (entry.cycles, entry.pc),
              inst.name,
              "[ld:%d st:%d]" % (entry.is_load, entry.is_store))

        # dump read/write
        reg_str = self.repr_register(entry)
        if entry.is_load:
            print("%s = [%x]" % (reg_str, entry.memory_address))
        elif entry.is_store:
            print("[%x] = %s" % (entry.memory_address, reg_str))

        if (entry.gpr_number() != -1):
            print("$%d = %x" % (entry.gpr_number(), entry.reg_value_gp()))
        elif (entry.capreg_number() != -1):
            cap = entry.reg_value_cap()
            print("$c%d = b:%x o:%x l:%x" %
                  (entry.capreg_number(), cap.base,
                   cap.offset, cap.length))

    def parse(self, start, end):

        def _scan(entry, regs, idx):
            inst = self.dis.disassemble(entry.inst)
            if (self.find_instr is not None and
                self.find_instr != inst.name.strip().split("\t")[0]):
                return False

            if self.kernel_mode != entry.is_kernel():
                if entry.is_kernel():
                    print("Enter kernel mode {%d}" % (entry.cycles))
                else:
                    print("Enter user mode {%d}" % (entry.cycles))
                self.kernel_mode = entry.is_kernel()

            # dump instr
            self.dump_instr(entry, regs, idx)
            self.dump_regs(entry, regs)
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
