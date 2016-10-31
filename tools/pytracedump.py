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
import argparse
import logging

from cheri_trace_parser.core.parser import CallbackTraceParser
from cheri_trace_parser.core.tool import Tool

logger = logging.getLogger(__name__)

class PyDumpParser(CallbackTraceParser):

    def __init__(self, find, *args):
        super(PyDumpParser, self).__init__(None, *args)
        self.dump_registers = False
        """Enable register set dump"""
        
        self.find_instr = find
        """Find occurrences of this instruction"""
        
        self.kernel_mode = False
        """Keep track of kernel-userspace transitions"""

    def repr_register(self, entry):
        if (entry.gpr_number() != -1):
            return "$%d" % entry.gpr_number()
        elif (entry.capreg_number() != -1):
            return "$c%d" % entry.capreg_number()

    def dump_regs(self, entry, regs, last_regs):
        if not self.dump_registers:
            return

        for idx in range(0,31):
            real_regnum = idx + 1
            print("[%d] $%d = %x" % (
                regs.valid_gprs[idx],
                real_regnum,
                regs.gpr[idx]))
        for idx in range(0,32):
            print("[%d] $c%d = b:%x o:%x l:%x" % (
                regs.valid_caps[idx],
                idx,
                regs.cap_reg[idx].base,
                regs.cap_reg[idx].offset,
                regs.cap_reg[idx].length))


    def dump_instr(self, inst, entry, idx):
        print("{%d} 0x%x" % (entry.cycles, entry.pc),
              inst.inst.name,
              "[ld:%d st:%d]" % (entry.is_load, entry.is_store))

        # dump read/write
        if inst.cd is None:
            # no operands for the instruction
            return

        if entry.is_load:
            print("$%s = [%x]" % (inst.cd.name, entry.memory_address))
        elif entry.is_store:
            print("[%x] = $%s" % (entry.memory_address, inst.cd.name))

        if (entry.gpr_number() != -1):
            if inst.implicit:
                gpr_value = inst.implicit.value
                gpr_name = inst.implicit.name
            else:
                gpr_value = inst.cd.value
                gpr_name = inst.cd.name
            print("$%s = %x" % (gpr_name, gpr_value))
        elif (entry.capreg_number() != -1):
            if inst.implicit:
                cap_name = inst.implicit.name
                cap_value = inst.implicit.value
            else:
                cap_name = inst.cd.name
                cap_value = inst.cd.value
            print("$%s = b:%x o:%x l:%x" % (
                cap_name, cap_value.base, cap_value.offset, cap_value.length))

    def scan_all(self, inst, entry, regs, last_regs, idx):
        if (self.find_instr is not None and
            self.find_instr != inst.opcode):
            return False
        
        if self.kernel_mode != entry.is_kernel():
            if entry.is_kernel():
                print("Enter kernel mode {%d}" % (entry.cycles))
            else:
                print("Enter user mode {%d}" % (entry.cycles))
            self.kernel_mode = entry.is_kernel()
        # dump instr
        self.dump_instr(inst, entry, idx)
        self.dump_regs(entry, regs, last_regs)
        return False

class PyTraceDump(Tool):
    """
    Pytracedump is similar to cheri-tracedump although
    it has some additional features.
    """
    
    description="Dump CHERI binary trace "\
                 "(python version of cheri-tracedump)."

    def init_arguments(self):
        super(PyTraceDump, self).init_arguments()
        self.parser.add_argument("-s", "--start", type=int, default=None,
                                 help="Start at given offset")
        self.parser.add_argument("-e", "--end", type=int, default=None,
                                 help="Stop at given offset")
        self.parser.add_argument("-i", "--info",
                                 help="Print trace info and exit",
                                 action="store_true")
        self.parser.add_argument("-r", "--regs", help="Dump register content",
                                 action="store_true")
        self.parser.add_argument("-f", "--find",
                                 help="Find instruction occurrences")

    def _run(self, args):
        pdp = PyDumpParser(args.find, args.trace)
        pdp.dump_registers = args.regs

        if (args.info):
            print("Trace size: %d" % len(pdp))
            exit()

        start = args.start if args.start is not None else 0
        end = args.end if args.end is not None else len(pdp)
        pdp.parse(start, end)
        
if __name__ == "__main__":
    tool = PyTraceDump()
    tool.run()
