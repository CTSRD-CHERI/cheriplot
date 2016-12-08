"""
This module defines parsers that are used to support debugging with
instruction traces.
"""

import logging

from collections import deque

from cheriplot.core.parser import CallbackTraceParser

logger = logging.getLogger(__name__)

class TraceDumpMixin:
    """
    Mixin providing convenience functions to dump parsed instructions
    from a trace.
    """

    def __init__(self, *args, raw=False, **kwargs):
        """
        :param raw: (kwarg) enable printing of the raw instruction hex.
        :type raw: bool
        """
        super(TraceDumpMixin, self).__init__(*args, **kwargs)
        self.raw = raw
        """Show raw instruction dump"""

    def repr_register(self, entry):
        if (entry.gpr_number() != -1):
            return "$%d" % entry.gpr_number()
        elif (entry.capreg_number() != -1):
            return "$c%d" % entry.capreg_number()

    def dump_regs(self, entry, regs, last_regs):

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

        if self.raw:
            print("raw: 0x%x", entry.inst)
        # dump read/write
        if inst.cd is None:
            # no operands for the instruction
            return

        if entry.is_load:
            print("$%s = [%x]" % (inst.cd.name, entry.memory_address))
        elif entry.is_store:
            print("[%x] = $%s" % (entry.memory_address, inst.cd.name))

        if (entry.gpr_number() != -1):
            gpr_value = inst.cd.value
            gpr_name = inst.cd.name
            print("$%s = %x" % (gpr_name, gpr_value))
        elif (entry.capreg_number() != -1):
            cap_name = inst.cd.name
            cap_value = inst.cd.value
            print("$%s = b:%x o:%x l:%x" % (
                cap_name, cap_value.base, cap_value.offset, cap_value.length))


class TraceDumpParser(CallbackTraceParser, TraceDumpMixin):
    """
    Parser that performs basic lookup on a trace file
    """

    def __init__(self, dataset, trace_path, dump_registers=False, find=None,
                 pc=None, follow=None, before=0, after=0, **kwargs):
        """
        :param dump_registers: dump register set after each instruction
        :type dump_registers: bool
        :param find: find occurrences of given instruction mnemonic
        :type find: str
        :param pc: find occurrences of given PC value
        :type pc: str
        :param follow: show all instructions that touch the given
        register (register name).
        :type follow: int or str
        :param before: dump N instructions before the matching one,
        default N=0
        :type before: int
        :param after: dump N instructions after the matching one,
        default N=0
        """
        super(TraceDumpParser, self).__init__(dataset, trace_path, **kwargs)

        self.dump_registers = dump_registers
        """Enable register set dump."""

        self.find_instr = find
        """Find occurrences of this instruction."""

        self.pc = pc
        """Find occurrences of given PC."""

        self.follow_reg = follow
        """Find occurrences of given register."""

        self.show_before = before
        """Number of instructions to dump before the matching one."""

        self.show_after = after
        """Number of instructions to dump after the matching one."""

        self._entry_history = deque([], self.show_before)
        """FIFO instructions that may be shown if a match is found"""

        self._dump_next = 0
        """The remaining number of instructions to dump after a match"""

        self._kernel_mode = False
        """Keep track of kernel-userspace transitions"""

        if before != 0 or after != 0:
            assert (pc is not None or
                    follow is not None or
                    find is not None), "after and before can only be "\
                    "specified with matching rules"

    def do_dump(self, inst, entry, regs, last_regs, idx):
        if self._kernel_mode != entry.is_kernel():
            if entry.is_kernel():
                print("Enter kernel mode {%d}" % (entry.cycles))
            else:
                print("Enter user mode {%d}" % (entry.cycles))
            self._kernel_mode = entry.is_kernel()
        # dump instr
        self.dump_instr(inst, entry, idx)
        if self.dump_registers:
            self.dump_regs(entry, regs, last_regs)

    def scan_all(self, inst, entry, regs, last_regs, idx):
        if self._dump_next > 0:
            self._dump_next -= 1
            self.do_dump(inst, entry, regs, last_regs, idx)
        else:
            match_opc = True
            match_pc = True
            match_reg = True

            if self.find_instr is not None:
                match_opc = self.find_instr == inst.opcode
            if self.pc is not None:
                match_pc = self.pc == entry.pc
            if self.follow_reg is not None:
                match_reg = False
                for operand in inst.operands:
                    if not operand.is_register:
                        continue
                    match_reg = operand.name == self.follow_reg
                    if match_reg:
                        break
            if match_opc and match_pc and match_reg:
                # dump all the instructions in the queue
                while len(self._entry_history) > 0:
                    old_inst, idx = self._entry_history.popleft()
                    self.do_dump(old_inst, old_inst.entry, old_inst._regset,
                                 old_inst._prev_regset, idx)
                self.do_dump(inst, entry, regs, last_regs, idx)
                self._dump_next = self.show_after
            else:
                self._entry_history.append((inst, idx))
        return False
