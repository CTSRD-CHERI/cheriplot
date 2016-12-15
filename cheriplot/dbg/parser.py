"""
This module defines parsers that are used to support debugging with
instruction traces.
"""

import logging

from collections import deque

from cheriplot.core.parser import CallbackTraceParser
from cheriplot.core.provenance import CheriCap

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

    def dump_cap(self, cap):
        chericap = CheriCap(cap)
        return str(chericap)

    def dump_regs(self, entry, regs, last_regs):

        for idx in range(0,31):
            real_regnum = idx + 1
            print("[%d] $%d = %x" % (
                regs.valid_gprs[idx],
                real_regnum,
                regs.gpr[idx]))
        for idx in range(0,32):
            print("[%d] $c%d = %s" % (regs.valid_caps[idx], idx,
                                      self.dump_cap(regs.cap_reg[idx])))


    def dump_instr(self, inst, entry, idx):
        if entry.exception != 31:
            exception = "except:%x" % entry.exception
        else:
            # no exception
            exception = ""
        print("{%d} 0x%x %s %s" % (entry.cycles, entry.pc, inst.inst.name,
              exception))


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
            print("$%s = %s" % (
                cap_name, self.dump_cap(cap_value)))


class TraceDumpParser(CallbackTraceParser, TraceDumpMixin):
    """
    Parser that performs basic lookup on a trace file
    """

    def __init__(self, dataset, trace_path, dump_registers=False,
                 match_opcode=None, match_pc=None, match_reg=None,
                 match_addr=None, match_exc=None, match_nop=None,
                 match_mode="and", before=0, after=0, **kwargs):
        """
        This parser filters the trace according to a set of match
        conditions. Multiple match conditions can be used at the same time
        to refine or widen the filter.

        :param dump_registers: dump register set after each instruction
        :type dump_registers: bool

        :param match_opcode: find occurrences of given instruction mnemonic
        :type match_opcode: str

        :param match_pc: find occurrences of given PC value
        :type match_pc: str

        :param match_reg: show all instructions that touch the given
        register (register name).
        :type match_reg: str

        :param match_addr: show all instructions that touch the given
        memory location.
        :type match_addr: int

        :param match_exc: show all instructions that cause the given
        exception.
        :type match_addr: int

        :param match_nop: match the given canonical NOP code
        :type match_addr: int

        :param match_mode: how multiple match args are combined, valid
        values are "and" and "or"
        :type match_mode: str

        :param before: dump N instructions before the matching one,
        default N=0
        :type before: int

        :param after: dump N instructions after the matching one,
        default N=0
        :type after: int
        """
        super(TraceDumpParser, self).__init__(dataset, trace_path, **kwargs)

        self.dump_registers = dump_registers
        """Enable register set dump."""

        self.find_instr = match_opcode
        """Find occurrences of this instruction."""

        self.pc = match_pc
        """Find occurrences of given PC."""

        self.follow_reg = match_reg
        """Find occurrences of given register."""

        self.follow_addr = match_addr
        """Find occurences of given memory location."""

        self.match_exc = match_exc
        """Find occurrences of given exception. The value 'any' is also valid."""

        self.match_nop = match_nop
        """Find occurrences of given canonical NOP."""

        self.match_mode = match_mode
        """How to compose multiple match conditions (and, or)."""

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

        self._nested_exceptions = 1
        """Number of nested exceptions. Start at 1 because"""

        if (match_pc is None and match_reg is None and
            match_addr is None and match_opcode is None and
            match_exc is None):
            # if no match condition is specified the match options
            # must have the default value
            self.before = 0
            self.after = 0
            self.match_mode = "and"

    def dump_kernel_user_switch(self, entry):
        if self._kernel_mode != entry.is_kernel():
            if entry.is_kernel():
                print("Enter kernel mode {%d}" % (entry.cycles))
            else:
                print("Enter user mode {%d}" % (entry.cycles))
            self._kernel_mode = entry.is_kernel()

    def do_dump(self, inst, entry, regs, last_regs, idx):
        # dump instr
        self.dump_instr(inst, entry, idx)
        if entry.exception != 31:
            print("Nested exceptions: %d" % self._nested_exceptions)
        if self.dump_registers:
            self.dump_regs(entry, regs, last_regs)

    def _update_match_result(self, match=None, value=None):
        """
        Combine the current match result with the value of
        a test according to the match mode, if value is None
        return the initial value for the match
        """
        if self.match_mode == "and":
            if value is None:
                match = True
            else:
                match = match and value
        else:
            if value is None:
                match = False
            else:
                match = match or value
        return match

    def _match_instr(self, inst, match):
        """Check if the current instruction matches"""
        if self.find_instr is None:
            return match
        test_result = self.find_instr == inst.opcode
        return self._update_match_result(match, test_result)

    def _match_pc(self, inst, match):
        """Check if the current instruction PC matches"""
        if self.pc is None:
            return match
        test_result = self.pc == inst.entry.pc
        return self._update_match_result(match, test_result)

    def _match_addr(self, inst, match):
        """Check if the current load or store address matches"""
        if self.follow_addr is None:
            return match
        if inst.entry.is_load or inst.entry.is_store:
            match_addr = self.follow_addr == inst.entry.memory_address
        else:
            match_addr = False
        return self._update_match_result(match, match_addr)

    def _match_reg(self, inst, match):
        """Check if the current instruction uses a register"""
        if self.follow_reg is None:
            return match
        match_reg = False
        for operand in inst.operands:
            if not operand.is_register:
                continue
            match_reg = operand.name == self.follow_reg
            if match_reg:
                break
        return self._update_match_result(match, match_reg)

    def _match_exception(self, inst, match):
        """Check if an exception occurred while executing an instruction"""
        if self.match_exc is None:
            return match
        match_exc = False
        if inst.entry.exception != 31:
            if self.match_exc == "any":
                match_exc = True
            else:
                match_exc = inst.entry.exception == int(self.match_exc)
        return self._update_match_result(match, match_exc)

    def _match_nop(self, inst, match):
        """Check if instruction is a given canonical NOP"""
        if self.match_nop is None:
            return match
        test_result = False
        if inst.opcode == "lui":
            test_result = (inst.op0.gpr_index == 0 and
                           inst.op1.value == self.match_nop)
        return self._update_match_result(match, test_result)

    def scan_all(self, inst, entry, regs, last_regs, idx):
        self.dump_kernel_user_switch(entry)
        if self._dump_next > 0:
            self._dump_next -= 1
            self.do_dump(inst, entry, regs, last_regs, idx)
        else:
            match = self._update_match_result()
            match = self._match_instr(inst, match)
            match = self._match_pc(inst, match)
            match = self._match_addr(inst, match)
            match = self._match_reg(inst, match)
            match = self._match_exception(inst, match)
            match = self._match_nop(inst, match)

            if entry.exception != 31 or inst.opcode == "syscall":
                self._nested_exceptions += 1
            if inst.opcode == "eret":
                self._nested_exceptions -= 1

            if match:
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
