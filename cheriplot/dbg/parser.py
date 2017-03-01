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
        print("{%d:%d} 0x%x %s %s" % (entry.asid, entry.cycles, entry.pc,
                                      inst.inst.name, exception))


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
                 match_opcode=None, match_pc_start=None, match_pc_end=None,
                 match_reg=None, match_addr_start=None, match_addr_end=None,
                 match_exc=None, match_nop=None, match_syscall=None,
                 match_perm=None, match_mode="and", before=0, after=0, **kwargs):
        """
        This parser filters the trace according to a set of match
        conditions. Multiple match conditions can be used at the same time
        to refine or widen the filter.
        """
        super(TraceDumpParser, self).__init__(dataset, trace_path, **kwargs)

        self.dump_registers = dump_registers
        """Enable register set dump."""

        self.find_instr = match_opcode
        """Find occurrences of this instruction."""

        self.pc_start = match_pc_start
        """Find occurrences with pc higher than start."""

        self.pc_end = match_pc_end
        """Find occurrences with pc lower than end."""

        self.follow_reg = match_reg
        """Find occurrences of given register."""

        self.match_addr_start = match_addr_start
        """Find occurences of accesses beyond this memory location."""

        self.match_addr_end = match_addr_end
        """Find occurences of accesses before this memory location."""

        self.match_exc = match_exc
        """Find occurrences of given exception. The value 'any' is also valid."""

        self.match_nop = match_nop
        """Find occurrences of given canonical NOP."""

        self.match_syscall = match_syscall
        """Find occurrences of the given syscall"""

        self.match_perm = match_perm
        """
        Find occurrences of capabilities with (at least) the given permission
        """

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

        if (match_pc_start is None and match_pc_end and match_reg is None and
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
                print("Enter kernel mode {%d:%d}" % (entry.asid, entry.cycles))
            else:
                print("Enter user mode {%d:%d}" % (entry.asid, entry.cycles))
            self._kernel_mode = entry.is_kernel()

    def do_dump(self, inst, entry, regs, last_regs, idx):
        # dump instr
        self.dump_instr(inst, entry, idx)
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

    def _check_limits(self, start, end, value):
        result = True
        if start != None and start > value:
            result = False
        if end != None and end < value:
            result = False
        return result

    def _match_instr(self, inst, match):
        """Check if the current instruction matches"""
        if self.find_instr is None:
            return match
        test_result = self.find_instr == inst.opcode
        return self._update_match_result(match, test_result)

    def _match_pc(self, inst, match):
        """Check if the current instruction PC matches"""
        if self.pc_start is None and self.pc_end is None:
            return match
        test_result = True
        if self.pc_start is not None and self.pc_start > inst.entry.pc:
            test_result = False
        if self.pc_end is not None and self.pc_end < inst.entry.pc:
            test_result = False
        return self._update_match_result(match, test_result)

    def _match_addr(self, inst, match):
        """Check if the current load or store address matches"""
        if self.match_addr_start is None and self.match_addr_end is None:
            return match
        if inst.entry.is_load or inst.entry.is_store:
            match_addr = self._check_limits(self.match_addr_start,
                                            self.match_addr_end,
                                            inst.entry.memory_address)
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

    def _match_syscall(self, inst, regs, match):
        """Check if this instruction is a syscall with given code"""
        if self.match_syscall is None:
            return match
        match_syscall = False
        if inst.opcode == "syscall" and inst.entry.exception == 8:
            # system call code is in v0
            if regs.valid_caps[2] and regs.cap_reg[2] == self.match_syscall:
                match_syscall = True
        return self._update_match_result(match, match_syscall)

    def _match_perm(self, inst, match):
        """Check if this instruction uses capabilities with the given perms"""
        if self.match_perm is None:
            return match
        match_perm = False
        for operand in inst.operands:
            if not operand.is_capability:
                continue
            if operand.value is None:
                # the register in the register set is not valid
                continue
            cap_reg = CheriCap(operand.value)
            match_perm = cap_reg.has_perm(self.match_perm)
            if match_perm:
                break
        return self._update_match_result(match, match_perm)

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
        if self._dump_next > 0:
            self.dump_kernel_user_switch(entry)
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
            match = self._match_syscall(inst, regs, match)
            match = self._match_perm(inst, match)

            if match:
                self.dump_kernel_user_switch(entry)
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
