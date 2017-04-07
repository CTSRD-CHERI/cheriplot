#-
# Copyright (c) 2016-2017 Alfredo Mazzinghi
# All rights reserved.
#
# This software was developed by SRI International and the University of
# Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
# ("CTSRD"), as part of the DARPA CRASH research programme.
#
# @BERI_LICENSE_HEADER_START@
#
# Licensed to BERI Open Systems C.I.C. (BERI) under one or more contributor
# license agreements.  See the NOTICE file distributed with this work for
# additional information regarding copyright ownership.  BERI licenses this
# file to you under the BERI Hardware-Software License, Version 1.0 (the
# "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at:
#
#   http://www.beri-open-systems.org/legal/license-1-0.txt
#
# Unless required by applicable law or agreed to in writing, Work distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations under the License.
#
# @BERI_LICENSE_HEADER_END@
#

import logging

from functools import reduce
from collections import deque
from cheriplot.provenance import CallbackTraceParser, CheriCap
from cheriplot.core import (
    BaseTraceTaskDriver, ConfigurableComponent, Option, NestedConfig,
    interactive_tool, option_range_validator, any_int_validator)

logger = logging.getLogger(__name__)

class TraceDumpParser(CallbackTraceParser, ConfigurableComponent):
    """Parser that performs filtering and search operations on a trace"""

    range_format_help = "Accept a range in the form <start>-<end>, -<end>, "\
                        "<start>- or <single_value>"

    start = Option("-s", type=int, default=0, help="Start offset in the trace")
    end = Option("-e", type=int, default=None, help="Stop offset in the trace")
    show_regs = Option("-r", action="store_true", help="Dump register content")
    # show_regs = Option("-r", help="Dump register content")
    instr = Option(default=None, help="Find instruction occurrences")
    reg = Option(
        default=None,
        help="Show the instructions that use the given register")
    pc = Option(
        type=option_range_validator,
        default=None,
        help="Find instructions with PC in given range. " + range_format_help)
    mem = Option(
        type=option_range_validator,
        default=None,
        help="Show the instructions that use the given memory address. " +
        range_format_help)
    exception = Option(
        default=None,
        help="Show the instructions that raise a given exception. "
        "Accept the exception number in [0-30] or 'any'.")
    syscall = Option(
        default=None,
        type=int,
        help="Show the syscalls with given code")
    nop = Option(
        type=any_int_validator,
        default=None,
        help="Show canonical nops with given code")
    perms = Option(
        type=any_int_validator,
        default=None,
        help="Find instructions that touch capabilities"
        " with the given permission bits set")
    after = Option(
        "-A",
        type=int,
        default=0,
        help="Dump n instructions after a matching one")
    before = Option(
        "-B",
        type=int,
        default=0,
        help="Dump n instructions before a matching one")
    match_any = Option(
        action="store_true",
        help="Return a trace entry when matches any of the conditions "
        "instead of all")

    def __init__(self, **kwargs):
        """
        This parser filters the trace according to a set of match
        conditions. Multiple match conditions can be used at the same time
        to refine or widen the filter.
        """
        super().__init__(**kwargs)

        self._entry_history = deque([], self.config.before)
        """FIFO instructions that may be shown if a match is found"""

        self._dump_next = 0
        """The remaining number of instructions to dump after a match"""

        self._kernel_mode = False
        """Keep track of kernel-userspace transitions"""

        self.filters = [
            self._match_instr,
            self._match_pc,
            self._match_addr,
            self._match_reg,
            self._match_exception,
            self._match_nop,
            self._match_syscall,
            self._match_perm
        ]

        self.update_config(self.config)

    def update_config(self, config):
        self._entry_history = deque([], config.before)
        self._dump_next = 0
        self._kernel_mode = False

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
        if self.config.show_regs:
            self.dump_regs(entry, regs, last_regs)

    def _update_match_result(self, match, value):
        """
        Combine the current match result with the value of
        a test according to the match mode
        """
        if value is None:
            return match
        if self.config.match_any:
            return match or value
        else:
            return match and value

    def _check_limits(self, start, end, value):
        result = True
        if start != None and start > value:
            result = False
        if end != None and end < value:
            result = False
        return result

    def _match_instr(self, inst, regs):
        """Check if the current instruction matches"""
        if self.config.instr:
            return self.config.instr == inst.opcode
        return None

    def _match_pc(self, inst, regs):
        """Check if the current instruction PC matches"""
        if self.config.pc:
            start, end = self.config.pc
            return self._check_limits(start, end, inst.entry.pc)
        return None

    def _match_addr(self, inst, regs):
        """Check if the current load or store address matches"""
        if self.config.mem:
            if inst.entry.is_load or inst.entry.is_store:
                start, end = self.config.mem
                return self._check_limits(start, end, inst.entry.memory_address)
            else:
                return False
        return None

    def _match_reg(self, inst, regs):
        """Check if the current instruction uses a register"""
        if self.config.reg:
            for operand in inst.operands:
                if not operand.is_register:
                    continue
                if operand.name == self.config.reg:
                    return True
            return False
        return None

    def _match_exception(self, inst, regs):
        """Check if an exception occurred while executing an instruction"""
        if self.config.exception:
            if inst.entry.exception == 31:
                # no exception
                return False
            elif self.config.exception == "any":
                return  True
            else:
                return inst.entry.exception == int(self.config.exception)
        return None

    def _match_syscall(self, inst, regs):
        """Check if this instruction is a syscall with given code"""
        # system call code is in v0
        code_reg = 2
        if self.config.syscall:
            if inst.opcode == "syscall" and inst.entry.exception == 8:
                if (regs.valid_grps[code_reg] and
                    regs.gpr[code_reg] == self.config.syscall):
                    return True
            return False
        return None

    def _match_perm(self, inst, regs):
        """Check if this instruction uses capabilities with the given perms"""
        if self.config.perms:
            for operand in inst.operands:
                if (not operand.is_capability or
                    operand.value is None):
                    # if not a capability or the register in the register set
                    # is not valid
                    continue
                cap_reg = CheriCap(operand.value)
                if cap_reg.has_perm(self.config.perms):
                    return True
            return False
        return None

    def _match_nop(self, inst, regs):
        """Check if instruction is a given canonical NOP"""
        if self.config.nop:
            if inst.opcode == "lui":
                return (inst.op0.gpr_index == 0 and
                        inst.op1.value == self.config.nop)
            return False
        return None

    def scan_all(self, inst, entry, regs, last_regs, idx):
        if self._dump_next > 0:
            self.dump_kernel_user_switch(entry)
            self._dump_next -= 1
            self.do_dump(inst, entry, regs, last_regs, idx)
        else:
            # initial match value, if match_any is true
            # we OR the match results so start with false
            # else we AND them, so start with true
            match = not self.config.match_any
            for checker in self.filters:
                result = checker(inst, regs)
                match = self._update_match_result(match, result)
            if match:
                self.dump_kernel_user_switch(entry)
                # dump all the instructions in the queue
                while len(self._entry_history) > 0:
                    old_inst, idx = self._entry_history.popleft()
                    self.do_dump(old_inst, old_inst.entry, old_inst._regset,
                                 old_inst._prev_regset, idx)
                self.do_dump(inst, entry, regs, last_regs, idx)
                self._dump_next = self.config.after
            else:
                self._entry_history.append((inst, idx))
        return False

    def parse(self, start=None, end=None, direction=0):
        super().parse(self.config.start, self.config.end)


@interactive_tool(key="scan")
class PytracedumpDriver(BaseTraceTaskDriver):

    description = """Dump CHERI binary trace.
    Each instruction entry has the following format:
    {<ASID>:<instruction_cycle_number>} <PC> <instr_mnemonic> <operands>

    Memory accesses show the referenced address in the line below:
    <target_register> = [<hex_addr>] or [<hex_addr>] = <source_register>

    Capabilities as displayed in the following format:
    [b:<base> o:<offset> l:<length> p:<permission> t:<obj_type> v:<valid> s:<sealed>]
    t_alloc and t_free are only relevant in the provenance graph.

    When dumping the register set, the format of each entry is the following:
    [<register_value_valid>] <register> = <value>"""

    scan = NestedConfig(TraceDumpParser)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.parser = TraceDumpParser(trace_path=self.config.trace,
                                      config=self.config.scan)

    def update_config(self, config):
        super().update_config(config)
        self.parser.update_config(config.scan)

    def run(self):
        self.parser.parse()
