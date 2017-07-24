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

import pycheritrace as pct

logger = logging.getLogger(__name__)

class MockTraceWriter:
    """Helper to write mock traces for testing."""

    def __init__(self, outfile):
        fd = open(outfile, "wb")
        fd.truncate(0)
        fd.close()

        self.writer = pct.trace_writer.open(outfile)
        self.asm = pct.assembler()
        self.pc = 0x1000
        self.cycles = 0

    def get_next_entry(self):
        entry = pct.debug_trace_entry()
        entry.cycles = self.cycles
        entry.pc = self.pc
        entry.is_store = False
        entry.is_load = False
        entry.exception = 31 # no exception
        entry.asid = 0
        entry.hwthread = 0
        self.cycles += 1
        self.pc += 4
        return entry

    def _process_entry(self, instr, side_effects):
        entry = self.get_next_entry()
        entry.inst = self.asm.assemble(instr)
        self._process_side_effects(entry, side_effects)
        return entry

    def _process_side_effects(self, entry, side_effects):
        for key,val in side_effects.items():
            self._side_effect(entry, key, val)

    def _side_effect(self, entry, key, val):
        if key == "load":
            entry.is_load = True
        elif key == "store":
            entry.is_store = True
        elif key == "mem":
            entry.memory_address = val
        elif key == "exc":
            entry.exception = val
        else:
            # GP or capability register
            entry.reg_value_set(val)
            if key[0] == "c":
                reg_num = int(key[1:]) + 64
            elif key[0] == "f":
                reg_num = int(key[1:]) + 32
            else:
                reg_num = int(key)
            entry.reg_num = reg_num

    def write_trace(self, trace_data, pc=None, cycle=None):
        """
        Write entries given a list of (instruction, side_effects).
        The initial pc and cycles can be set.
        """
        self.pc = pc if pc != None else self.pc
        self.cycles = cycle if cycle != None else self.cycles
        for instr, side_effects in trace_data:
            entry = self._process_entry(instr, side_effects)
            if entry:
                self.writer.append(entry)


def pct_cap(base, off, leng, perm, otype=0, seal=False, valid=True):
    """
    Shortcut constructor for a pycheritrace capability_register.
    """
    c = pct.capability_register()
    c.base = base
    c.offset = off
    c.length = leng
    c.type = otype
    c.permissions = perm
    c.valid = valid
    c.unsealed = seal # XXX fix this in cheritrace as it is very confusing
    return c
