#-
# Copyright (c) 2017 Alfredo Mazzinghi
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
import re
import struct
import ctypes
import enum

from cheriplot.utils import ProgressPrinter
from cheriplot.core.parser import CallbackTraceParser
from cheriplot.core.provenance import CheriCap

logger = logging.getLogger(__name__)

class State(enum.IntEnum):
    S_SKIP = 0
    S_INSTR = 1
    S_REG = 2
    S_MEM = 3
    S_CAP_MEM = 5
    S_INSTR_END = 6


class TxtTraceCmpParser(CallbackTraceParser):
    """
    Compare a text trace with a binary trace and
    report any difference.
    """

    def __init__(self, txt_trace, *args, pc_only=False, **kwargs):
        super().__init__(*args, **kwargs)

        self.pc_only = pc_only

        self.progress = ProgressPrinter(len(self), "Scan traces")

        # txt trace perser state machine
        self.txt_parse_state = State.S_INSTR
        self.txt_trace = open(txt_trace, "r")
        # skip lines from the txt trace until the first
        # instruction
        self._skiplines(inst_only=True)
        self.txt_parse_state = State.S_INSTR
        # while True:
        #     saved_pos = self.txt_trace.tell()
        #     line = self.txt_trace.readline()
        #     if re.match("[0-9xa-f]+:", line):
        #         self.txt_trace.seek(saved_pos)
        #         break

    def _skiplines(self, inst_only=False):
        """Skip lines that are not used"""

        while True:
            saved_pos = self.txt_trace.tell()
            line = self.txt_trace.readline()
            # test all the pattern that should not be skipped
            if inst_only == False:
                if re.search("Cap Memory Read", line) is not None:
                    self.txt_parse_state = State.S_CAP_MEM
                    break
                if re.search("Cap Memory Write", line) is not None:
                    self.txt_parse_state = State.S_CAP_MEM
                    break
                if re.search("Memory Read", line) is not None:
                    self.txt_parse_state = State.S_MEM
                    break
                if re.search("Memory Write", line) is not None:
                    self.txt_parse_state = State.S_MEM
                    break
                if re.search("Write [C\$]?[a-z0-9]+", line) is not None:
                    self.txt_parse_state = State.S_REG
                    break
            if re.match("[0-9xa-f]+:", line) is not None:
                # the next call to the parser function will
                # continue from here
                self.txt_parse_state = State.S_INSTR_END
                break
        self.txt_trace.seek(saved_pos)

    def _txt_instr(self, inst):
        line = self.txt_trace.readline()
        # line matches "[0-9xa-f]+:"
        # parse addr
        addr,rest = line.split(':')
        _,addr = addr.split("x")
        intaddr = struct.unpack(">Q", bytes.fromhex(addr))[0]
        inst["pc"] = intaddr
        rest = re.sub("[ \t]+", " ", rest.strip())
        opcode = rest.split(" ")[0]
        inst["opcode"] = opcode
        if len(rest.split(" ")) > 1:
            operands = rest.split(" ")[1]
            op0 = operands.split(",")[0]
        else:
            op0 = None

        # if we find a li zero, <something> is a canonical nop so
        # we need to skip until the next instruction is found
        if inst["opcode"] == "li" and op0 == "zero":
            self._skiplines(inst_only=True)
        else:
            # seek to next valid line and change state
            self._skiplines()

    def _txt_reg(self, inst):
        line = self.txt_trace.readline()
        m = re.search("Write \$?([a-z0-9]+) = ([a-f0-9]+)", line)
        if m:
            # write to gpr format
            # Write t4 = 0000000000008400
            reg = m.group(1)
            val = m.group(2)
            intval = struct.unpack(">Q", bytes.fromhex(val))[0]
            inst["reg"] = reg
            inst["data"] = intval
        else:
            # write to cap register format
            # Write C24|v:1 s:0 p:7fff807d b:0000007fffffdb20 l:0000000000000400
            # |o:0000000000000000 t:0
            m = re.search("Write C([0-9]+)\|v:([01]) s:([01]) p:([a-f0-9]+) "
                          "b:([a-f0-9]+) l:([a-f0-9]+)", line)
            if m is None:
                raise RuntimeError("Malformed cap reg write")
            # first line of a capability match
            # next line must match this
            line = self.txt_trace.readline()
            nxt = re.search("\|o:([a-f0-9]+) t:([a-f0-9]+)", line)
            if nxt is None:
                raise RuntimeError("Malformed cap reg write")
            v = m.group(2)
            s = m.group(3)
            p = m.group(4)
            b = m.group(5)
            l = m.group(6)
            o = nxt.group(1)
            t = nxt.group(2)
            try:
                if len(t) % 2:
                    # hotfix fromhex() that do not like odd num of digits
                    t = "0" + t
                t = bytes.fromhex(t)
                if len(t) < 4:
                    for i in range(4 - len(t)):
                        t = bytes.fromhex("00") + t
            except Exception:
                logger.error("Can not load type field %s %s", m.groups(), nxt.groups())
                raise
            # take only 16bit for permissions, the upper 16bit
            # are stored in the trace but ignored by cheritrace
            # as we do not care about uperms apparently.
            intp = struct.unpack(">L", bytes.fromhex(p))[0] & 0xffff
            intb = struct.unpack(">Q", bytes.fromhex(b))[0]
            intl = struct.unpack(">Q", bytes.fromhex(l))[0]
            into = struct.unpack(">Q", bytes.fromhex(o))[0]
            intt = struct.unpack(">L", t)[0] & 0x00ffffff
            inst["cap"] = {
                "valid": int(v),
                "sealed": int(s),
                "perms": intp,
                "base": intb,
                "length": intl,
                "offset": into,
                "otype": intt,
            }
        # seek to next valid line and change state
        self._skiplines()

    def _txt_mem(self, inst):
        line = self.txt_trace.readline()
        m = re.search("(Cap )?Memory Read +\[([0-9a-f]+)\]", line)
        if m:
            # data load
            is_cap = m.group(1)
            addr = m.group(2)
            intaddr = struct.unpack(">Q", bytes.fromhex(addr))[0]
            inst["load"] = intaddr
            if is_cap:
                # skip another line
                self.txt_trace.readline()
        else:
            m = re.search("(Cap )?Memory Write +\[([0-9a-f]+)\]", line) 
            if m is None:
                raise RuntimeError("Mem not a read nor a write")
            #data store
            is_cap = m.group(1)
            addr = m.group(2)
            intaddr = struct.unpack(">Q", bytes.fromhex(addr))[0]
            inst["store"] = intaddr
            if is_cap:
                # skip another line
                self.txt_trace.readline()
        # seek to next valid line and change state
        self._skiplines()

            
    def _next_txt_instr(self):
        """
        Fetch the next instruction from the txt trace.
        This is the state machine main loop.
        """
        instr = {}

        while self.txt_parse_state != State.S_INSTR_END:
            if self.txt_parse_state == State.S_SKIP:
                self._skiplines()
            elif self.txt_parse_state == State.S_INSTR:
                self._txt_instr(instr)
            elif self.txt_parse_state == State.S_REG:
                self._txt_reg(instr)
            elif self.txt_parse_state == State.S_MEM:
                self._txt_mem(instr)
            elif self.txt_parse_state == State.S_CAP_MEM:
                self._txt_mem(instr)
        # next call starts always from an instruction
        self.txt_parse_state = State.S_INSTR
        return instr

    def _dump_txt_inst(self, txt_inst):
        string = "pc:0x%x %s" % (txt_inst["pc"], txt_inst["opcode"])
        if "load" in txt_inst:
            string += " load:%x" % txt_inst["load"]
        if "store" in txt_inst:
            string += " store:%x" % txt_inst["store"]
        if "data" in txt_inst:
            string += " val:%x" % txt_inst["data"]    
        if "cap" in txt_inst:
            txt_cap = txt_inst["cap"]
            string += " v:%d s:%d b:%x o:%x l:%x p:%x t:%x" % (
            txt_cap["valid"], txt_cap["sealed"],
            txt_cap["base"], txt_cap["offset"], txt_cap["length"],
            txt_cap["perms"], txt_cap["otype"])
        return string

    def _parse_exception(self, entry, regs, disasm, idx):
        super()._parse_exception(entry, regs, disasm, idx)

        # read entry from
        txt_inst = self._next_txt_instr()
        logger.debug("Scan txt:<%s>, bin:<unparsed>",
                     self._dump_txt_inst(txt_inst))
        # check only pc which must be valid anyway
        assert txt_inst["pc"] == entry.pc

    def scan_all(self, inst, entry, regs, last_regs, idx):

        # read entry from
        txt_inst = self._next_txt_instr()
        logger.debug("Scan txt:<%s>, bin:%s",
                     self._dump_txt_inst(txt_inst), inst)
        try:
            # check that the instruction matches
            assert txt_inst["pc"] == entry.pc
            if self.pc_only:
                # only check pc, skip everything else
                return False
            if inst.opcode in ["mfc0"]:
                # these have weird behaviour so just ignore for now
                return False

            if txt_inst["opcode"] != inst.opcode:
                # opcode check is not mandatory due to disassembly differences
                # issue a warning anyway for now
                logger.warning("Opcode differ {%d} txt:<%s> bin:%s",
                               entry.cycles, self._dump_txt_inst(txt_inst),
                               inst)
            if "load" in txt_inst:
                assert txt_inst["load"] == entry.memory_address
            if "store" in txt_inst:
                assert txt_inst["store"] == entry.memory_address
            if "data" in txt_inst:
                if inst.opcode not in ["mfc0"]:
                    reg_number = entry.gpr_number()
                    for op in inst.operands:
                        if op.is_register and op.gpr_index == reg_number:
                            logger.debug("gpr:%d reg:%d")
                            assert txt_inst["data"] == op.value, \
                                "reg data do not match %d != %d" % (
                                    txt_inst["data"], op.value)
                            break
                #     # XXX we have a problem with extracting the jump target
                #     # from jal/j the binary trace have an offset that does
                #     # not make much sense..
                #     assert txt_inst["data"] == inst.op0.value
            if "cap" in txt_inst:
                cap = CheriCap(inst.op0.value)
                txt_cap = txt_inst["cap"]
                assert txt_cap["valid"] == cap.valid, \
                    "tag do not match %d != %d" % (
                        txt_cap["valid"], cap.valid)
                assert txt_cap["sealed"] == cap.sealed, \
                    "seal do not match %d != %d" % (
                        txt_cap["sealed"], cap.sealed)
                assert txt_cap["base"] == cap.base, \
                    "base do not match %x != %x" % (
                        txt_cap["base"], cap.base)
                assert txt_cap["length"] == cap.length, \
                    "length do not match %x != %x" % (
                        txt_cap["length"], cap.length)
                assert txt_cap["offset"] == cap.offset, \
                    "offset do not match %x != %x" % (
                        txt_cap["offset"], cap.offset)
                assert txt_cap["perms"] == cap.permissions, \
                    "perms do not match %x != %x" % (
                        txt_cap["perms"], cap.permissions)
                assert txt_cap["otype"] == cap.objtype, \
                    "otype do not match %x != %x" % (
                        txt_cap["otype"], cap.objtype)
            
        except AssertionError:
            logger.error("Assertion failed at {%d} inst:%s txt:<%s>",
                         entry.cycles, inst, self._dump_txt_inst(txt_inst))
            raise
        self.progress.advance()
        return False
        
