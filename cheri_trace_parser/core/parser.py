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


Parser for cheri trace files based on the cheritrace library
"""

import os
import math
import re
import numpy as np
import logging

import pycheritrace as pct

from enum import Enum
from itertools import repeat, chain

# experimental
from multiprocessing import RawValue, Process
from ctypes import py_object

from cheri_trace_parser.utils import ProgressPrinter

logger = logging.getLogger(__name__)

class TraceParser:
    """
    Base trace parser without parsing infrastructure

    This handles only the loading of the trace file
    """

    def __init__(self, trace_path=None):
        self.path = trace_path
        self.trace = None

        if trace_path is not None:
            if not os.path.exists(trace_path):
                raise IOError("File not found %s" % trace_path)
            self.trace = pct.trace.open(trace_path)
            if self.trace is None:
                raise IOError("Can not open trace %s" % trace_path)

    def __len__(self):
        if self.trace:
            return self.trace.size()
        return 0


class Instruction:
    """
    Internal instruction representation that provides more
    information in addition to the pycheritrace disassembler.
    """

    class IClass(Enum):
        """
        Enumerate instruction classes for
        :meth:`.Instruction.is_type`.
        """

        I_CAP_LOAD = "cap_load"
        """Load via capability."""
        I_CAP_STORE = "cap_store"
        """Store via capability."""
        I_CAP_CAST = "cap_cast"
        """Cast capability to or from pointer."""
        I_CAP_ARITH = "cap_arith"
        """Arithmetic capability manipulation."""
        I_CAP_BOUND = "cap_bound"
        """Change capability bounds."""
        I_CAP_FLOW = "cap_flow"
        """Capability flow control."""
        I_CAP_OTHER = "cap_other"
        """Other capability instruction not in previous classes."""
        I_CAP = "cap"
        """Generic capability instruction."""


    class Operand:
        """
        Helper class for parsing instruction operands.
        """

        def __init__(self, name, regset, is_immediate):
            self.is_immediate = is_immediate
            """True if the operand an immediate."""

            self.name = name
            """Matched argument string, e.g. c4 for the register $c4."""

            self.value = None
            """Value of the operand."""
            if self.cap_index != -1:
                if regset.valid_caps[self.cap_index]:
                    self.value = regset.cap_reg[self.cap_index]
                else:
                    logger.warning("Taking value of %s from "\
                                   "invalid cap register", name)
            elif self.reg_index != -1:
                if self.reg_index == 0:
                    self.value = 0
                elif regset.valid_gprs[self.reg_index - 1]:
                    self.value = regset.gpr[self.reg_index - 1]
                else:
                    logger.warning("Taking value of %s from "\
                                   "invalid gpr register", name)

        @property
        def cap_index(self):
            if (self.is_immediate or self.name is None):
                return -1
            if (self.name and str(self.name)[0] == "c"):
                return int(self.name[1:])
            return -1

        @property
        def reg_index(self):
            if (self.is_immediate or self.name is None):
                return -1
            strval = str(self.name)
            if self.name and strval[0] == "c":
                return -1
            if self.name == "gp":
                return 28
            if self.name == "sp":
                return 29
            if self.name == "fp":
                return 30
            if self.name == "ra":
                return 31
            if self.name == "zero":
                return 0
            if strval[0] != "f":
                # do not support floating point registers for now
                return int(self.name)
            return -1

        def __repr__(self):
            return "<operand %s = %s>" % (self.name, self.value)

    class Implicit:
        """
        Helper class representing an implicit register written by an
        instruction.
        """

        def __init__(self, entry):
            if entry.gpr_number() != -1:
                self.name = entry.gpr_number()
                self.value = entry.reg_value_gp()
            elif entry.capreg_number() != -1:
                self.name = entry.capreg_number()
                self.value = entry.reg_value_cap()

        def __repr__(self):
            return "<implicit %s = %s>" % (self.name, self.value)


    # map each instruction class to a set of opcodes
    iclass_map = {
        IClass.I_CAP_LOAD: [
            "clc", "clb", "clh", "clw",
            "cld", "clhu", "clwu", "cllc",
            "cllb", "cllh", "cllw", "clld",
            "cllhu", "cllwu"],
        IClass.I_CAP_STORE: [
            "csc", "csb", "csh", "csw",
            "csd", "cscc", "cscb", "csch",
            "cscw", "cscd"],
        IClass.I_CAP_CAST: [
            "ctoptr", "cfromptr"],
        IClass.I_CAP_ARITH: [
            "cincoffset", "csetoffset", "csub"],
        IClass.I_CAP_BOUND: [
            "csetbounds", "csetboundsexact"],
        IClass.I_CAP_FLOW: [
            "cbtu", "cbts", "cjr", "cjalr",
            "ccall", "creturn"],
        IClass.I_CAP_OTHER: [
            "cgetperm", "cgettype", "cgetbase", "cgetlen",
            "cgettag", "cgetsealed", "cgetoffset", "cgetpcc",
            "cgetpccsetoffset", "cseal", "cunseal", "candperm",
            "ccleartag", "ceq", "cne", "clt",
            "cle", "cltu","cleu", "cexeq",
            "cgetcause", "csetcause", "ccheckperm", "cchecktype",
            "clearlo", "clearhi", "cclearlo", "cclearhi",
            "fpclearlo", "fpclearhi"]
        }

    def __init__(self, inst, entry, regset, prev_regset):
        """
        Construct instruction from pycheritrace instruction.

        :param inst: pycheritrace disassembler instruction
        :type inst: :class:`pycheritrace.instruction_info`
        :param regset: register set after the execution 
        of the instruction
        :type regset: :class:`pycheritrace.register_set`
        :param prev_regset: register set before the execution 
        of the instruction
        :type prev_regset: :class:`pycheritrace.register_set`
        """
        self._regset = regset
        """Register set used for the destination register."""

        self._prev_regset = prev_regset
        """Register set used for the source register(s)."""

        self.inst = inst
        """Disassembled instruction."""

        self.entry = entry
        """Trace entry of the instruction"""

        self._parsed = False
        """Flag indicating whether :meth:`parse` has been called."""

        # the opcode is the only thing needed every time
        parts = inst.name.split("\t")
        self.opcode = parts[1]
        """Instruction opcode"""

    def parse(self):
        """
        Perform the expensive part of instruction parsing.
        This is separate from __init__ so that it can be performed
        only when strictly necessary.
        """
        if self._parsed:
            return

        disasm = self.inst.name
        if len(disasm.split("\n")) > 1:
            # remove pseudo instructions such as .set
            logger.info("Directives are not yet supported%s", disasm)
            disasm = disasm.split("\n")[1]

        # XXX the operand registers and immediates should really be
        # available from llvm, don't know how yet.
        match = re.match("^\s*([a-z0-9]+)\s*(\$?)(c?[sfgpra]{0,2}[0-9]*)?\s*,?"\
                         "\s*(\$?)(c?[sfgpra0-9]{1,2})?\s*,?"\
                         "\s*(\$?)([0-9csfgpxra\$\(\)]+)?", disasm)
        if match == None:
            logger.error("Asm expression not supported %s", disasm)
            raise ValueError("Malformed disassembly %s", disasm)
        if match.group(3):
            self.cd = self.Operand(match.group(3), self._regset,
                                   match.group(2) == "")
        else:
            self.cd = None

        if match.group(5):
            self.cb = self.Operand(match.group(5), self._prev_regset,
                                   match.group(4) == "")
        else:
            self.cb = None

        if match.group(7):
            self.rt = self.Operand(match.group(7), self._prev_regset,
                                   match.group(6) == "")
        else:
            self.rt = None

        # check for implicit register write
        gpr_number = self.entry.gpr_number()
        cap_number = self.entry.capreg_number()
        if ((gpr_number != -1 and (self.cd is None or self.cd.reg_index != gpr_number)) or
            (cap_number != -1 and (self.cd is None or self.cd.cap_index != cap_number))):
            self.implicit = self.Implicit(self.entry)
        else:
            self.implicit = None

        # logger.debug("parsed instruction cd:%s cb:%s rt:%s impl:%s",
        #              self.cd, self.cb, seplf.rt, self.implicit)


class CallbackTraceParser(TraceParser):
    """
    Trace parser that provides help to filter
    and normalize instructions.

    This class performs the filtering of instructions
    that are interesting to the parser and calls the appropriate
    callback if it is defined.
    Callback methods must start with "scan_" followed by the opcode
    or instruction class (e.g. scan_ld will be invoked every time an
    "ld" instruction is found, scan_cap_load will be invoked every time
    a load or store through a capability is found).
    The callback must have the follwing signature:
    scan_<name>(inst, entry, regs, last_regs, idx).

    Valid instruction class names are:

    all: all instructions
    cap: all capability instructions
    cap_load: all capability load
    cap_store: all capability store
    cap_arith: all capability pointer manipulation
    cap_bound: all capability bound modification
    cap_cast: all conversions from and to capability pointers
    cap_other: all capability instructions that do not fall in
    the previous "cap_" classes
    """

    def __init__(self, dataset, trace_path):
        super(CallbackTraceParser, self).__init__(trace_path)

        self.dataset = dataset
        """The dataset where the parsed data will be stored"""

        self.progress = ProgressPrinter(
            len(self), desc="Scanning trace %s" % trace_path)
        """Progress object to display feedback to the user"""

        self._last_regs = None
        """Snapshot of the registers of the previous instruction"""

        self._dis = pct.disassembler()
        """Disassembler"""

        # Enumerate the callbacks at creation time to save
        # time during scanning
        self._callbacks = {}

        # for each opcode we may be interested in, check if there is
        # one or more callbacks to call, if so these will be stored
        # in _callbacks[<opcode>] so that the _get_callbacks function
        # can retrieve them in ~O(1)
        for attr in dir(self):
            method = getattr(self, attr)
            if (not attr.startswith("scan_") or not callable(method)):
                continue
            instr_name = attr[5:]
            for iclass in Instruction.IClass:
                if instr_name == iclass.value:
                    # add the iclass callback for all the
                    # instructions in such class
                    if iclass == Instruction.IClass.I_CAP:
                        opcodes = []
                        for iclass_opcodes in Instruction.iclass_map.values():
                            opcodes += iclass_opcodes
                    else:
                        opcodes = Instruction.iclass_map.get(iclass, [])
                    for opcode in opcodes:
                        try:
                            self._callbacks[opcode].append(method)
                        except KeyError:
                            self._callbacks[opcode] = [method]
                    break
            else:
                self._callbacks[instr_name] = [method]

        logger.debug("Loaded callbacks for CallbackTraceParser %s",
                     self._callbacks)

    def _get_callbacks(self, inst):
        """
        Return a list of callback methods that should be called to
        parse this instruction

        :param inst: instruction object for the current instruction
        :type inst: :class:`.Instruction`
        :return: list of methods to be called
        :rtype: list of callables
        """
        # try to get the callback for all instructions, if any
        callbacks = self._callbacks.get("all", [])
        callbacks += self._callbacks.get(inst.opcode, [])
        if len(callbacks):
            # parse instruction operands only when
            # absolutely necessary
            inst.parse()
        return callbacks

    def parse(self, start=None, end=None):
        """
        Parse the trace

        For each trace entry a callback is invoked, some classes
        of instructions cause the callback for the group to be called,
        e.g. scan_cap_load is called whenever a load from memory through
        a capability is found.

        Each instruction opcode can have a callback in the form 
        scan_<opcode>.

        :param start: index of the first trace entry to scan
        :type start: int
        :param end: index of the last trace entry to scan
        :type end: int
        """

        if start is None:
            start = 0
        if end is None:
            end = len(self)

        def _scan(entry, regs, idx):
            self.progress.advance()
            disasm = self._dis.disassemble(entry.inst)
            try:
                if self._last_regs is None:
                    self._last_regs = regs
                inst = Instruction(disasm, entry, regs, self._last_regs)
            except Exception:
                logger.error("Error parsing instruction #%d pc:0x%x: %s raw: 0x%x",
                             entry.cycles, entry.pc, disasm.name, entry.inst)
                return False

            ret = False

            for cbk in self._get_callbacks(inst):
                ret |= cbk(inst, entry, regs, self._last_regs, idx)
                if ret:
                    break

            self._last_regs = regs
            return ret

        self.trace.scan(_scan, start, end)
        self.progress.finish()


class ThreadedTraceParser:
    """
    Trace parser that scans a trace using multiple processes

    The scanning processes are forked from the current parser
    and each one is allocated a range of the trace. The parsed
    data items are piped through one or more queues. The current
    process pulls data from the queue(s) and stores it in the
    dataset

    XXX: experimental
    """

    def __init__(self, path, parser, threads=2):
        self.trace = RawValue(py_object, None)
        """Trace in shared memory"""
        self.parser = parser
        """
        Callback that handles each trace block, this is run
        in separate processes
        """
        self.n_threads = threads
        """Number of subprocesses that are spawned"""
        self.path = path
        """Trace path"""

        if not os.path.exists(path):
            raise IOError("File not found %s" % path)
        self.trace = pct.trace.open(path)
        if self.trace is None:
            raise IOError("Can not open trace %s" % path)

    def __len__(self):
        if self.trace:
            return self.trace.size()
        return 0

    def parse(self, *args, **kwargs):
        start = kwargs.pop("start", 0)
        end = kwargs.pop("end", len(self))
        block_size = math.floor((end - start) / self.n_threads)
        start_indexes = np.arange(start, end - block_size + 1, block_size)
        end_indexes = np.arange(start + block_size, end + 1, block_size) - 1
        # the last process consumes any remaining entries left by the
        # rounding of block_size
        end_indexes[-1] = end

        procs = []
        for idx_start, idx_end in zip(start_indexes, end_indexes):
            print(idx_start, idx_end)
            p = Process(target=self.parser, args=(self.path, idx_start, idx_end))
            procs.append(p)

        for p in procs:
            p.start()
        for p in procs:
            p.join()
