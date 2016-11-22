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

from ..utils import ProgressPrinter

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


class Operand:
    """
    Helper class used to parse memory operands
    """

    def __init__(self, op_info, instr):

        self.info = op_info
        """The operand_info structure for this operand"""

        self.instr = instr
        """The instruction with this operand"""

        self.is_register = op_info.is_register
        """Operand is a register?"""

        self.is_immediate = op_info.is_immediate
        """Operand is immediate?"""

    @property
    def name(self):
        """Operand register name or None"""
        if self.is_register:
            return pct.cvar.mips_register_names[self.info.register_number]
        else:
            return None

    @property
    def value(self):
        """Operand value"""
        if self.is_immediate:
            return self.info.immediate
        elif self.is_register:
            reg_num = self.info.register_number
            if reg_num == 0:
                return 0
            elif reg_num < 32:                
                if not self.instr._regset.valid_gprs[reg_num - 1]:
                    logger.debug("Taking GPR value $%d from invalid register",
                                   reg_num)
                return self.instr._regset.gpr[reg_num - 1]
            elif reg_num < 64:
                logger.warning("Floating point registers not yet supported")
                return 0
            else:
                if not self.instr._regset.valid_caps[reg_num - 64]:
                    logger.debug("Taking CAP value $c%d from invalid register",
                                   reg_num - 64)
                return self.instr._regset.cap_reg[reg_num - 64]
        else:
            logger.error("Operand type not supported")
            raise ValueError("Operand type not supported")

    @property
    def is_capability(self):
        """The operand is a capability register?"""
        return self.is_register and self.info.register_number >= 64

    @property
    def cap_index(self):
        """Return the register number in the range 0-31"""
        if not (self.is_register and self.info.register_number >= 64):
            logger.error("Operand is not a capability register,"
                         " can not get register number")
            raise IndexError("Operand is not a capability register")
        return self.info.register_number - 64

    @property
    def gpr_index(self):
        """Return the register number in the range 0-31"""
        if not (self.is_register and self.info.register_number < 32):
            logger.error("Operand is not a GPR register,"
                         " can not get register number")
            raise IndexError("Operand is not a GPR register")
        return self.info.register_number

    def __str__(self):
        if self.is_immediate:
            return "<Op %s>" % self.value
        elif self.is_register:
            return "<Op $%s = %s>" % (self.name, self.value)
        else:
            return "<Op unknown>"


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

        parts = inst.name.split("\t")
        self.opcode = parts[1]
        """Instruction opcode"""

        # if inst.type == inst.instruction_type.memory_access:
        # last two operands are offset+register

        # XXX may make operand parsing lazy to save parsing time
        self.operands = []
        """List of instruction operands :class:`.Operand`"""
        
        for op in inst.operands:
            self.operands.append(Operand(op, self))

    def _op_n(self, n):
        """Shorthand getter for operand N."""
        if len(self.operands) > n:
            return self.operands[n]
        return None
            
    @property
    def op0(self):
        """Shorthand getter for operand 0."""
        return self._op_n(0)

    @property
    def op1(self):
        """Shorthand getter for operand 1."""
        return self._op_n(1)

    @property
    def op2(self):
        """Shorthand getter for operand 2."""
        return self._op_n(2)

    @property
    def op3(self):
        """Shorthand getter for operand 3."""
        return self._op_n(3)

    # backward compatibility aliases
    cd = op0
    cb = op1
    rt = op2

    def __str__(self):
        instr_repr = "<Inst %s " % self.opcode
        for op in self.operands:
            instr_repr += str(op)
        instr_repr += ">"
        return instr_repr


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

    * all: all instructions
    * cap: all capability instructions
    * cap_load: all capability load
    * cap_store: all capability store
    * cap_arith: all capability pointer manipulation
    * cap_bound: all capability bound modification
    * cap_cast: all conversions from and to capability pointers
    * cap_other: all capability instructions that do not fall in
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
                        if opcode in self._callbacks:
                            self._callbacks[opcode].append(method)
                        else:
                            self._callbacks[opcode] = [method]
                    break
            else:
                if instr_name in self._callbacks:
                    self._callbacks[instr_name] += [method]
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
        callbacks = list(self._callbacks.get("all", []))
        callbacks += self._callbacks.get(inst.opcode, [])
        # if len(callbacks):
        #     # parse instruction operands only when
        #     # absolutely necessary
        #     inst.parse()
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
            except Exception as e:
                logger.error("Error parsing instruction #%d pc:0x%x: %s raw: 0x%x",
                             entry.cycles, entry.pc, disasm.name, entry.inst)
                return False

            ret = False

            try:
                for cbk in self._get_callbacks(inst):
                    ret |= cbk(inst, entry, regs, self._last_regs, idx)
                    if ret:
                        break
            except Exception as e:
                logger.error("Error in callback %s: %s", cbk, e)
                raise

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

    XXX: experimental/broken
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
