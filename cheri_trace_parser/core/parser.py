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


class CallbackMeta(type):
    """
    Resolve callback methods in :class:`.CallbackTraceParser`
    by looking for methods in the form scan_*
    """

    def __new__(cls, name, bases, namespace, **kwds):
        result = type.__new__(cls, name, bases, namespace, **kwds)
        result._callbacks = {}
        for opcode in Instruction.cap_opcodes:
            callback_method = "scan_%s" % opcode
            if hasattr(result, callback_method):
                result._callbacks[opcode] = getattr(result, callback_method)

class Instruction:
    """
    Internal instruction representation that provides more
    information in addition to the pycheritrace disassembler
    """

    class IClass(Enum):
        """
        Enumerate instruction classes for
        :meth:`.Instruction.is_type`
        """

        I_CAP = "cap"
        """Generic capability instruction"""
        I_CAP_LOAD = "cap_load"
        """Load via capability"""
        I_CAP_STORE = "cap_store"
        """Store via capability"""
        I_CAP_CAST = "cap_cast"
        """Cast capability to or from pointer"""
        I_CAP_ARITH = "cap_arith"
        """Arithmetic capability manipulation"""
        I_CAP_BOUND = "cap_bound"
        """Change capability bounds"""
        I_CAP_FLOW = "cap_flow"
        """Capability flow control"""


    class Operand:
        """
        Helper class for parsing instruction operands
        """

        def __init__(self, name, regset, is_immediate):
            self.is_immediate = is_immediate
            """True if the operand an immediate"""

            self.name = name
            """Matched argument string, e.g. c4 for the register $c4"""

            self.value = None
            """Value of the operand"""

            if self.cap_index != -1:
                if regset.valid_caps[self.cap_index]:
                    self.value = regset.cap_reg[self.cap_index]
                else:
                    logger.warning("Taking value of %s from "\
                                   "invalid cap register", name)
            elif self.reg_index != -1:
                if regset.valid_gprs[self.reg_index]:
                    self.value = regset.gpr[self.reg_index]
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
            if self.name == "sp":
                return 29
            if self.name == "fp":
                return 30
            if strval[0] != "f":
                # do not support floating point registers for now
                return int(self.name)
            return -1


    # XXX may be desirable to replace the matching
    # with something provided by the llvm backend

    cap_load = ["clc", "clb", "clh", "clw",
                "cld", "clhu", "clwu", "cllc",
                "cllb", "cllh", "cllw", "clld",
                "cllhu", "cllwu"]
    cap_store = ["csc", "csb", "csh", "csw",
                 "csd", "cscc", "cscb", "csch",
                 "cscw", "cscd"]
    cap_cast = ["ctoptr", "cfromptr"]
    cap_arith = ["cincoffset", "csetoffset", "csub"]
    cap_bound = ["csetbounds", "csetboundsexact"]
    cap_flow = ["cbtu", "cbts", "cjr", "cjalr",
                "ccall", "creturn"]
    cap_other = ["cgetperm", "cgettype", "cgetbase", "cgetlen",
                 "cgettag", "cgetsealed", "cgetoffset", "cgetpcc",
                 "cgetpccsetoffset", "cseal", "cunseal", "candperm",
                 "ccleartag", "ceq", "cne", "clt",
                 "cle", "cltu","cleu", "cexeq",
                 "cgetcause", "csetcause", "ccheckperm", "cchecktype",
                 "clearlo", "clearhi", "cclearlo", "cclearhi",
                 "fpclearlo", "fpclearhi"]

    def __init__(self, inst, regset):
        """
        Construct instruction from pycheritrace instruction

        :param inst: pycheritrace disassembler instruction
        :type inst: :class:`pycheritrace.instruction_info`
        """
        self.regset = regset
        self.inst = inst
        self._parsed = False

        # the opcode is the only thing needed every time
        parts = inst.name.split("\t")
        self.opcode = parts[1]

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
        # XXX currently assuming CHERI capability instruction
        # the operand registers and immediates should really be
        # available from llvm, I just don't know how yet.
        match = re.match("^\s*([a-z]+)\s*(\$?)(c?[sfp0-9]{1,2})?\s*,?"\
                         "\s*(\$?)(c?[sfp0-9]{1,2})?\s*,?"\
                         "\s*(\$?)([0-9csfpx\$\(\)]+)?", disasm)
        if match == None:
            logger.error("Asm expression not supported %s", disasm)
            raise ValueError("Malformed disassembly %s", disasm)
        self.cd = self.Operand(match.group(3), self.regset,
                               match.group(2) == "")
        self.cb = self.Operand(match.group(5), self.regset,
                               match.group(4) == "")
        self.rt = self.Operand(match.group(7), self.regset,
                               match.group(6) == "")


class CallbackTraceParser(TraceParser):
    """
    Trace parser that provides help to filter
    and normalize instructions
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

        # generic callbacks for instruction classes
        # look in this object for iclass callbacks of the
        # form scan_<iclass_name> and temporarily store the
        # methods here. The methods are added to all the opcodes in
        # the relevant iclass in the _callbacks dictionary
        iclass_callbacks = {}
        for iclass in Instruction.IClass:
            callback_method = "scan_%s" % iclass.value
            try:
                iclass_callbacks[iclass] = getattr(self, callback_method)
            except AttributeError:
                continue

        # for each opcode we may be interested in, check if there is
        # one or more callbacks to call, if so these will be stored
        # in _callbacks[<opcode>] so that the _get_callbacks function
        # can retrieve them in ~O(1)
        cap_opcodes = (Instruction.cap_load + Instruction.cap_store +
                       Instruction.cap_cast + Instruction.cap_arith +
                       Instruction.cap_bound + Instruction.cap_flow +
                       Instruction.cap_other)
        cap_iclass = chain(repeat(Instruction.IClass.I_CAP_LOAD,
                                  len(Instruction.cap_load)),
                           repeat(Instruction.IClass.I_CAP_STORE,
                                  len(Instruction.cap_store)),
                           repeat(Instruction.IClass.I_CAP_CAST,
                                  len(Instruction.cap_cast)),
                           repeat(Instruction.IClass.I_CAP_ARITH,
                                  len(Instruction.cap_arith)),
                           repeat(Instruction.IClass.I_CAP_BOUND,
                                  len(Instruction.cap_bound)),
                           repeat(Instruction.IClass.I_CAP_FLOW,
                                  len(Instruction.cap_flow)),
                           repeat(None, len(Instruction.cap_other)))
        for opcode, iclass in zip(cap_opcodes, cap_iclass):
            callbacks = []
            callback_method = "scan_%s" % opcode
            try:
                callbacks.append(iclass_callbacks[Instruction.IClass.I_CAP])
            except KeyError:
                pass

            try:
                callbacks.append(iclass_callbacks[iclass])
            except KeyError:
                pass

            try:
                callbacks.append(getattr(self, callback_method))
            except AttributeError:
                pass
            self._callbacks[opcode] = callbacks
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
        try:

            callbacks = self._callbacks[inst.opcode]
            # parse instruction operands only when
            # absolutely necessary
            inst.parse()
            return callbacks
        except KeyError:
            return []

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
            inst = Instruction(disasm, regs)

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
