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

"""
Parser for cheri trace files based on the cheritrace library.
"""

import math
import numpy as np
import logging
import os
import pycheritrace as pct
import sys

from cached_property import cached_property
from collections import defaultdict
from enum import Enum
from functools import reduce
from itertools import chain
from multiprocessing import Pool, Value, Manager, Lock, Condition

from cheriplot.core.utils import ProgressPrinter

logger = logging.getLogger(__name__)

class TraceParser:
    """
    Base trace parser without parsing infrastructure.
    This handles only the loading of the trace file

    :param trace_path: path to the cvtrace file to open
    :type trace_path: str
    """

    def __init__(self, trace_path=None, defer_preload=False, **kwargs):
        super().__init__(**kwargs)
        self.path = trace_path
        self.trace = None

        if trace_path is not None:
            if not os.path.exists(trace_path):
                raise IOError("File not found %s" % trace_path)
            logger.debug("Open trace %s (preload=%s)", trace_path, defer_preload)
            self.trace = pct.trace.open(trace_path, None, defer_preload)
            if self.trace is None:
                raise IOError("Can not open trace %s" % trace_path)

    def __len__(self):
        if self.trace is not None:
            return self.trace.size()
        return 0


class Operand:
    """
    Helper class used to parse instruction operands,
    this wraps a pycheritrace operand_info.
    """

    def __init__(self, op_info, instr, is_target=False):

        self.info = op_info
        """The operand_info structure for this operand"""

        self.instr = instr
        """The instruction with this operand"""

        self.is_register = op_info.is_register
        """Operand is a register?"""

        self.is_immediate = op_info.is_immediate
        """Operand is immediate?"""

        self.is_destination = is_target
        """Is the operand the target of the instruction?"""

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

            # select the correct register set to take the value
            # this is important when we modify the source register e.g.
            # daddiu $2, $2, 1
            # the source value is in prev_regset while the destination
            # value is in the current regset
            if self.is_destination:
                regset = self.instr._regset
            else:
                regset = self.instr._prev_regset

            if reg_num == 0:
                # $zero is always zero
                return 0

            elif reg_num < 32:
                if not regset.valid_gprs[reg_num - 1]:
                    logger.debug("Taking GPR value $%d from invalid register",
                                   reg_num)
                    return None
                return regset.gpr[reg_num - 1]
            elif reg_num < 64:
                logger.warning("Floating point registers not yet supported")
                return 0
            else:
                if not regset.valid_caps[reg_num - 64]:
                    logger.debug("Taking CAP value $c%d from invalid register",
                                   reg_num - 64)
                    return None
                return regset.cap_reg[reg_num - 64]
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
            logger.error("Operand %s is not a capability register,"
                         " can not get register number", self)
            raise IndexError("Operand is not a capability register")
        return self.info.register_number - 64

    @property
    def gpr_index(self):
        """Return the register number in the range 0-31"""
        if not (self.is_register and self.info.register_number < 32):
            logger.error("Operand %s is not a GPR register,"
                         " can not get register number", self)
            raise IndexError("Operand is not a GPR register")
        return self.info.register_number

    def __str__(self):
        if self.is_immediate:
            return "<Op %s>" % self.value
        elif self.is_register:
            if self.is_capability:
                if self.value is None:
                    # the value is None if the operand was fetched
                    # from an invalid register in the cheritrace
                    # regset
                    value = "reg_invalid"
                else:
                    value = "[b:0x%x, o:0x%x, l:0x%x, v:%d, s:%d]" % (
                        self.value.base, self.value.offset,
                        self.value.length, self.value.valid,
                        self.value.unsealed)
            else:
                value = self.value
            return "<Op $%s = %s>" % (self.name, value)
        else:
            return "<Op unknown>"


class Instruction:
    """
    Internal instruction representation that provides more
    information in addition to the pycheritrace disassembler.
    """

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

        parts = inst.name.split("\t")
        self.opcode = parts[1]
        """Instruction opcode"""

    @cached_property
    def operands(self):
        op_list = []
        for idx, op in enumerate(self.inst.operands):
            is_target = (idx == 0)
            op_list.append(Operand(op, self, is_target))
        return op_list

    def _op_n(self, n):
        """Shorthand getter for operand N."""
        if len(self.inst.operands) > n:
            is_target = (n == 0)
            return Operand(self.inst.operands[n], self, is_target)
        return None

    @cached_property
    def op0(self):
        """Shorthand getter for operand 0."""
        return self._op_n(0)

    @cached_property
    def op1(self):
        """Shorthand getter for operand 1."""
        return self._op_n(1)

    @cached_property
    def op2(self):
        """Shorthand getter for operand 2."""
        return self._op_n(2)

    @cached_property
    def op3(self):
        """Shorthand getter for operand 3."""
        return self._op_n(3)

    # backward compatibility aliases
    cd = op0
    cb = op1
    rt = op2

    @property
    def has_exception(self):
        return self.entry.exception != 31

    def __str__(self):
        instr_repr = "<Inst {%d} pc:0x%x %s " % (
            self.entry.cycles, self.entry.pc, self.opcode)
        for op in self.operands:
            instr_repr += str(op)
        instr_repr += ">"
        return instr_repr


class IClass(Enum):
    """
    Enumerate instruction classes with
    the relative callback name.
    There are two more reserved classes
    I_ALL and I_EXCEPTION that define
    the callback invoked for every instruction
    and whenever an instruction causes an exception.
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
    I_CAP_CPREG = "cap_cpreg"
    """Manipulation of reserved coprocessor registers"""
    I_CAP_CMP = "cap_cmp"
    """Capability comparison"""
    I_CAP_OTHER = "cap_other"
    """Other capability instruction not in previous classes."""
    I_CAP = "cap"
    """Generic capability instruction."""


class CallbacksManager:
    """
    Gather callbacks from CallbackTraceParser and
    any registered subparser.
    The extractor returns the callbacks registered
    for a given instruction during the parse loop.
    This saves time by avoiding to check for callbacks
    dynamically during the loop.
    """

    iclass_map = defaultdict(lambda: [])
    """
    This is meant to be overridden in subclasses to define
    architecture-specific mapping from instruction to
    instruction classes.
    This default returns no callback names for any IClass.
    """

    def __init__(self):
        self._callbacks = defaultdict(lambda: [])
        """
        Map the instruction mnemonic to the list of callbacks
        registered to handle it.
        """

    def gather_callbacks(self, obj):
        """
        Fetch callbacks defined in the given object.
        All functions starting with the "scan_" prefix are treated as
        callbacks.
        All callbacks of the form "scan_<mnemonic>" are called when
        an instruction with a matching mnemonic is found.

        Additionally callbacks for instruction classes can be registerd
        as "scan_<iclass>" (e.g. scan_cap_cmp), these are called
        whenever an instruction in that class is found (this is specified
        in the CallbackManager.iclass_map).

        There are some reserved callback names:
        - scan_all: this callback will be invoked for every instruction.
        - scan_exception: this callback will be invoked when the parser
        finds an instruction that generate an exception.

        This step ensures that all callbacks are be stored
        in _callbacks[<opcode>] so that the get_callbacks function
        can retrieve them in ~O(1).
        """
        for attr in dir(obj):
            method = getattr(obj, attr)
            if (not attr.startswith("scan_") or not callable(method)):
                continue
            # remove the scan_ prefix
            cbk_name = attr[5:]
            for iclass in IClass:
                if cbk_name == iclass.value:
                    # add the iclass callback for all the
                    # instructions in such class
                    opcodes = self.iclass_map.get(iclass, [])
                    for opcode in opcodes:
                        self._callbacks[opcode].append(method)
                    break
            else:
                self._callbacks[cbk_name].append(method)
        logger.debug("CallbackManager loaded callbacks:\n%s",
                     self._dbg_repr_callbacks())

    def _dbg_repr_callbacks(self):
        """
        Return a debug representation of the callbacks registered
        by the parser.

        :return: str
        """
        pairs = map(
            lambda c: "%s -> %s" % (
                c[0],list(map(lambda m: m.__qualname__, c[1]))),
            self._callbacks.items())
        return reduce(lambda p,a: "%s\n%s" % (a, p), pairs, "")

    def get_callbacks(self, inst):
        """
        Return a list of callback methods that should be called to
        parse this instruction

        :param inst: instruction object for the current instruction
        :type inst: :class:`Instruction`
        :return: list of methods to be called
        :rtype: list of callables
        """
        # the <all> callback should be the last one executed
        if inst.has_exception:
            return chain(self._callbacks[inst.opcode],
                         self._callbacks["exception"],
                         self._callbacks["all"])
        elif inst.entry.is_load:
            return chain(self._callbacks[inst.opcode],
                         self._callbacks["mem_load"],
                         self._callbacks["all"])
        elif inst.entry.is_store:
            return chain(self._callbacks[inst.opcode],
                         self._callbacks["mem_store"],
                         self._callbacks["all"])
        else:
            return chain(self._callbacks[inst.opcode], self._callbacks["all"])


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
    * exception: all instruction with an exception
    * cap: all capability instructions
    * cap_load: all capability load
    * cap_store: all capability store
    * cap_arith: all capability pointer manipulation
    * cap_bound: all capability bound modification
    * cap_cast: all conversions from and to capability pointers
    * cap_cpreg: all manipulations of ddc, kdc, epcc, kcc
    * cap_other: all capability instructions that do not fall in
    the previous "cap_" classes
    """

    callback_manager_class = CallbacksManager

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.progress = ProgressPrinter(
            len(self), desc="Scanning trace %s" % self.path)
        """Progress object to display feedback to the user"""

        self._last_regs = None
        """Snapshot of the registers of the previous instruction"""

        self._dis = pct.disassembler()
        """Disassembler"""

        self._cbk_manager = self.callback_manager_class()
        """Helper that implements callbacks resolution"""

        self._cbk_manager.gather_callbacks(self)
        self._subparsers = []
        """Other parsers that can be added to the composite"""

        self.cycles_start = None
        """Cycles count of the first entry"""

        self.cycles_end = None
        """Cycles count of the last entry"""


    def _add_subparser(self, sub):
        self._subparsers.append(sub)
        self._cbk_manager.gather_callbacks(sub)

    def _parse_exception(self, entry, regs, disasm, idx):
        """
        Callback invoked when an instruction could not be parsed
        XXX make this debug because the mul instruction always fails
        and it is too verbose but should report it as a warning/error
        """
        logger.debug("Error parsing instruction #%d pc:0x%x: %s raw: 0x%x",
                     entry.cycles, entry.pc, disasm.name, entry.inst)

    def parse(self, start=None, end=None, direction=0):
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
        :param direction: scan direction (forward = 0, backward=1)
        :type direction: int
        """
        if start is None:
            start = 0
        if end is None:
            end = len(self)
        self._do_parse(start, end, direction)

    def _do_parse(self, start, end, direction):
        """
        Actual implementation of the tracing progression.
        See :meth:`CallbackTraceParser.parse`.
        """
        logger.debug("Scan trace [%d, %d]", start, end)
        # fast progress processing, calling progress.advance() in each
        # _scan call is too expensive
        progress_points = list(range(start, end, int((end - start) / 100) + 1))
        progress_points.append(end)

        def _scan(entry, regs, idx):
            if idx >= progress_points[0]:
                progress_points.pop(0)
                self.progress.advance(to=idx)
            if start == idx:
                self.cycles_start = entry.cycles
            elif end == idx:
                self.cycles_end = entry.cycles
            disasm = self._dis.disassemble(entry.inst)
            try:
                if self._last_regs is None:
                    self._last_regs = regs
                inst = Instruction(disasm, entry, regs, self._last_regs)
            except Exception as e:
                self._parse_exception(entry, regs, disasm, idx)
                return False

            ret = False

            try:
                for cbk in self._cbk_manager.get_callbacks(inst):
                    ret |= cbk(inst, entry, regs, self._last_regs, idx)
                    if ret:
                        break
            except Exception as e:
                logger.error("Error in callback %s (cycles offset %s): %s",
                             cbk, self.cycles_start, e)
                raise

            self._last_regs = regs
            return ret

        logger.debug("scanning %s %s %d %d %d", self.trace, _scan, start, end, direction)
        self.trace.scan(_scan, start, end, direction)
        self.progress.finish()


class MultiprocessCallbackParser(CallbackTraceParser):
    """
    Callback trace parser with multiprocessing support
    """

    class MultiprocessState:
        """
        This holds the state for multiprocessing for a parser
        instance.
        """

        def __init__(self, threads):
            self.pid = os.getpid()
            """Current process PID"""

            self.threads = threads
            """Number of workers to use."""

            self.pool = None
            """Subprocess pool."""

            self.results = []
            """Async results."""


    class ParserBuilder:
        """
        Wrapper that builds the parser in the worker processes.
        This is required since Swig objects are not pickle-able.
        """
        def __init__(self, klass, kwargs):
            self.klass = klass
            self.kwargs = kwargs

        def __call__(self):
            return self.klass(is_worker=True, **self.kwargs)

    @staticmethod
    def _run_worker(parser_builder, parse_args):
        """
        Multiprocessing parser worker body.

        This is the main function running a parser worker in
        a separate process.
        """
        parser = parser_builder()
        logger.debug("Trace created %d", os.getpid())
        parser._do_parse(*parse_args)
        return parser.mp_result()

    def __init__(self, is_worker=False, threads=os.cpu_count(), **kwargs):
        """
        Decorator constructor

        :param threads: number of worker processes to use.
        """
        if threads > 1 and "defer_preload" not in kwargs:
            kwargs["defer_preload"] = True
        super().__init__(**kwargs)
        assert threads > 0, "At least a worker process must be used!"

        self.is_worker = is_worker or threads == 1
        """Flag set if this is running in a worker process"""

        if not self.is_worker or threads == 1:
            self.mp = self.MultiprocessState(threads)
            self.kwargs = kwargs

    def mp_result(self):
        """
        Extract the partial result from the current worker.
        """
        return None

    def mp_merge(self, results):
        """
        Merge partial results from workers.
        """
        return

    def parse(self, start=None, end=None, direction=0):
        """
        Parse the trace with multiple subprocesses.
        This is run only by the master process
        """
        assert self.mp.threads > 0, "Number of workers must be > 0"
        logger.debug("Begin multiprocessing parse (master pid:%d)", self.mp.pid)

        start = start if start != None else  0
        end = end + 1 if end != None else len(self)
        if self.mp.threads == 1:
            # no need to start the pool and split the work, do everything
            # in the current process
            logger.debug("Running %s with 1 worker", self.__class__.__name__)
            self._do_parse(start, end, direction)
            self.mp_merge([self.mp_result()])
            return

        # split the start-end interval in sub-invervals for the workers
        block_size = math.floor((end - start) / self.mp.threads)
        rest = (end - start) % self.mp.threads
        start_indexes = np.arange(start, end - rest, block_size)
        end_indexes = np.arange(start + block_size - 1, end - rest,
                                block_size)
        # add the remaining to the last block
        end_indexes[-1] += rest

        # delay pool creation because the decorated calss must be available
        # in subprocesses as well.
        # Also avoid spawning processes for nothing if parse()
        # is never called.
        self.mp.pool = Pool(processes=self.mp.threads)
        # run the workers
        for start_idx, end_idx in zip(start_indexes, end_indexes):
            builder = self.ParserBuilder(self.__class__, dict(self.kwargs))
            # make sure that start and end are python integers otherwise
            # cheritrace bindings will complain about numpy.int
            parse_args = (int(start_idx), int(end_idx), int(direction))
            # prepare the worker main arguments
            args = (builder, parse_args)
            result = self.mp.pool.apply_async(
                    MultiprocessCallbackParser._run_worker, args)
            self.mp.results.append(result)
            # wait for all workers to finish
        self.mp.pool.close()
        self.mp.pool.join()
        # propagate exceptions and fetch results
        results = []
        for r in self.mp.results:
            results.append(r.get())

        # we don't need the pool anymore, kill anything that may
        # be still there
        self.mp.pool.terminate()
        del self.mp.pool
        # merge partial results
        self.mp_merge(results)
