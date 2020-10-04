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
import sys
import tempfile
import shutil
import time
import pickle
from enum import Enum

from functools import reduce
from collections import deque
from cheriplot.core import (
    MultiprocessCallbackParser, BaseTraceTaskDriver, ConfigurableComponent,
    Option, NestedConfig, interactive_tool, option_range_validator,
    any_int_validator)
from cheriplot.vmmap import VMMapFileParser
from cheriplot.provenance import CheriCap
from cheriplot.dbg.symbols import SymReader
sys.path.append(r'/root/cheri/cheriplot/cheriplot/cheriverify/')
sys.path.append(r'/root/cheri/cheriplot/cheriplot/cheriverify/coredump')
sys.path.append(r'/root/cheri/cheriplot/cheriplot/cheriverify/dwarfreader')
sys.path.append(r'/root/cheri/cheriplot/cheriplot/cheriverify/annotator')
from coredump.colour_print import *
from coredump.symbol_table_reader import symbol_table_reader
from coredump.capability import capability
from coredump.symbol_info import symbol_info
from coredump.symbol_type import symbol_type
from coredump.utility import count_leading_zero, compute_num_ls_zeroes
from dwarf_manager import dwarf_manager, dwarf_stack_variable_location_type, dwarf_variable_data_type
from subprocess import Popen, PIPE, TimeoutExpired
from annotator.annotator import annotator, annotation

logger = logging.getLogger(__name__)


def find_object_file(object_file_boundaries, cap: capability):
    for k, boundary in object_file_boundaries.items():
        if boundary.check_cursor_pointing_to_objfile(cap):
            return k
    return None

def check_bound(cap: capability, sym_info: symbol_info, object_file_boundaries, symbol="<unknown symbol>"):
    prGreen("Checking bound")
    # check the bound of a capability
    # if the capability is an object with size < 4k, size should matches the expected size exactly
    # otherwise, the difference should be smaller than the threshold and the base and top should satisfy the alignment requirement
    # have no idea why direct comparison does not work, compare the values instead
    if sym_info.expected_type.value == symbol_type.OBJECT.value:
        if sym_info.expected_size < 4096:
            if cap.length != sym_info.expected_size:
                print("> {} SIZE & BOUND MISMATCH -> Expacted: {}, Actual: {}".format(symbol, str(sym_info.expected_size), str(cap.length)))
                print("> {}".format(str(cap)))
                return False
            else:
                return True
        else:
            ls_zeroes = compute_num_ls_zeroes(cap.length)
            mask = "1" * ls_zeroes
            error = 0
            if int(mask, 2) & int(cap.base, 16):
                print("> {} Base violates alignment requirement.".format(symbol))
                error = 1
            if int(mask, 2) & int(cap.top, 16):
                print("> {} Top violates alignment requirement.".format(symbol))
                error = 1
            if sym_info.expected_size > cap.length:
                print("> {} Too strictive bound.".format(symbol))
                error = 1
            if abs(sym_info.expected_size - cap.length) > int(mask, 2):
                print("> {} Bound is not minimal.".format(symbol))
                error = 1
            if error:
                print("> Alignment mask: {}, Expected: {}, Actual: {}".format(mask, str(sym_info.expected_size), str(cap.length)))
                print("> {}".format(str(cap)))
                return False
            else:
                return True
    # if the capability is a function, the location of the function should be used to look up which object file it belongs to
    # the bound of a function capability should match the bound of the object file in which it is located
    elif sym_info.expected_type.value == symbol_type.FUNC.value:
        obj_file = find_object_file(object_file_boundaries, cap)
        if not obj_file:
            prRed("Function capability not pointing to any object file")
            return False
        if object_file_boundaries[obj_file].check_in_bound(cap):
            return True
        else:
            prRed("Function capability has different bounds against the containing object file.")
            prRed("Expected: {}, Function cap: {}".format(object_file_boundaries[obj_file], cap))
            return False
    # if the capability is a no type, we currently have no way to check it as we cannot deduce the type of it. 
    # but it would NORMALLY be either object or function. We could try
    elif sym_info.expected_type.value == symbol_type.NOTYPE.value:
        return True
    else:
        return False


class CheriVerifyParser(MultiprocessCallbackParser, ConfigurableComponent):
    """Parser that performs checks for stack variable bounds"""

    range_format_help = "Accept a range in the form <start>-<end>, -<end>, "\
                        "<start>- or <single_value>"

    info = Option(action="store_true", help="Print trace info and exit")
    start = Option("-s", type=int, default=0, help="Start offset in the trace")
    end = Option("-e", type=int, default=None, help="Stop offset in the trace")
    outfile = Option(
        "-o",
        type=str,
        default=None,
        help="Write output to the given file")
    step_over = Option("-z", action="store_true", help="Enable step_over mode. Press <Enter> to proceed.")
    show_regs = Option("-r", action="store_true", help="Dump register content")
    instr = Option(default=None, help="Find instruction occurrences")
    function_name = Option(
        "-f",
        type=str,
        default=None,
        help="Cheriverify: only update results for instructions in the given function"
    )
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

        :param sym_reader: symbol reader helper, used to extract
        symbol information
        """
        sym_reader = kwargs.pop("sym_reader")
        symbol_table = kwargs.pop("symbol_table")
        dwarf = kwargs.pop("dwarf")

        assert "trace_path" in kwargs, "trace_path argument is required!"
        if "keyframe_file" not in kwargs:
            kwargs["keyframe_file"] = "{}.kf".format(kwargs["trace_path"])
        super().__init__(**kwargs)

        if not self.is_worker:
            # update kwargs used to create workers
            self.kwargs["sym_reader"] = sym_reader

        self._entry_history = deque([], self.config.before)
        """FIFO instructions that may be shown if a match is found"""

        self._dump_next = 0
        """The remaining number of instructions to dump after a match"""

        self._kernel_mode = False
        """Keep track of kernel-userspace transitions"""

        self.sym_reader = sym_reader
        """Helper used to search symbols for addresses"""

        self.symbol_table = symbol_table
        """Helper used to search symbols for addresses(CheriVerify version)"""

        self.dwarf = dwarf
        """Helper used to look up for details of functions in dwarf info"""

        self.kernel_space_address_min = int("0xffffffff80000000", 16)

        self.violation_record = {}
        """Collection of instructions violating CheriVerify Checks"""

        self.tls_register = dict()

        self.out_of_bounds_access = {}

        self.tls_access = {}

        self.unknown_jump_address = {}

        self.dwarf_unknown_cjalr_address = {}

        self.set_bound_pending_reg = {} 
        """
        helper to store the registers that should require a 
        setbound before a load using that register
        key: register, value: (variable name, expected size)
        """

        self.found_subobject_access = {}

        self.found_stack_allocation = {}
        """
        helper to record the stack variable accessed
        key: function_name:variable, value: [incoffset_pc, setbound_pc]
        """

        self.log_f = open("/root/cheriverify.log", "w")

        self.previous_pc = None
        """the pc value of the previous instruciton parsed, used to detect jumps"""

        self.current_func_lowpc = None
        """lowpc of the current function being executed"""

        self.current_func_highpc = None
        """highpc of the current function being executed"""

        self.current_function_dwarf = None
        """Dwarf Stack Function object for the function currently being executed"""

        self.is_test = False

        self.result = {
            "Pass": 0,
            "Fail" : 0,
            "Object": 0,
            "Function": 0,
            "Notype": 0,
            "Out of Bounds": 0,
            "Object_unknown": 0,
            "Function_unknown": 0,
            "Notype_unknown": 0,
            "clc": 0,
            "clcr": 0,
            "clci": 0,
            "clcbi": 0,
            "clcbi from captable": 0,
            "clcbi not from captable": 0,
            "clc from captable": 0,
            "cgetpccincoffset": 0,
            "point to captable":0,
            "not point to captable":0, 
            "base not created with getpccincoffset":0,
            "fail sanity check": 0,
            "pass sanity check": 0,
            "jump detected": 0,
            "dwarf-known jump": 0,
            "dwarf-unknown jump": 0,
            "load from captable with incorrect bound": 0,
            "load from captable with correct bound": 0,
            "Found Stack Allocation": 0,
            "Stack Bound Set Correctly": 0,
            "Stack Bound Set Incorrectly": 0,
            "Accessed before bound set": 0, 
            "Taking pointer to aggregate type": 0,
            ####### cjalr
            # return address not belonging to any object file, 
            # potentiall PLT stubs or kernel space address
            "unknown return address": 0, 
            # cjalr jump desitnation capability having DSO bounds
            "cjalr with correct capability": 0,
            # cjalr jump desitnation capability NOT having DSO bounds
            "cjalr with incorrect capability": 0,
            # return capability that have DSO bound
            "return capability with correct bound": 0,
            # return capability that does NOT have DSO bound
            "return capability with incorrect bound": 0,
            # cjalr to unknown address, typically corrupted addresses
            "cjalr to unknown address": 0,
            "csetbounds for stack allocation": 0,
            "csetbounds" :0,
            # subobject
            "Subobject accessed before bound set": 0,
            "subobject bound set correctly": 0,
            "subobject bound set incorrectly": 0,
            # annotation check
            "Capability Incorrect Bounds":0,
            "Capability Correct Bounds":0,
            # candperm
            "candperm": 0,
            "candperm for on stack argument": 0,
            "candperm matches": 0,
            "Not in function when encountering candperm":0,
            "csetbounds for andperm pending":0,
            # cmove
            "cmove": 0,
            "Subobject allocation": 0,
            "cjalr": 0,
            "return capability": 0
        }

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

        self.out = sys.stdout
        """Output file stream"""

        if self.config.outfile:
            self.out = tempfile.NamedTemporaryFile(mode="w")

        self.update_config(self.config)

    def _update_result(self, result_key):
        # update the result if the current function matches the filter
        if result_key not in self.result:
            raise ValueError("key not in self.result")
        if self.config.function_name:
            if not self.current_function_dwarf:
                return
            elif self.current_function_dwarf.function_name != self.config.function_name:
                return
        self.result[result_key] += 1

    def _process_cjalr(self, inst, entry):
        # check return value capability
        return_addr = inst.op0.value.base + inst.op0.value.offset
        obj_file = self.symbol_table.find_object_file(return_addr)
        if not obj_file:
            prRed("Function capability not pointing to any object file")
            self._update_result(result_key="unknown return address")
        else:
            # return value 
            return_cap = capability()
            return_cap.base = str(hex(inst.op0.value.base))
            return_cap.offset = str(hex(inst.op0.value.offset))
            return_cap.cursor = str(hex(return_addr))
            return_cap.length = inst.op0.value.length
            return_cap.top = str(hex(inst.op0.value.base + inst.op0.value.length))
            return_cap.sealed = not inst.op0.value.unsealed
            self._update_result(result_key="return capability")
            if self.symbol_table.extracted_info["object_file_boundaries"][obj_file].check_in_bound(return_cap):
                self._update_result(result_key="return capability with correct bound")
            else:
                # raise ValueError("cjalr return address with incorrect capability")
                self._update_result(result_key="return capability with incorrect bound")
        # check destination value capability 
        sym_addr = inst.op1.value.base + inst.op1.value.offset
        # ignore jumps to kernel
        if sym_addr >= self.kernel_space_address_min:
            return
        symbol_info = self.symbol_table.find_symbol_at_addr(sym_addr)
        print(symbol_info)
        if symbol_info:
            first_k = None
            if isinstance(symbol_info, dict):
                first_k = next(iter(symbol_info))
                symbol_info = symbol_info[first_k]
                prGreen("<<<<<<<<<<<<<<<<<<<Call to {} function>>>>>>>>>>>>>>>>>>>>>".format(first_k))
            else:
                prGreen("<<<<<<<<<<<<<<<<<<<Call to Unknown function>>>>>>>>>>>>>>>>>>>>>")
            # check that the return value is of section size
            cap = capability()
            cap.base = str(hex(inst.op1.value.base))
            cap.offset = str(hex(inst.op1.value.offset))
            cap.cursor = str(hex(sym_addr))
            cap.length = inst.op1.value.length
            cap.top = str(hex(inst.op1.value.base + inst.op1.value.length))
            cap.sealed = not inst.op1.value.unsealed
            r = check_bound(cap, symbol_info, self.symbol_table.extracted_info["object_file_boundaries"], first_k if first_k else "unknown")
            self._update_result(result_key="cjalr")
            if r:
                self._update_result(result_key="cjalr with correct capability")
                return
            else:
                self._update_result(result_key="cjalr with incorrect capability")
                # raise ValueError("cjalr with incorrect capability")
        else:
            self._update_result(result_key="cjalr to unknown address")

    def _process_cjr(self, inst, entry):
        # if the this cjr is indeed within the current function, the function is returning
        # if the pending setbounds capabilities dictionaries are non-empty, report
        if self.current_function_dwarf:
            # clear the aggregate variable capabilities
            assert len(self.current_function_dwarf.setbound_pending_capabilities) == 0
            assert len(self.current_function_dwarf.andperm_pending_capabilities) == 0
            self.current_function_dwarf.cap_table_register = dict()
            self.current_function_dwarf.aggregate_variable_capabilities = dict()
            self.current_function_dwarf.setbound_pending_subobject_capabilities = dict()
            self.current_function_dwarf.andperm_pending_capabilities = dict()

    def _process_creadhwr(self, inst, entry):
        if inst.op1.name == "chwr_userlocal":
            # TLS accesses is done by reading a capability from the userlocal hwr which
            # provides a capability to access the TLS
            addr = inst.op0.value.base + inst.op0.value.offset
            self.tls_access[str(hex(addr))] = entry.pc 
            cap = capability()
            cap.base = str(hex(inst.op0.value.base))
            cap.offset = str(hex(inst.op0.value.offset))
            cap.cursor = str(hex(addr))
            cap.length = inst.op0.value.length
            cap.top = str(hex(inst.op0.value.base + inst.op0.value.length))
            cap.sealed = not inst.op0.value.unsealed
            self.tls_access[str(hex(addr))] = entry.pc 
            self.tls_register[inst.op0.name] = cap

    def _process_cgetpccincoffset(self, inst, entry):
        """ 
        with the current implementation, global variable accesses
        are mostly done by a cgetpccincoffset and clcbi, here, 
        we perform a check on the resulting register value to 
        confirm that it is pointing to a captable section of 
        some DSO
        """
        captable_addr = inst.op0.value.base + inst.op0.value.offset
        self._update_result(result_key="cgetpccincoffset")
        print("Is cgetpccincoffset")
        # find the corresponding captable in some object file
        objfile_path, section_info = self.symbol_table.find_cap_table(captable_addr)
        if objfile_path:
            # if the capability is pointing to a captable section, we store the address
            # of this register and check that the register still has the same value in
            # later accesses
            self._update_result(result_key="point to captable")
            if self.current_function_dwarf:
                self.current_function_dwarf.cap_table_register[inst.op0.name] = captable_addr
                prCyan("{} added to cap_table_register set".format(inst.op0.name))
            else:
                raise ValueError("Not in function when loading from captable")
        else:
            self._update_result(result_key="not point to captable")
            raise ValueError("Address {} is not pointing to any captable".format(str(hex(captable_addr))))

    def _process_candperm(self, inst, entry):
        self._update_result(result_key="candperm")
        if inst.op0.name == "c13":
            if self.current_function_dwarf:
                self._update_result(result_key="candperm for on stack argument")
                cap_register = inst.op1.name
                if cap_register in self.current_function_dwarf.andperm_pending_capabilities:
                    self._update_result(result_key="candperm matches")                    
                    print("match")
                    print(self.current_function_dwarf.andperm_pending_capabilities)
                    del self.current_function_dwarf.andperm_pending_capabilities[cap_register]
                else:
                    self._update_result(result_key="candperm mesmatches")
                    print("mismatch")
                    print(self.current_function_dwarf.andperm_pending_capabilities)
            else:
                self._update_result(result_key="Not in function when encountering candperm")
                raise ValueError("Not in function when encountering candperm")

    def _print_ops(self, inst):
        result = ""
        if inst.op0:
            result += " OP0: {}".format(inst.op0)
        if inst.op1:
            result += " OP1: {}".format(inst.op1)
        if inst.op2:
            result += " OP2: {}".format(inst.op2)
        if inst.op3:
            result += " OP3: {}".format(inst.op3)
        print(result)

    def _process_cmove(self, inst, entry):
        """
        when there is a copy of stack pointer record that, may be used for stack argument
        """
        self._update_result(result_key="cmove")
        # self._print_ops(inst)
        # if inst.op1.name == "c11" and inst.op0.name != "c24":
        #     input()

    def _process_csetbounds(self, inst, entry):
        """
        when there is a setbounds on the frame pointer(c24), 
        this is likely trying to access the vp_list pointer on the stack
        raise an exception
        """
        self._update_result(result_key="csetbounds")
        if inst.op0.name != inst.op1.name:
            # csetbounds for on-stack arguments can be done via $cx $c11 <value>
            # later candperm, moves $cx to $13
            if inst.op1.name == "c11":
                if self.current_function_dwarf:
                    cap_register = inst.op0.name
                    if cap_register not in self.current_function_dwarf.andperm_pending_capabilities:
                        self._update_result(result_key="csetbounds for andperm pending")
                        self.current_function_dwarf.andperm_pending_capabilities[cap_register] = (entry.pc)
                        print( self.current_function_dwarf.andperm_pending_capabilities)
                    else:
                        raise ValueError("cap register already in andperm pending list")
            return
        else:
            if self.current_function_dwarf:
                cap_register = inst.op0.name
                if cap_register in self.current_function_dwarf.setbound_pending_subobject_capabilities:
                    variable, m, pc = self.current_function_dwarf.setbound_pending_subobject_capabilities[cap_register]
                    expected_size = m.size
                    if inst.op2.value == expected_size:
                        self._update_result(result_key="subobject bound set correctly")
                        k = self.current_function_dwarf.function_name + ":" + variable.variable_name + ":" + m.name
                        # assert k in self.found_subobject_access
                        # assert len(self.found_subobject_access[k]) != 0
                        # assert len(self.found_subobject_access[k][-1]) == 1
                        # self.found_subobject_bounds_set[k][-1].append(str(hex(entry.pc)))
                        # prGreen("csetbounds sets {}(capability to access member {} in {}) to expected size: {}".format(
                        #     inst.op0.name, m.name, parameter.variable_name, inst.op2.value))
                    else:
                        self._update_result(result_key="subobject bound set incorrectly")
                        prRed("csetbounds fails to set {} to expected size: {}, actual size: {}".format(
                            inst.op0.name, inst.op2.value, expected_size))
                    del self.current_function_dwarf.setbound_pending_subobject_capabilities[cap_register]
                

    def _process_cincoffset(self, inst, entry):
        """
        when there is a cincoffset on a capability that is known to be pointing to 
        a struct on the stack or in global storage, the cincoffset is likely a subobject access
        """
        if self.current_function_dwarf:
            cap_reg_str = inst.op1.name
            # if the cincoffset instruction tries to increase the offset of a capability known to be pointign to an aggregate variable
            if cap_reg_str in self.current_function_dwarf.aggregate_variable_capabilities:
                # fetch information about that variable
                parameter = self.current_function_dwarf.aggregate_variable_capabilities[cap_reg_str]
                offset = inst.op2.value
                prGreen("variable: {}, offset: {}".format(parameter, str(offset)))
                # Assertion: if the variable is an aggregate type, it should have non-None members field 
                assert parameter.members is not None
                # iterate through all members, see which one it is accessing
                for m in parameter.members:
                    if offset == m.offset:
                        self._update_result(result_key="Subobject allocation")
                        prGreen("Access to member: {} at offset: {}".format(m.name, str(m.offset)))
                        k = self.current_function_dwarf.function_name + ":" + parameter.variable_name + ":" + m.name
                        if k not in self.found_subobject_access:
                            self.found_subobject_access[k] = []
                        # when subobject bound is not enabled, comment this out, 
                        #   as it is never possible to find pairing cincoffset and csetbounds for subobject
                        # if len(self.found_subobject_access[k]) > 0:
                        #     assert(len(self.found_subobject_access[k][-1]) == 2)
                        
                        # record the pc when this subobject access is found
                        self.found_subobject_access[k].append(str(hex(entry.pc)))
                        # store the variable and the member that is being accessed by this cincoffset
                        self.current_function_dwarf.setbound_pending_subobject_capabilities[inst.op0.name] = (parameter, m, entry.pc) 

    def _process_clcbi(self, inst, entry):
        # if the instruction used a previous cap_table_register,
        # it is an access to global variable
        self._update_result(result_key="clcbi")
        # if this is a captable access, this address should point to a captable
        base_capability_addr = inst.op2.value.base + inst.op2.value.offset
        # in purecap mode, all these should be accessed from the captable?
        objfile_path, section_info = self.symbol_table.find_cap_table(base_capability_addr)
        # if the capability is pointing to the .captable section, it is a global variable 
        # access, and we can proceed to check the capability
        if objfile_path:
            prGreen(self.current_function_dwarf.cap_table_register)
            # sanity check, if the base capability matches the capability value previously
            # loaded via cgetpccincoffset
            if inst.op2.name in self.current_function_dwarf.cap_table_register:
                if base_capability_addr == self.current_function_dwarf.cap_table_register[inst.op2.name]:
                    self._update_result(result_key="pass sanity check")
                else:
                    self._update_result(result_key="fail sanity check")
                    prYellow("Expected: {}, Actual: {}".format(self.current_function_dwarf.cap_table_register[inst.op2.name], base_capability_addr))
            else:
                if entry.pc < self.kernel_space_address_min:                    
                    self._update_result(result_key="base not created with getpccincoffset")
                    # raise ValueError("base not created with getpccincoffset")
            self._update_result(result_key="clcbi from captable")
            """Checking the capability used to access the captable is having the correct bound"""
            expected_captable_size = section_info.get_size()
            if inst.op2.value.length != expected_captable_size:
                self._update_result(result_key="load from captable with incorrect bound")
            else:
                self._update_result(result_key="load from captable with correct bound")
            # the base pointer is pointing to the captable
            # look up the address of the loaded cap register in the symbol table
            object_addr = inst.op0.value.base + inst.op0.value.offset
            symbol_info = self.symbol_table.find_symbol_at_addr(object_addr)
            cap = capability()
            cap.base = str(hex(inst.op0.value.base))
            cap.offset = str(hex(inst.op0.value.offset))
            cap.cursor = str(hex(object_addr))
            cap.length = inst.op0.value.length
            cap.top = str(hex(inst.op0.value.base + inst.op0.value.length))
            cap.sealed = not inst.op0.value.unsealed
            # TODO: add permissions, otype etc if necessary
            # try to find the object file pointed to by this capability
            objectfile_path = find_object_file(self.symbol_table.extracted_info["object_file_boundaries"], cap)
            if not objectfile_path:
                # this is particularly interesting if we are looking for corrupted value in registers
                # and checking capabilities pointing to TLS storage and PLT, 
                # and their may be bugs of the trace or qemu exposed if the capability is not pointing to any
                # of these
                self._update_result(result_key="Out of Bounds")
                if cap.cursor not in self.out_of_bounds_access:
                    self.out_of_bounds_access[cap.cursor] = 1
                else:
                    self.out_of_bounds_access[cap.cursor] += 1
            elif symbol_info:
                if isinstance(symbol_info, dict):
                    first_k = next(iter(symbol_info))
                    symbol_info = symbol_info[first_k]
                    prGreen(symbol_info)
                    prYellow(cap)
                    r = check_bound(cap, symbol_info, self.symbol_table.extracted_info["object_file_boundaries"], first_k)
                    if symbol_info.expected_type.value == symbol_type.FUNC.value:
                        self._update_result(result_key="Function")
                    elif symbol_info.expected_type.value == symbol_type.OBJECT.value:
                        self._update_result(result_key="Object")
                    else:
                        self._update_result(result_key="Notype")
                    if r:
                        self._update_result(result_key="Pass")
                    else:
                        self._update_result(result_key="Fail")
                        prRed("{} at {}, Expected size: {}, Actual size: {}, Type: {}".format(
                            first_k, 
                            cap.cursor,
                            symbol_info.expected_size, 
                            cap.length, 
                            symbol_info.expected_type))
                else:
                    prGreen(symbol_info)
                    prYellow(cap)
                    r = check_bound(cap, symbol_info, self.symbol_table.extracted_info["object_file_boundaries"])
                    if symbol_info.expected_type.value == symbol_type.FUNC.value:
                        self._update_result(result_key="Function_unknown")
                    elif symbol_info.expected_type.value == symbol_type.OBJECT.value:
                        self._update_result(result_key="Object_unknown")
                    else:
                        self._update_result(result_key="Notype_unknown")
                    if r:
                        self._update_result(result_key="Pass")
                    else:
                        self._update_result(result_key="Fail")
                        prRed("Unknown symbol at {}, Expected size: {}, Actual size: {}, Type: {}".format(
                            cap.cursor, 
                            symbol_info.expected_size,
                            cap.length,
                            symbol_info.expected_type))
            else:
                prRed("Could not find symbol with address {}".format(str(hex(object_addr))))
                str_addr = str(hex(object_addr))
                if str_addr not in self.violation_record:
                    self.violation_record[str_addr] = 0
                self.violation_record[str_addr] += 1
                self._update_result(result_key="Fail")
        else:
            if base_capability_addr not in self.violation_record:
                self.violation_record[base_capability_addr] = 0
            self.violation_record[base_capability_addr] += 1 
            self._update_result(result_key="clcbi not from captable")
            prRed("\"clcbi\" Not loading from captable")
        # prGreen(self.result)
        # prCyan(self.out_of_bounds_access)
        # prYellow(self.tls_access)

    def update_config(self, config):
        self._entry_history = deque([], config.before)
        self._dump_next = 0
        self._kernel_mode = False

    def repr_register(self, entry):
        if (entry.gpr_number() != -1):
            return "$%d" % entry.gpr_number()
        elif (entry.capreg_number() != -1):
            return "$c%d" % entry.capreg_number()

    def interact(self):
        if self.config.step_over:
            input()

    def check_capability_length(self, symbol: str, expected_size: int, cap: CheriCap):
        if expected_size < 4096:
            if cap.length != expected_size:
                print("> {} SIZE & BOUND MISMATCH -> Expacted: {}, Actual: {}".format(symbol, str(expected_size), str(cap.length)))
                print("> {}".format(str(cap)))
                return False
            else:
                return True
        else:
            ls_zeroes = compute_num_ls_zeroes(cap.length)
            mask = "1" * ls_zeroes
            error = 0
            if int(mask, 2) & cap.base:
                print("> {} Base violates alignment requirement.".format(symbol))
                error = 1
            if int(mask, 2) & (cap.base + cap.length):
                print("> {} Top violates alignment requirement.".format(symbol))
                error = 1
            if expected_size > cap.length:
                print("> {} Too strictive bound.".format(symbol))
                error = 1
            if abs(expected_size - cap.length) > int(mask, 2):
                print("> {} Bound is not minimal.".format(symbol))
                error = 1
            if error:
                print("> Alignment mask: {}, Expected: {}, Actual: {}".format(mask, str(expected_size), str(cap.length)))
                print("> {}".format(str(cap)))
                return False
            else:
                return True

    def dump_cap(self, cap):
        chericap = CheriCap(cap)
        return str(chericap)

    def check_variable_bound(self, inst, entry, regs, parameter):
        """
        function to check all variables in scope against the instruction
        being executed 
        """
        for loc in parameter.locations:
            if loc.type.value == dwarf_stack_variable_location_type.LOC_UNHANDLED.value:
                continue
            elif loc.type.value == dwarf_stack_variable_location_type.LOC_CAP_REGISTER.value:
                # a location type with LOC_CAP_REGISTER usually represents that the
                # variable is a pointer itself, and it is stored in a cap register
                if loc.cap_register == "unknown":
                    continue
                # we are not interested in capability stored in cap register itself
                # but we print it out to inspect the content
                if loc.lowpc <= entry.pc < loc.highpc - 4:
                    cap_index = int(loc.cap_register[1:])
                    prGreen("(lowpc: %s, highpc: %s, current pc: %s)[%d] $c%d = %s\n" % (
                        str(hex(loc.lowpc)), str(hex(loc.highpc)), str(hex(entry.pc)),
                        regs.valid_caps[cap_index], cap_index,
                        self.dump_cap(regs.cap_reg[cap_index])))
                    if parameter.annotation:
                        # self.interact()
                        cap = CheriCap(regs.cap_reg[cap_index])
                        result = self.check_capability_length(parameter.variable_name, parameter.annotation.expected_length, cap)
                        if not result:
                            parameter.annotation.counter_wrong += 1
                            prRed("Variable: {} has the incorrect length: Expected {}, Actual: {}".format(parameter, parameter.annotation.expected_length, cap.length))
                            self.log_f.write("pc: {}, variable: {}, expected_size: {}, cap: {}\n".format(str(hex(entry.pc)), parameter,  parameter.annotation.expected_length, str(cap)))
                            self._update_result("Capability Incorrect Bounds")
                        else:
                            parameter.annotation.counter_correct += 1
                            prGreen("Variable: {} has the correct length: {}".format(parameter, cap.length))
                            self._update_result("Capability Correct Bounds")
                        # raise ValueError("Parameter: {} has annotation: {}".format(parameter, parameter.annotation))
                    
            elif loc.type.value == dwarf_stack_variable_location_type.LOC_CAP_OFFSET.value:
                """ a location type with LOC_CAP_OFFSET works for any variables or parameters
                that are at some specific offset from the stack pointer
                the content may be accessed by deriving a capability from the stack pointer
                and then perform a set bounds on the derived capability
                we are not interested in the value of the variable stored on the stack
                but we want to check the capability used to access that variable
                this can be done by scanning for a cincoffset and a csetbounds in the 
                given range
                if the location type is LOC_CAP_OFFSET, and that entry.pc is within the 
                range of lowpc and highpc inclusively when entry.pc is equal to lowpc, 
                the instruction should be a cincoffset that increases the offset of the 
                STACK POINTER c11 by some amount equal to the offset specified in the 
                parameter information this destination capability of the csetbound is 
                then added to the lookup table together with the expected bound of the 
                capability a violation should be reported if a load is performed on a 
                capability in the lookup table which is waiting for a csetbounds the 
                capability is removed from the lookup table when entry.pc equals to
                the highpc of the range, when it is removed from the list, we also want
                to report the number of instructions in which it is having the incorrect bound
                the number of instructions having the correct bound"""
                # stack variable accesses are done by offsetting from the stack pointer c11, drop any others
                if loc.cap_register != "c11":
                    continue
                # when the location expression is within scope
                if loc.lowpc <= entry.pc < loc.highpc - 4:
                    # if the current instruction is a cincoffset, 
                    # check whether this is a cincoffset to increace the offset from c11 and generating a capability(except c11)
                    if inst.opcode == "cincoffset":
                        prGreen(self.current_function_dwarf.setbound_pending_capabilities)
                        # the destination shoud not be the stack pointer or the frame pointer
                        # the source should be the stack pointer OR the frame pointer
                        if inst.op0.name not in ["c11", "c24"] and (inst.op1.name == "c11" or inst.op1.name == "c24"):
                            prGreen("cincoffset from stack pointer by {}, expected: {}".format(inst.op2.value, loc.offset))
                            # if the offset increased is identical to the offset known from dwarf
                            # this matches the parameter, and we add it to the lookup table
                            if inst.op2.value == loc.offset:
                                self._update_result(result_key="Found Stack Allocation")
                                k = self.current_function_dwarf.function_name + ":" + parameter.variable_name
                                if k not in self.found_stack_allocation:
                                    self.found_stack_allocation[k] = []
                                if len(self.found_stack_allocation[k]) != 0:
                                    # assert len(self.found_stack_allocation[k][-1]) == 2
                                    pass
                                self.found_stack_allocation[k].append([str(hex(entry.pc))])
                                prGreen("{} stores the capability pointing to {}".format(inst.op0.name, parameter.variable_name))
                                if inst.op0.name not in self.current_function_dwarf.setbound_pending_capabilities:
                                    self.current_function_dwarf.setbound_pending_capabilities[inst.op0.name] = (parameter, entry.pc)
                                else:
                                    pass
                    elif inst.opcode == "csetbounds":
                        # a csetbounds for stack variable is usually in the form of "csetbounds $c* $c* bound"
                        # here, we only care about setbounds that can be associated with a previous cincoffset
                        prGreen(self.current_function_dwarf.setbound_pending_capabilities)
                        if self.current_function_dwarf:
                            # csetbounds on the capability register itself is shrinking its own bounds
                            if inst.op0.name == inst.op1.name:
                                # if the capability is in the pending lookup table
                                if inst.op0.name in self.current_function_dwarf.setbound_pending_capabilities:
                                    self._update_result(result_key="csetbounds for stack allocation")
                                    parameter, pc = self.current_function_dwarf.setbound_pending_capabilities[inst.op0.name]
                                    expected_size = parameter.size
                                    k = self.current_function_dwarf.function_name + ":" + parameter.variable_name
                                    cap_index = int(inst.op0.name[1:])
                                    cap = CheriCap(regs.cap_reg[cap_index])
                                    result = self.check_capability_length(parameter.variable_name, expected_size, cap)
                                    if result:
                                        self._update_result(result_key="Stack Bound Set Correctly")
                                        prGreen("csetbounds sets {}(capability to access {}) to expected size: {}".format(inst.op0.name, parameter.variable_name, inst.op2.value))
                                        if parameter.type.value in [dwarf_variable_data_type.VAR_TYPE_STRUCT.value, dwarf_variable_data_type.VAR_TYPE_UNION.value, dwarf_variable_data_type.VAR_TYPE_CLASS.value]:
                                            self._update_result(result_key="Taking pointer to aggregate type")
                                            self.current_function_dwarf.aggregate_variable_capabilities[inst.op0.name] = parameter
                                    else:
                                        self._update_result(result_key="Stack Bound Set Incorrectly")
                                        prRed("csetbounds fails to set {} to expected size: {}, actual size: {}".format(inst.op0.name, expected_size, inst.op2.value))
                                    assert k in self.found_stack_allocation
                                    assert len(self.found_stack_allocation[k]) != 0
                                    assert len(self.found_stack_allocation[k][-1]) == 1
                                    self.found_stack_allocation[k][-1].append(str(hex(entry.pc)))
                                    del self.current_function_dwarf.setbound_pending_capabilities[inst.op0.name]
                                else:
                                    prRed("Unknown csetbounds: {}".format(inst))
                            else:
                                prRed("Unknown csetbounds: {}".format(inst))
                        else:
                            raise ValueError("csetbounds encounters when not in function")

    
    def check_accessed_before_setbounds(self, inst, entry):
        """
        called after the instruction is processed
        if any capability register waiting for csetbounds is used, record unbounded access and remove it from the waitlist
        """       
        result = False
        to_remove = []
        # prGreen(self.current_function_dwarf.setbound_pending_capabilities)
        for cap in self.current_function_dwarf.setbound_pending_capabilities:
            parameter, pc = self.current_function_dwarf.setbound_pending_capabilities[cap]
            prYellow("capability inserted at pc: {}, current pc: {}".format(str(hex(pc)), str(hex(entry.pc))))
            # skip the check since the entry of lookup table is just inserted by the current instruction
            if int(pc) == int(entry.pc):
                continue
            # if the capability register is used for load/store/dereference of some instruction, insert into the list, later remove all together
            if (inst.op0 and inst.op0.name == cap) or (inst.op1 and inst.op1.name == cap) or (inst.op2 and inst.op2.name == cap) or (inst.op3 and inst.op3.name == cap):
                prRed("capability register {} accessed before setbounds".format(cap))
                to_remove.append(cap)
                result = True
        for to_r in to_remove:
            # avoid double counting, check if the cap is still in the lookup table
            if to_r in self.current_function_dwarf.setbound_pending_capabilities:
                del self.current_function_dwarf.setbound_pending_capabilities[to_r]
                self._update_result(result_key="Accessed before bound set")
        to_remove = []
        # prGreen(self.current_function_dwarf.setbound_pending_subobject_capabilities)
        for cap in self.current_function_dwarf.setbound_pending_subobject_capabilities:
            variable, m, pc = self.current_function_dwarf.setbound_pending_subobject_capabilities[cap]
            # skip the check since the entry of lookup table is just inserted by the current instruction
            prYellow("capability inserted at pc: {}, current pc: {}".format(str(hex(pc)), str(hex(entry.pc))))
            # skip the check since the entry of lookup table is just inserted by the current instruction
            if int(pc) == int(entry.pc):
                continue
            # if the capability register is used for load/store/dereference of some instruction, report
            if (inst.op0 and inst.op0.name == cap) or (inst.op1 and inst.op1.name == cap) or (inst.op2 and inst.op2.name == cap) or (inst.op3 and inst.op3.name == cap):
                prRed("capability register {} accessed before setbounds".format(cap))
                result = True
                to_remove.append(cap)
        for to_r in to_remove:
            # avoid double counting, check if the cap is still in the lookup table
            if to_r in self.current_function_dwarf.setbound_pending_subobject_capabilities:
                del self.current_function_dwarf.setbound_pending_subobject_capabilities[to_r]
                self._update_result(result_key="Subobject accessed before bound set")

        to_remove = []
        # prGreen(self.current_function_dwarf.setbound_pending_subobject_capabilities)
        for cap in self.current_function_dwarf.andperm_pending_capabilities:
            pc = self.current_function_dwarf.andperm_pending_capabilities[cap]
            # skip the check since the entry of lookup table is just inserted by the current instruction
            prYellow("pending and perm capability inserted at pc: {}, current pc: {}".format(str(hex(pc)), str(hex(entry.pc))))
            # skip the check since the entry of lookup table is just inserted by the current instruction
            if int(pc) == int(entry.pc):
                continue
            # if the capability register is used for load/store/dereference of some instruction, report
            if (inst.op0 and inst.op0.name == cap) or (inst.op1 and inst.op1.name == cap) or (inst.op2 and inst.op2.name == cap) or (inst.op3 and inst.op3.name == cap):
                prRed("capability register {} accessed before andperm".format(cap))
                result = True
                to_remove.append(cap)
        for to_r in to_remove:
            # avoid double counting, check if the cap is still in the lookup table
            if to_r in self.current_function_dwarf.andperm_pending_capabilities:
                del self.current_function_dwarf.andperm_pending_capabilities[to_r]
                self._update_result(result_key="andperm_pending_capability accessed before andperm")
        return result

    def check_jumps(self, inst, entry):
        # when there is a jump, the pc difference between two consecutive instructions will differ
        # by more than 4 bytes, trigger a switch of dwarf_func
        if self.previous_pc:
            # this is the first instruction that is ever run
            if abs(entry.pc - self.previous_pc) > 4:
                self._update_result(result_key="jump detected")
                prCyan("Prev: PC: {}, Current PC: {}".format(str(hex(self.previous_pc)), str(hex(entry.pc))))
                if entry.pc < self.kernel_space_address_min:
                    # only look up the function if the pc value is in user space
                    tree_node = self.dwarf.find_function_by_addr(entry.pc)
                    # if we can find the function we are jumping to, update the current function dwarf info
                    if tree_node:
                        dg = tree_node.val
                        prGreen(dg)
                        self._update_result(result_key="dwarf-known jump")
                        self.current_func_lowpc = dg.lowpc
                        self.current_func_highpc = dg.highpc
                        self.current_function_dwarf = dg
                        prGreen("Current function lowpc: {}, highpc: {}".format(str(hex(dg.lowpc)), str(hex(dg.highpc))))
                        prCyan("Jump to {}".format(dg))
                    else:
                        self._update_result(result_key="dwarf-unknown jump")
                        # record the unknown jumps, these jump locations are not known by dwarf and
                        # should only be the PLT stubs
                        addr_str = str(hex(entry.pc))
                        prRed("Fail to find address {}".format(addr_str))
                        # we only care about unknown jumps to non-kernel space
                        if addr_str not in self.unknown_jump_address:
                            self.unknown_jump_address[addr_str] = 1
                        else:
                            self.unknown_jump_address[addr_str] += 1
                        self.current_func_highpc = None
                        self.current_func_lowpc = None
                        self.current_function_dwarf = None
                else:
                    # if jumps into kernel space, set everything to None
                    self.current_func_highpc = None
                    self.current_func_lowpc = None
                    self.current_function_dwarf = None
        self.previous_pc = entry.pc


    def lookup_current_function(self, entry):
        tree_node = self.dwarf.find_function_by_addr(entry.pc)
        if tree_node:
            dg = tree_node.val
            self.current_func_lowpc = dg.lowpc
            self.current_func_highpc = dg.highpc
            self.current_function_dwarf = dg
            prGreen("Current function lowpc: {}, highpc: {}".format(str(hex(dg.lowpc)), str(hex(dg.highpc))))
                

    def dump_regs(self, inst, entry, regs, last_regs):
        if not self.current_function_dwarf:
            self.lookup_current_function(entry)
        if self.current_function_dwarf:
            prYellow("Current function: {}".format(self.current_function_dwarf))
            # prGreen("Checking arguments")
            for p in self.current_function_dwarf.parameters:
                # prGreen("Checking {}".format(p))
                self.check_variable_bound(inst, entry, regs, p)
            # prGreen("Checking variables")
            for v in self.current_function_dwarf.variables:
                # prGreen("Checking {}".format(p))
                self.check_variable_bound(inst, entry, regs, v)
            self.check_accessed_before_setbounds(inst, entry)
            # if self.check_accessed_before_setbounds(inst, entry):
            #     print(self.current_function_dwarf.setbound_pending_capabilities)
            #     print(self.current_function_dwarf.setbound_pending_subobject_capabilities)
        # for idx in range(0,31):
            # real_regnum = idx + 1
            # self.out.write("[%d] $%d = %x\n" % (
            #     regs.valid_gprs[idx],
            #     real_regnum,
            #     regs.gpr[idx]))
        # for idx in range(0,32):
            # self.out.write("[%d] $c%d = %s\n" % (
            #     regs.valid_caps[idx], idx,
            #     self.dump_cap(regs.cap_reg[idx])))

    def remove_from_lookup_tables_on_update(self, entry, register_name):
        """
        remove a register from the cap_table register and aggregate_variable lookup tables
        """
        # if a cap register has been used as a cap_table_register
        # remove it since its content has been overwritten
        # we do not remove it from the map if it is in the exception handler
        if self.current_function_dwarf:
            if entry.pc < self.kernel_space_address_min:
                if register_name in self.current_function_dwarf.cap_table_register:
                    prGreen("{} removed from cap_table_register set".format(register_name))
                    del self.current_function_dwarf.cap_table_register[register_name]
                if register_name in self.current_function_dwarf.aggregate_variable_capabilities:
                    prGreen("{} removed from aggregate_variable_capabilities".format(register_name))
                    del self.current_function_dwarf.aggregate_variable_capabilities[register_name]

    def dump_instr(self, inst, entry, idx):
        # self.out.write(str(inst))
        if entry.exception != 31:
            exception = "except:%x" % entry.exception
        else:
            # no exception
            exception = ""
        instr_dump = "{%d:%d} 0x%x %s %s" % (
            entry.asid, entry.cycles, entry.pc, inst.inst.name, exception)

        self.out.write(instr_dump)
        self.out.write("\n")
        # dump read/write
        if inst.cd is None:
            # no operands for the instruction
            return
        # if there is a jump in pc value, update the current_function_dwarf
        self.check_jumps(inst, entry)
        if entry.is_load or entry.is_store:
            sym = self.sym_reader.find_symbol(entry.memory_address)
            if sym:
                loc = "[%x (%s)]" % (entry.memory_address, sym)
            else:
                loc = "[%x]" % entry.memory_address
            if entry.is_load:
                # loading from a memory address to a register
                self.out.write("$%s = %s\n" % (inst.cd.name, loc))
                self.remove_from_lookup_tables_on_update(entry, inst.cd.name)
            else:
                self.out.write("%s = $%s\n" % (loc, inst.cd.name))
        
        if inst.opcode in ["cincoffset", "cmove", "candperm", "cincoffsetimm", "creadhwr", "csetoffset"]:
            self.remove_from_lookup_tables_on_update(entry, inst.cd.name)

        if inst.op0.is_register:
            if (inst.op0.gpr_index != -1):
                gpr_value = inst.op0.value
                gpr_name = inst.op0.name
                if gpr_value is not None:
                    self.out.write("$%s = %x\n" % (gpr_name, gpr_value))
                else:
                    self.out.write("$%s = Unknown\n" % gpr_name)
            elif (inst.op0.cap_index != -1 or inst.op0.caphw_index != -1):
                cap_name = inst.op0.name
                cap_value = inst.op0.value
                if cap_value is not None:
                    self.out.write("$%s = %s\n" % (
                        cap_name, self.dump_cap(cap_value)))
                else:
                    self.out.write("$%s = Unknown\n" % cap_name)
                symbol_info = None
        
        # the jump destination of cjalr and cjr should be of DSO size
        if inst.opcode == "cjalr":
            self._process_cjalr(inst, entry)
        elif inst.opcode == "cmove":
            self._process_cmove(inst, entry)
        elif inst.opcode == "cjr":
            self._process_cjr(inst, entry)            
        elif inst.opcode == "jalr" or inst.opcode == "jr":
            sym_addr = inst.op0.value
            symbol_info = self.symbol_table.find_symbol_at_addr(sym_addr)
        elif inst.opcode == "creadhwr":
            self._process_creadhwr(inst, entry)
        elif inst.opcode == "cgetpccincoffset":
            self._process_cgetpccincoffset(inst, entry)
        elif inst.opcode == "csetbounds":
            self._process_csetbounds(inst, entry)
        elif inst.opcode == "clcbi":
            self._process_clcbi(inst, entry)
        elif inst.opcode == "candperm":
            self._process_candperm(inst, entry)
        elif inst.opcode == "clc":
            """Checking the source of the capabilities"""
            # we want to collect the stats related to the source cap register
            # where they are pointing to, our assumption is that it can be a
            # mix of different things
            if inst.op3.value:                
                src_address = inst.op3.value.base + inst.op3.value.offset
                rt = inst.op1.value
                offset = inst.op2.value
                load_src = src_address + offset + rt
                self._update_result(result_key="clc")
                # check if the clc is loading from any of the captables, though very unlikely
                objfile_path, section_info = self.symbol_table.find_cap_table(load_src)
                if objfile_path:
                    if src_address <= self.kernel_space_address_min:
                        self._update_result(result_key="clc from captable")
                else:
                    src_addr_str = str(hex(src_address))
        elif inst.opcode == "clcr":
            # clcr is never encountered in helloworld and not processed in this prototype
            self._update_result(result_key="clcr")
        elif inst.opcode == "clci":
            # clci is never encountered in helloworld and not processed in this prototype
            self._update_result(result_key="clci")
        elif inst.opcode == "cincoffset":
            self._process_cincoffset(inst, entry)

        

    def dump_kernel_user_switch(self, entry):
        if self._kernel_mode != entry.is_kernel():
            if entry.is_kernel():
                self.out.write("Enter kernel mode {%d:%d}\n" % (
                    entry.asid, entry.cycles))
            else:
                self.out.write("Enter user mode {%d:%d}\n" % (
                    entry.asid, entry.cycles))
            self._kernel_mode = entry.is_kernel()

    def do_dump(self, inst, entry, regs, last_regs, idx):
        # dump instr
        self.dump_instr(inst, entry, idx)
        if self.config.show_regs:
            self.dump_regs(inst, entry, regs, last_regs)

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
        else:
            # return inst.opcode == "cgetpcc" or inst.opcode == "cgetpccincoffset" or inst.opcode == "clcbi" or inst.opcode == "cjalr" or inst.opcode == "creadhwr"
            # return inst.opcode == "cjalr"
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
                try:
                    self.do_dump(inst, entry, regs, last_regs, idx)
                except Exception as e:
                    logger.error("exception type: %s", e.__class__.__name__)
                    logger.error("Can not dump instruction %s: %s",
                                 inst, e)
                    raise
                    return True
                self._dump_next = self.config.after
            else:
                self._entry_history.append((inst, idx))
        return False

    def parse(self, start=None, end=None, direction=0):
        start = start or self.config.start
        end = end or self.config.end
        if self.config.info:
            self.out.write("Trace size: %s\n" % len(self))
        else:
            super().parse(start, end)
            # conclusion: out of bounds accesses are accesses into kernel space or plt stub
            print(self.out_of_bounds_access)
            print(self.tls_access)
            # conclusion: unknown jumps are usually into kernel space or plt stub or assembly functions not extracted
            print(self.unknown_jump_address)
            print(self.dwarf_unknown_cjalr_address)
            # conclusion: those cbcbi not loading from captable normally are due to corrupted addresses
            print(self.violation_record)
            print(self.found_stack_allocation)
            print(self.found_subobject_access)
            print(self.result)
            # pickle.dump(self.out_of_bounds_access, open("/root/out_of_bounds_access.pickle", "wb"))
            # pickle.dump(self.tls_access, open("/root/tls_access.pickle", "wb"))
            # pickle.dump(self.unknown_jump_address, open("/root/unknown_jump_address.pickle", "wb"))
            # pickle.dump(self.dwarf_unknown_cjalr_address, open("/root/dwarf_unknown_cjalr_address.pickle", "wb"))
            # pickle.dump(self.violation_record, open("/root/violation_record.pickle", "wb"))
            # pickle.dump(self.result, open("/root/result.pickle", "wb"))

    def mp_result(self):
        """Return the temporary file."""
        self.out.flush()
        return self.out.name

    def mp_merge(self, results):
        """Concatenate temporary files"""
        if self.config.outfile:
            with open(self.config.outfile, 'wb') as out:
                for in_file in results:
                    with open(in_file,'rb') as fd:
                        shutil.copyfileobj(fd, out, 1024*1024*50)


@interactive_tool(key="scan")
class PyCheriVerifyDriver(BaseTraceTaskDriver):

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

    scan = NestedConfig(CheriVerifyParser)
    symbols_path = Option(
        nargs="*",
        help="Path where to look for binaries in the vmmap, "
        "default is current directory.",
        default=["."])
    vmmap = NestedConfig(VMMapFileParser)
    threads = Option(
        type=int,
        default=1,
        help="Run the tool with the given number of workers")
    coredump = Option(
        "-C",
        type=str,
        default=None,
        help="Use the coredump file to perform capability validation"
    )
    executable = Option(
        "-E",
        type=str,
        default=None,
        help="Use the executable to perform capability validation"
    )

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.vmmap = VMMapFileParser(config=self.config.vmmap)
        self.vmmap.parse()
        self.symbols = SymReader(vmmap=self.vmmap,
                                 path=self.config.symbols_path)
        assert self.config.coredump and self.config.executable            
        object_file_boundaries_file = "/root/cheri/object_file_boundaries.pickle"
        section_info_file = "/root/cheri/section_info.pickle"
        dwarf_stack_executable_path = "/root/cheri-verify/dwarf_reader/read_stack"
        # run static analysis once to produce the object file mapping
        with Popen(["bash", "/root/cheri/cheriplot/cheriplot/cheriverify/static_analysis.sh",
                    self.config.executable, 
                    self.config.coredump], stdout=PIPE, stderr=PIPE, stdin=PIPE, text=True) as static_analysis_proc:
            prGreen("Performed static analysis")
            # err = static_analysis_proc.stderr.read()
        prGreen("Reading symbol table")
        self.symbol_table = symbol_table_reader(object_file_boundaries_file, section_info_file)
        # check the symbol table and ensure that object with the same address but different name will have the same size
        count_not_all_equal = 0
        for object_file, sym in self.symbol_table.extracted_info["symbol_table_from_object_files_address"].items():
            for addr, d_address in sym.items():
                if len(d_address) > 1:
                    common_len = None
                    not_all_equal = False
                    for name, symbol_i in d_address.items():
                        if not common_len:
                            common_len = symbol_i.expected_size
                        if common_len != symbol_i.expected_size:
                            not_all_equal = True
                    if not_all_equal:
                        prYellow(d_address)
                        count_not_all_equal += 1
        if count_not_all_equal:
            prRed("Conflicting symbol inforomation: {}".format(str(count_not_all_equal)))
        else:
            prGreen("Conflicting symbol inforomation: {}".format(str(count_not_all_equal)))

        # initialise the dwarf manager and extract dwarf information
        self.dwarf = dwarf_manager(object_file_boundaries_file, dwarf_stack_executable_path, self.symbol_table)
        self.parser = CheriVerifyParser(trace_path=self.config.trace,
                                      sym_reader=self.symbols,
                                      config=self.config.scan,
                                      threads=self.config.threads,
                                      symbol_table=self.symbol_table,
                                      dwarf=self.dwarf)
        

    def update_config(self, config):
        super().update_config(config)
        self.parser.update_config(config.scan)

    def run(self):
        self.parser.parse(self.config.scan.start, self.config.scan.end)
