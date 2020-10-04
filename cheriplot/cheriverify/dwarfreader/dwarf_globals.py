#-
# Copyright (c) 2016-2017 Yixing(Ethan) Zheng
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
import json
import sys
sys.path.append(r"/root/cheri/cheriplot/cheriplot/cheriverify/")
sys.path.append(r'/root/cheri/cheriplot/cheriplot/cheriverify/coredump')
sys.path.append(r'/root/cheri/cheriplot/cheriplot/cheriverify/dwarfreader')
sys.path.append(r'/root/cheri/cheriplot/cheriplot/cheriverify/')
from re import compile
from subprocess import Popen, PIPE, TimeoutExpired
from colour_print import prLightPurple, prRed, prGreen, prYellow
from dwarf_variable_type import dwarf_variable_data_type
from object_file_boundary import object_file_boundary
from symbol_table_reader import symbol_table_reader

# executable used to read dwarf information of object file and output all the global variables and functions
dwarf_reader = "/root/cheri-verify/dwarf_reader/read_globals"
dwarf_reader_json = "/root/cheri-verify/dwarf_reader/read_globals_json"

# class to store the dwarf information about global / static objects
class dwarf_global:

    def __init__(self, name=None, size=-1, addr=None, t=None, variable_type=dwarf_variable_data_type.VAR_TYPE_UNHANDLED, members=list()):
        self.name = name            # name of the variable or function as specified as DW_AT_name
        self.size = size            # size of the variable or function which is derived from DW_AT_type or DW_AT_lowpc, DW_AT_highpc respectively
        self.addr = addr            # the address of the variable or function, this will be the global address of variables or the lowpc of functions
        self.touched = False        # Reserved to indicate whether this dwarf_global information has been used to check any capability
        self.type = t               # a string that is either "function" or "variable"
        self.variable_type = variable_type  # enumeration type telling the aggregate type of the variable
        self.members = members              # unless variable_type is VAR_TYPE_UNHANDLED, this is a list of members in the aggregate type

    def __repr__(self):
        return "name: {}, size: {}, addr:{}, touched:{}".format(self.name, str(self.size), str(hex(self.addr)), str(self.touched))

    def __str__(self):
        return "name: {}, size: {}, addr:{}, touched:{}".format(self.name, str(self.size), str(hex(self.addr)), str(self.touched))

# generate two look up tables for each object file
# 1. name_lookup: a lookup table which uses the name of symbols as the key, 
#   the value is a dictionary(key: address, value: dwarf_global object)
# 2. address_lookup: a lookup table which uses the address of symbols as the key, 
#   the value is a dwarf_global object if the address points to a variable 
#   OR list of dwarf_global object if pointing to function (one can use isistance() to check the value)
def generate_global_lookup_table(object_files, object_file_boundaries):
    address_lookup = dict.fromkeys(object_files, None)
    name_lookup = dict.fromkeys(object_files, None)
    variable_pattern = compile(r"variable name:(?P<variable_name>[a-zA-Z_\.\*\(\), :0-9]+|<unknown>), size:(?P<size>[0-9]+|<unknown>)(, at address 0x(?P<addr>[0-9a-zA-Z]+))?")
    function_pattern = compile(r"codesegment name:(?P<function_name>[a-zA-Z_\.\*\(\), :0-9]+|Unnamed Segment), lowpc: 0x(?P<lowpc>[a-fA-F0-9]+), highpc: 0x(?P<highpc>[a-fA-F0-9]+)")
    for objfile_path in object_files:
        # dwarf_global_reader will output the functions before variables
        # after we first detected a variable has been output, this is set to True
        # and we will skip the regex matching for function from that point onwards
        start_variable = False
        object_file_base = object_file_boundaries[objfile_path].base
        # invoke the dwarf_global_reader to read the global variables and functions together with their addresses and expected sizes
        with Popen([dwarf_reader, objfile_path], stderr=PIPE, stdout=PIPE, stdin=PIPE, text=True) as dwarf_reader_proc:
            outs, errs = dwarf_reader_proc.communicate()
            obj_addr_lookup = {} 
            # look up table which uses the addr as the key, 
            # for function, the value is a list which stores a list of dg
            # for variable, the value is a single dg
            obj_name_lookup = {}
            # look up table which uses the name as the key,
            # for both function and variable, the value is a dictionary
            # the dictionary is a lookup table using the address as the key and list the actual dgs as the value
            # if a variable or function has only name, it is put into the dictionary with an address of -1 
            #      (these are unlikely to be useful as we cannot confirm they correspond to the object pointed to by any capabilities, but we store them anyway)
            # if a variable or function has address, we append it to the list keyed by that address
            for line in outs.split("\n"):
                m = function_pattern.match(line)
                if not start_variable and m:
                    # the input line represents a function
                    gd = m.groupdict()
                    name = gd["function_name"]
                    # take the start address as the address used for lookup
                    addr = int(gd["lowpc"], 16)
                    # check that the address is not 0, only add the object_file_base if the address was originally non-zero
                    if addr == 0:
                        # functions without lowpc/highpc are the ones that are inlined, 
                        # only the expansion of inline functions will have lowpc/highpc
                        raise ValueError("Error: function without address\n{}".format(line))
                    else:
                        # add the start virtual address of the mapping of the object file
                        addr += object_file_base
                    highpc = int(gd["highpc"], 16)
                    if highpc == 0:
                        # highpc is 0 while lowpc is not 0 happens if the function is from an assembly file
                        # we need to update it by looking it up from the symbol table
                        pass
                    # the size of the function is the difference between highpc and lowpc
                    size = int(gd["highpc"], 16) - int(gd["lowpc"], 16)
                    # create a dwarf_global object
                    dg = dwarf_global(name, size, addr, "function")
                    # if the address of the function is not 0, we can use the address(i.e., the lowpc) to look up this function
                    if addr != 0:
                        # normally there should only be one function having a specific value of lowpc, in the case of assembly files, this can be different
                        # we may have a capability pointing to the whole assembly file as well as some smaller capabilities pointing to code snippets within
                        # the assembly file, so we make the value looked up by the key a list to store multiple instances for this special case
                        if addr not in obj_addr_lookup:
                            obj_addr_lookup[addr] = []
                        else:
                            # we use list to store only function capabilities, there should be exactly one variable starting at a particular address
                            # if the value looked up is not a list, that means this address has been used as a starting address of a variable, which
                            # is not expected, we need to report this
                            if isinstance(obj_addr_lookup[addr], list):
                                # there can be multiple functions starting at the same address, this is only true for functions from assembly files
                                # prYellow("Found multiple function capability pointing to the same start address {}".format(str(hex(addr))))
                                pass
                            else:
                                raise ValueError("Fatal: address {} has been used as start address for both function and variable".format(str(hex(addr))))
                        obj_addr_lookup[addr].append(dg)
                    if name != "Unnamed Segment":
                        if name not in obj_name_lookup:
                            obj_name_lookup[name] = dict()
                            obj_name_lookup[name][-1] = list()
                        if addr is None:
                            # really unlikely to reach this, a function should have a lowpc and highpc
                            obj_name_lookup[name][-1].append(dg)
                        else:
                            if addr not in obj_name_lookup[name]:
                                obj_name_lookup[name][addr] = list()
                            obj_name_lookup[name][addr].append(dg)
                    else:
                        # we should not have Unnamed Segments as all functions should have DW_AT_name except expansion of inline functions which are ignored
                        raise ValueError("Error: function without name. Can only look up by offset.\n{}".format(line))
                else:
                    m = variable_pattern.match(line)
                    if m:
                        # the input line may represent a variable, if it does, we start to treat all the 
                        # remaining lines as variable information
                        start_Variable = True
                        gd = m.groupdict()
                        name = gd["variable_name"]
                        # all variables should have names
                        if name == "<unknown>":
                            raise ValueError("Error: variable without name. Can only look up by offset.")
                        size = gd["size"]
                        if size.isnumeric():
                            size = int(size)
                        else:
                            size = -1
                        addr = gd["addr"]
                        if addr is None:
                            # some variables may not have a known address in dwarf, potentially they are not used or they are constant
                            # prYellow("Error: variable without address. Can only look up by name.")
                            pass
                        else:
                            addr = int(addr, 16) + object_file_base
                        dg = dwarf_global(name, size, addr, "variable")
                        if addr is not None:
                            # our model does not allow multiple variables to have the same address
                            # variable also cannot share start address with another function and vice versa
                            if addr in obj_addr_lookup:
                                prRed("Duplicated address")
                                # if the looked-up value is a list, this address as the key has been used for some function, this is unexpected
                                if isinstance(obj_addr_lookup[addr], list):
                                    prRed("Fatal: address {} has been used as start address for both function and variable".format(str(hex(addr))))
                            obj_addr_lookup[addr] = dg
                        if name != "<unknown>":
                            if name not in obj_name_lookup:
                                obj_name_lookup[name] = dict()
                                obj_name_lookup[name][-1] = list()
                            if addr is None:
                                obj_name_lookup[name][-1].append(dg)
                            else:
                                if addr in obj_name_lookup[name]:
                                    prRed("Fatal: variable with the same name and same address")
                                obj_name_lookup[name][addr] = dg
                    else:
                        # it is unlikely to reach this point where both function and variable matching fail
                        pass
            address_lookup[objfile_path] = obj_addr_lookup
            name_lookup[objfile_path] = obj_name_lookup

    return address_lookup, name_lookup

# generate two look up tables for each object file (JSON version)
# 1. name_lookup: a lookup table which uses the name of symbols as the key, 
#   the value is a dictionary(key: address, value: dwarf_global object)
# 2. address_lookup: a lookup table which uses the address of symbols as the key, 
#   the value is a dwarf_global object if the address points to a variable 
#   OR list of dwarf_global object if pointing to function (one can use isistance() to check the value)
def generate_global_lookup_table_json(object_file_boundaries, symbol_table: symbol_table_reader):
    address_lookup = dict.fromkeys(object_file_boundaries, None)
    name_lookup = dict.fromkeys(object_file_boundaries, None)
    for objfile_path in object_file_boundaries:
        object_file_base = object_file_boundaries[objfile_path].base
        with Popen([dwarf_reader_json, objfile_path], stderr=PIPE, stdout=PIPE, text=True) as dwarf_reader_proc:
            outs, errs = dwarf_reader_proc.communicate()
            obj_addr_lookup = {} 
            # look up table which uses the addr as the key, 
            # for function, the value is a list which stores a list of dg
            # for variable, the value is a single dg
            obj_name_lookup = {}
            json_obj = json.loads(outs)
            for f in json_obj["functions"]:
                name = f["name"]
                lowpc = int(f["lowpc"], 16)
                if lowpc == 0:
                    raise ValueError("Error: function without address\n{}".format(f))
                else:
                    addr = lowpc + object_file_base
                highpc = int(f["highpc"], 16)
                if highpc == 0:
                    symbol_info = symbol_table.find_symbol_at_addr(addr)
                    # some functions are not found in the symbol table
                    # these are usually a function in assembly file
                    if symbol_info is None:
                        continue
                    if not isinstance(symbol_info, dict):
                        print(objfile_path)
                        print(f)
                        print(symbol_info)
                        raise ValueError("function lookup by address not returning dict")
                    k = next(iter(symbol_info))
                    symbol_info = symbol_info[k]
                    size = symbol_info.expected_size
                    highpc = lowpc + size
                else:
                    size = highpc - lowpc
                dg = dwarf_global(name, size, addr, "function")
                if addr != 0:
                    if addr not in obj_addr_lookup:
                        obj_addr_lookup[addr] = []
                    else:
                        if not isinstance(obj_addr_lookup[addr], list):
                            raise ValueError("Fatal: address {} has been used as start address for both function and variable".format(str(hex(addr))))
                    obj_addr_lookup[addr].append(dg)
                else:
                    raise ValueError("Function with zero lowpc")
                if name != "Unnamed Segment":
                    # if the symbol has not been encountered before
                    if name not in obj_name_lookup:
                        obj_name_lookup[name] = dict()
                        obj_name_lookup[name][-1] = list()
                    if addr not in obj_name_lookup[name]:
                        obj_name_lookup[name][addr] = list()
                    obj_name_lookup[name][addr].append(dg)
                else:
                    raise ValueError("Error: function without name. Can only look up by offset.\n")
            for v in json_obj["variables"]:
                name = v["name"]
                size = int(v["size"])
                addr = None
                variable_type = dwarf_variable_data_type(v["type"])
                members = list()
                # if variable has no address, it might be a constant or optimised away
                if "address" in v:
                    addr = int(v["address"])
                    # print(addr)
                    if addr == 0:
                        raise ValueError("Address 0")
                    addr += object_file_base
                else:
                    print(v)
                    raise ValueError("No address")
                # all global variables should have names
                if name == "Unamed Variable":
                    raise ValueError("Error: variable without name. Can only look up by offset.")
                if variable_type.value in [dwarf_variable_data_type.VAR_TYPE_STRUCT.value, 
                                 dwarf_variable_data_type.VAR_TYPE_UNION.value,
                                 dwarf_variable_data_type.VAR_TYPE_CLASS.value]:
                    members = v["members"]
                dg = dwarf_global(name, size, addr, "variable", variable_type, members)
                if addr:
                    if addr in obj_addr_lookup:
                        if isinstance(obj_addr_lookup[addr], list):
                            prRed("Fatal: address {} has been used as start address for both function and variable".format(str(hex(addr))))
                    obj_addr_lookup[addr] = dg                   
                    
                if name != "<unknown>":
                    if name not in obj_name_lookup:
                        obj_name_lookup[name] = dict()
                        obj_name_lookup[name][-1] = list()
                    if addr is None:
                        obj_name_lookup[name][-1].append(dg)
                    else:
                        if addr in obj_name_lookup[name]:
                            prRed("Fatal: variable with the same name and same address")
                        obj_name_lookup[name][addr] = dg
                    
            address_lookup[objfile_path] = obj_addr_lookup
            name_lookup[objfile_path] = obj_name_lookup
    return address_lookup, name_lookup

if __name__ == "__main__":
    object_file_boundaries_file = "/root/cheri/object_file_boundaries.pickle"
    # section_info_file = "/root/cheri/section_info.pickle"
    import pickle
    object_file_boundaries = pickle.load(open(object_file_boundaries_file, "rb"))
    address_lookup, name_lookup = generate_global_lookup_table_json(object_file_boundaries)        
    print(name_lookup["/root/cheri/output/rootfs-purecap128/bin/helloworld"])
    # dwarf_stack_executable_path = "/root/cheri-verify/dwarf_reader/read_stack"
    # symbol_table = symbol_table_reader(object_file_boundaries_file, section_info_file)
    # manager = dwarf_manager(object_file_boundaries_file, dwarf_stack_executable_path, symbol_table)
    # addr = int("0x41061290", 16)
    # print(manager.extracted_info["object_file_boundaries"])
    # print(manager.function_lookup_tree)
    # print(manager.find_object_file(addr))
    # print(manager.find_function_by_addr(addr))