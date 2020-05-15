import re
import sys
import json
import pickle
sys.path.append(r'/root/cheri/cheriplot/cheriplot/cheriverify/')
sys.path.append(r'/root/cheri/cheriplot/cheriplot/cheriverify/coredump')
sys.path.append(r'/root/cheri/cheriplot/cheriplot/cheriverify/dwarfreader')
from coredump.coredump_analyser import coredump_analyser
from capability import capability
from object_file_boundary import object_file_boundary
from symbol_info import symbol_info
from dwarf_globals import generate_global_lookup_table_json, dwarf_global
from colour_print import *
from utility import count_leading_zero, compute_num_ls_zeroes
from symbol_type import symbol_type
from symbol_table_reader import symbol_table_reader


def find_object_file(object_file_boundaries, cap: capability):
    """ 
    find the object file where a cursor of the capability is pointing to
    """
    for k, boundary in object_file_boundaries.items():
        if boundary.check_cursor_pointing_to_objfile(cap):
            return k
    return None

def compare_symbol_and_debug_info(final_result: dict, symbol_name: str, cap: capability, objectfile_path: str, objectfile_boundary: object_file_boundary, symbol_info: symbol_info, dg: dwarf_global=None, l_dg: list=None):
    """
    compare the symbol info against the given dg or l_dg(list) of dg
    * symbol_info: information about the symbol extracted from symbol table
    * dg: DWARF debugging information about a global symbol(object)
    * l_dg: list of DWARF debugging information about
       either dg or l_dg is not None depending on the type of the symbol
        if dg is not None, the symbol SHOULD be an OBJECT(variable)
        if l_dg is not None, the symbol SHOULD be a FUNCTION
    """
    if dg:
        if symbol_info.expected_type == symbol_type.NOTYPE:
            # this is unlikely true, dwarf information only contains information about variable and functions, in the case where a symbol is NOTYPE, it might have been classified incorrectly by the compiler
            if symbol_info.expected_size == dg.size:
                final_result["Dwarf_Pass_Notype"] += 1
            else:
                prRed("{} at {} is a notype. Objfile: {}, Size from symtab: {}, size from dwarf: {}".format(symbol_name, cap.cursor, objectfile_path, str(symbol_info.expected_size), str(dg.size)))
                prYellow("Debug Info: {}, Offset: {}".format(dg, str(hex(dg.addr - objectfile_boundary.base))))
                prRed(cap)
                final_result["Dwarf_Fail_Notype"] += 1
        elif symbol_info.expected_type == symbol_type.OBJECT:
            if symbol_info.expected_size == dg.size:
                final_result["Dwarf_Pass_Object"] += 1
            else:
                prRed("{} at {} is an object. Objfile: {}, Size from symtab: {}, size from dwarf: {}".format(symbol_name, cap.cursor, objectfile_path, str(symbol_info.expected_size), str(dg.size)))
                prYellow("Debug Info: {}, Offset: {}".format(dg, str(hex(dg.addr - objectfile_boundary.base))))
                prRed(cap)
                final_result["Dwarf_Fail_Object"] += 1
        else:
            prRed("The object is expected to be a variable from DWARF but a function from symbol table")
    elif l_dg:
        if symbol_info.expected_type == symbol_type.NOTYPE:
            if any([symbol_info.expected_size == dg.size for dg in l_dg]):
                final_result["Dwarf_Pass_Notype"] += 1
            else:
                prRed("{} at {} is a notype. Objfile: {}, Size from symtab: {}, size from dwarf: {}".format
                    (
                        symbol_name, 
                        cap.cursor, 
                        objectfile_path, 
                        str(symbol_info.expected_size), 
                        " or ".join([str(dg.size) for dg in found_value])
                    )
                )
                prYellow(l_dg)
                prRed(cap)
                final_result["Dwarf_Fail_Notype"] += 1
        elif symbol_info.expected_type == symbol_type.FUNC:
            if any([symbol_info.expected_size == dg.size for dg in l_dg]):
                final_result["Dwarf_Pass_Function"] += 1
            else:
                prRed("{} at {} is a function. Objfile: {}, Size from symtab: {}, size from dwarf: {}".format
                    (
                        symbol_name, 
                        cap.cursor, 
                        objectfile_path, 
                        str(symbol_info.expected_size), 
                        " or ".join([str(dg.size) for dg in found_value])
                    )
                )
                prRed(cap)
                prYellow(l_dg)
                final_result["Dwarf_Fail_Function"] += 1 
        else:
            prRed("The object is expected to be a variable from DWARF but a function from symbol table")

def check_bound(cap: capability, sym_info: symbol_info, object_file_boundaries, symbol="<unknown symbol>"):
    """
    check the bound of the capability "cap" against the symbol information "sym_info"
    if the symbol is a function, it should have DSO bounds. The corresponding DSO bounds can be looked up from "object_file_boundaries"
    if the symbol is an object, the fields of the capability should match the alignment requirements and have minimal bounds to cover the object
    """
    # symbol table shows the symbol is an OBJECT
    if sym_info.expected_type == symbol_type.OBJECT:
        # if the size of the object is smaller than 4k, 
        # * it is not required to check alignment requirements 
        # * the size should equal to the length        
        if sym_info.expected_size < 4096:
            if cap.length != sym_info.expected_size:
                print("> {} SIZE & BOUND MISMATCH -> Expacted: {}, Actual: {}".format(symbol, str(sym_info.expected_size), str(cap.length)))
                print("> {}".format(str(cap)))
                return False
            else:
                return True
        else:
            # object of size larger than 4k
            # * the base and top of the capability should satisfy the alignment requirement
            # * the length of the capability should NOT be smaller than the size
            # * the absolute difference between the size and length should be minimal depending on the alignment mask
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
    # symbol table shows the symbol is a FUNCTION
    elif sym_info.expected_type == symbol_type.FUNC:
        # find out the object file containing the function
        obj_file = find_object_file(object_file_boundaries, cap)
        if not obj_file:
            prRed("Function capability not pointing to any object file")
            return False
        # once the containing object file is found, check against the DSO bounds
        if object_file_boundaries[obj_file].check_in_bound(cap):
            return True
        else:
            prRed("Function capability has different bounds against the containing object file.")
            prRed("Expected: {}, Function cap: {}".format(object_file_boundaries[obj_file], cap))
            return False
    # symbol table shows the symbol is NOTYPE, return True by default
    elif sym_info.expected_type == symbol_type.NOTYPE:
        return True
    else:
        return False

# executable_path = None
disable_dwarf_check = True

""""
the PATHs to output the extracted information on object file bounds and section info from ELF
""" 
object_file_boundaries_file = "/root/cheri/object_file_boundaries.pickle"
section_info_file = "/root/cheri/section_info.pickle"

"""
coredump analyser 
* reads the coredump file
* extracts the boundaries of the object files
* decompresses all capabilities in the capability table
"""
coredump = coredump_analyser()
coredump.dump_object_file_boundaries(object_file_boundaries_file, section_info_file)
"""
symbol table reader
* uses the object file boundaries information and section information read from coredump
* creates the lookup tables to look up symbols by addresses and names
Note: readelf is used internally to get the symbol tables and relocation information from ELF file
"""
symbol_table = symbol_table_reader(object_file_boundaries_file, section_info_file)

"""
regex expressions to read the symbol tables from gdb
"""
pattern = re.compile(r"\$[0-9]+ = 0x[A-Za-z0-9]+ <(?P<symbol_name>[a-zA-Z_\.\*\(\), :0-9]+)>")  # regex expression for symbol with name
pattern_for_unknown_symbol = re.compile(r"\$[0-9]+ = (?P<address>0x[A-Za-z0-9]+)") # regex expression for symbol without name
object_file_boundaries = pickle.load(open(object_file_boundaries_file, "rb"))

""""
generate the lookup table using DWARF debugging information for global symbols
* object_file_boundaries contain the pathes to the object files as the key, DWARF info is then read from executable and shared libraries
* symbol_table is passed into the function because the sizes of assembly functions can only be obtained from symbol table rather than DWARF
"""
dwarf_address_lookup, dwarf_name_lookup = generate_global_lookup_table_json(object_file_boundaries, symbol_table)
"""
dictionary of the results for static analysis
"""
final_result = {
    "Pass": 0,                  # no of capabilities that pass the check against symbol table and relocation information
    "Fail" : 0,                 # no of capabilities that fail the check against symbol table and relocation information
    "Not Found in Dwarf" :0,    # no of capabilities that do not have corresponding information from DWARF
    "Dwarf Found" : 0,          # no of capabilities that have corresponding information from DWARF
    "Dwarf_Pass_Object" : 0,    # no of capabilities that are OBJECTs(from symbol table) and pass the three-way check(symbol_info, debug_info, capability)
    "Dwarf_Fail_Object" : 0,    # no of capabilities that are OBJECTs(from symbol table) and fail the three-way check(symbol_info, debug_info, capability)
    "Dwarf_Pass_Function": 0,   # no of capabilities that are FUNCTIONs(from symbol table) and pass the three-way check(symbol_info, debug_info, capability)
    "Dwarf_Fail_Function": 0,   # no of capabilities that are FUNCTIONs(from symbol table) and fail the three-way check(symbol_info, debug_info, capability)
    "Dwarf_Pass_Notype": 0,     # no of capabilities that are NOTYPEs(from symbol table) and fail the three-way check(symbol_info, debug_info, capability)
    "Dwarf_Fail_Notype": 0,     # no of capabilities that are NOTYPEs(from symbol table) and fail the three-way check(symbol_info, debug_info, capability)
    "Out of Bounds": 0,         # no of capabilities that are not pointing to any of the object files(these are capabilities to PLT stubs)
    "Object": 0,                
    "Function": 0,
    "Notype": 0,
    "Object_unknown": 0,
    "Function_unknown": 0,
    "Notype_unknown": 0,
    "Total": 0
}
for object_file, cap_list in coredump.extracted_info["decompressed_caps"].items():
    obj_boundary = coredump.extracted_info["object_file_boundaries"][object_file]
    for cap in cap_list:
        final_result["Total"] += 1
        # Verify that the cursor is pointing to the current object file
        if not obj_boundary.check_cursor_pointing_to_objfile(cap):
            # if the capability is not pointing to the current object file, we look it up in the boundaries
            objectfile_path = find_object_file(coredump.extracted_info["object_file_boundaries"], cap)
            # if we found the object file to which it is pointing to
            if objectfile_path:
                # look up the symbol from the actual object file
                prCyan("Current: {}, External({}): {}".format(object_file.split("/")[-1], objectfile_path.split("/")[-1], cap))
                pass
            else:
                prYellow("Capability not pointing to any of the object files: {}".format(cap.cursor))
                final_result["Out of Bounds"] += 1
                continue
        else:
            objectfile_path = object_file
        # Look up the symbol table in gdb, ask for the symbol at the cursor of the capability
        output = gdb.execute("p/a {}".format(cap.cursor), False, True)
        m = pattern.match(output)
        if m:
            gd = m.groupdict()
            symbol_name = gd["symbol_name"]
            symbol_info = None
            lookup_by_symbol = False
            lookup_by_address = False
            dec_address = int(cap.cursor, 16)
            # Look up the symbol by its name first, this will prioritise global symbol over static symbol
            if symbol_name in symbol_table.extracted_info["symbol_table_from_object_files"][objectfile_path]:
                # look up the symbol by its address， the symbol information must match the cursor of capability
                if dec_address in symbol_table.extracted_info["symbol_table_from_object_files"][objectfile_path][symbol_name]:
                    symbol_info = symbol_table.extracted_info["symbol_table_from_object_files"][objectfile_path][symbol_name][dec_address]
                    lookup_by_symbol = True
            # in the case a symbol cannot be found by name, we can only look into relocation information
            if not symbol_info:
                if dec_address in symbol_table.extracted_info["unknown_symbol_info_table"][objectfile_path]:
                    symbol_info = symbol_table.extracted_info["unknown_symbol_info_table"][objectfile_path][dec_address]
                    lookup_by_address = True                             
            if not symbol_info:
                # prRed("{} at {} not found in symbol table in objfile: {}".format(symbol_name, cap.cursor, objectfile_path))
                final_result["Fail"] += 1
            else:
                result = check_bound(cap, symbol_info, coredump.extracted_info["object_file_boundaries"], symbol_name)
                if symbol_info.expected_type == symbol_type.FUNC:
                    final_result["Function"] += 1
                elif symbol_info.expected_type == symbol_type.OBJECT:
                    final_result["Object"] += 1
                else:
                    final_result["Notype"] += 1
                if result:
                    final_result["Pass"] += 1
                else:
                    final_result["Fail"] += 1
                    prRed("{} at {}, Expected size: {}, Actual size: {}, Type: {}".format(
                        symbol_name, 
                        cap.cursor,
                        symbol_info.expected_size, 
                        cap.length, 
                        symbol_info.expected_type))
                if not disable_dwarf_check:
                    # check against dwarf
                    found_value = None
                    if dec_address in dwarf_address_lookup[objectfile_path]:
                        # there may be variables with same name but different addresses, so we chose to look up by address first
                        found_value = dwarf_address_lookup[objectfile_path][dec_address]
                    elif symbol_name in dwarf_name_lookup[objectfile_path]:
                        print(objectfile_path)
                        raise ValueError("{} not found by address {}".format(symbol_name, dec_address))
                        # normally this should not be reached, but some variable has no address, in that case they will stay in the list
                        # coredump.extracted_info["dwarf_name_lookup"][objectfile_path][symbol_name][-1]
                        # here we only get the first one to check as we don't know which one it is exactly
                        found_value = dwarf_name_lookup[objectfile_path][symbol_name][-1][0]
                    if not found_value:
                        final_result["Not Found in Dwarf"] += 1
                        # if symbol_info.expected_type == symbol_type.FUNC:
                        #     print(symbol_info, symbol_name, str(hex(dec_address - coredump.extracted_info["object_file_boundaries"][objectfile_path].base)))
                            # raise ValueError("")
                        # if symbol_info.expected_type == symbol_type.OBJECT:
                        #     print(symbol_info, symbol_name, str(hex(dec_address - coredump.extracted_info["object_file_boundaries"][objectfile_path].base)))
                    else:
                        final_result["Dwarf Found"] += 1
                        if isinstance(found_value, list):
                            compare_symbol_and_debug_info(final_result, symbol_name, cap, objectfile_path, coredump.extracted_info["object_file_boundaries"][objectfile_path], symbol_info, None, found_value)
                        elif isinstance(found_value, dwarf_global):
                            compare_symbol_and_debug_info(final_result, symbol_name, cap, objectfile_path, coredump.extracted_info["object_file_boundaries"][objectfile_path], symbol_info, found_value, None)
                        else:
                            print("NOT LIST NOR DWARF_GLOBAL???")
        else:
            m2 = pattern_for_unknown_symbol.match(output)
            if m2:
                dec_address = int(cap.cursor, 16)
                if dec_address in symbol_table.extracted_info["unknown_symbol_info_table"][objectfile_path]:
                    symbol_info = symbol_table.extracted_info["unknown_symbol_info_table"][objectfile_path][dec_address]
                    result = check_bound(cap, symbol_info, coredump.extracted_info["object_file_boundaries"])
                    if symbol_info.expected_type == symbol_type.FUNC:
                        final_result["Function_unknown"] += 1
                    elif symbol_info.expected_type == symbol_type.OBJECT:
                        final_result["Object_unknown"] += 1
                    else:
                        final_result["Notype_unknown"] += 1
                    if result:
                        final_result["Pass"] += 1
                    else:
                        final_result["Fail"] += 1
                        prRed("Unknown symbol at {}, Expected size: {}, Actual size: {}, Type: {}".format(
                            cap.cursor, 
                            symbol_info.expected_size,
                            cap.length,
                            symbol_info.expected_type))
                else:
                    prRed("Unknown symbol at {} not found in unknown symbol table".format(cap.cursor))
                    final_result["Fail"] += 1
                if not disable_dwarf_check:
                    if dec_address in dwarf_address_lookup[objectfile_path]:
                        # if the found value is a list, it is a function, otherwise, it is a variable
                        found_value = dwarf_address_lookup[objectfile_path][dec_address]
                        final_result["Dwarf Found"] += 1                   
                        if isinstance(found_value, list):
                            compare_symbol_and_debug_info(final_result, "Unknown Symbol", cap, objectfile_path, coredump.extracted_info["object_file_boundaries"][objectfile_path], symbol_info, None, found_value)
                        elif isinstance(found_value, dwarf_global):
                            compare_symbol_and_debug_info(final_result, "Unknown Symbol", cap, objectfile_path, coredump.extracted_info["object_file_boundaries"][objectfile_path], symbol_info, found_value, None)
                        else:
                            print("NOT LIST NOR DWARF_GLOBAL???")
                    else:
                        # prRed("Unknown symbol at {} not found in dwarf lookup tables. objfile: {}".format(cap.cursor, objectfile_path.split("/")[-1]))
                        final_result["Not Found in Dwarf"] += 1
            else:
                prRed("Fail to parse: {}".format(output))
                final_result["Fail"] += 1
import sys
sys.stderr.write("\033[92m Result:{}\n\033[00m".format(str(final_result)))