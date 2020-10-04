# analyse the coredump file and executable to obtain virtual memory mapping
import gdb
import re
from section_info import section_info
import logging
from decompressor import cap_decompressor, cap_cc_decompressor
from object_file_boundary import object_file_boundary
from subprocess import Popen, PIPE, TimeoutExpired
from colour_print import *
from symbol_info import symbol_info

class coredump_analyser:

    def __init__(self):
        self.gdb_info = {
            "section_mapping_text" : gdb.execute("info files", False, True),
            "process_mapping_text" : gdb.execute("info proc mapping", False, True)
        }
        prGreen(self.gdb_info["process_mapping_text"])
        self.object_files = [o.filename for o in gdb.objfiles()] # list of object files mapped
        self.extracted_info = dict()
        self.extracted_info["section_info_dict"] = self._extract_section_info_dict()
        prGreen("Extracting .captable section")
        self.extracted_info["decompressed_caps"] = self._decompress_capablities()
        prGreen("Decompressinging capabilities")
        self.extracted_info["object_file_boundaries"] = self._extract_object_file_boundaries()
        prGreen("Calculating object file boundaries")
        # for k, objfile_boundary in self.extracted_info["object_file_boundaries"].items():
        #     prGreen("Found object file {} mapped to {}".format(k, objfile_boundary))
        prGreen("Extracting symbol table from ELF")  

    def _extract_section_info_dict(self):
        # Obtain executable name
        gdb_info = self.gdb_info
        object_files = self.object_files
        object_file_set = dict.fromkeys(object_files)
        section_info_dict = {}
        executable_dict = {}
        # Scam section mapping information to obtain information related to .captable
        pattern = re.compile(r"[ \t]+(?P<start_addr>0x[0-9a-fA-F]+) - (?P<end_addr>0x[0-9a-fA-F]+) is \.(?P<section_name>(captable|got|bss))( in (?P<obj_path>(\/[^\/]*)+\/?))?")
        for line in gdb_info["section_mapping_text"].split("\n"):
            m = pattern.match(line)
            if m:
                gd = m.groupdict()
                section_name = gd["section_name"]
                start_addr = gd["start_addr"]
                end_addr = gd["end_addr"]
                if gd["obj_path"] is None:
                    executable_dict[section_name] = section_info(start_addr, end_addr, section_name, None)
                else:
                    obj_path = gd["obj_path"]
                    if obj_path not in section_info_dict:
                        section_info_dict[obj_path] = {}
                    section_info_dict[obj_path][section_name] = section_info(start_addr, end_addr, section_name, obj_path)
                    if obj_path in object_file_set:
                        del object_file_set[obj_path]
        # The only obj file left in the set should be the executable, if there are more than one, we missed out some
        if len(object_file_set) != 1:
            print("Error when reading captable section data! Not all object files read.")
            sys.exit(1)
        else:
            # Replace the placeholder with the actual path name of executable
            executable_path = next(iter(object_file_set))
            for k, v in executable_dict.items():
                v.obj_path = executable_path
            section_info_dict[executable_path] = executable_dict
        return section_info_dict
    
    def _decompress_capablities(self): 
        # Initialise the decompressor
        section_info_dict = self.extracted_info["section_info_dict"]
        decompressor = cap_cc_decompressor()
        decompressed_caps = {}
        pattern = re.compile(r"[ \t]*0x[a-zA-Z0-9]* <(?P<symbol>[_A-Za-z0-9]+(\+[0-9]*)?)>:[\ \t]*(?P<giant_word1>0x[a-fA-F0-9]+)[ \t]*(?P<giant_word2>0x[a-fA-F0-9]+)")
        # Read the captable in all objfiles
        for objfile_path, all_section_info in section_info_dict.items():
            captable_info = all_section_info["captable"]
            num_of_entries = captable_info.section_size / 16
            output = gdb.execute("x/{}xg {}".format(str(2 * int(num_of_entries)), captable_info.start_addr), False, True)
            for line in output.split("\n"):
                m = pattern.match(line)
                if m:
                    gd = m.groupdict()
                    # to speed up, we add capabilities to buffer and decompress all capabilities within an object file's capability table all together
                    decompressor.add_to_buffer(gd["giant_word1"], gd["giant_word2"])
            decompressed_caps[objfile_path] = decompressor.decompress()
        return decompressed_caps
    
    def _extract_object_file_boundaries(self):
        # use process mapping text to get the base of capabilities
        object_files = self.object_files
        gdb_info = self.gdb_info
        section_info_dict = self.extracted_info["section_info_dict"]
        object_file_boundaries = dict.fromkeys(object_files)
        file_name_to_path = dict(zip([f.split("/")[-1] for f in object_files], object_files))
        # this pattern matches the output of "info proc mapping" and help us locate the start address where an object file is loaded
        pattern = re.compile(r"[ \t]*(?P<start_addr>0x[0-9a-zA-Z]+)[ \t]*(?P<end_addr>0x[0-9a-zA-Z]+)[ \t]*(?P<size>0x[0-9a-zA-Z]+)[ \t]*(?P<offset>0x[0-9a-zA-Z]+)[ \t]*(?P<permission>[rwx-]+)[ \t]*(?P<flags>[A-Z-]*)[ \t]*(?P<file>.*)")
        print(object_files)
        for line in gdb_info["process_mapping_text"].split("\n"):
            m = pattern.match(line)
            if m:
                gd = m.groupdict()
                if len(gd["file"]) > 0:
                    file_name = gd["file"].split("/")[-1]
                    if file_name not in file_name_to_path:
                        raise ValueError("Error. Unknown files in process memory mapping. File name: {}, file_lookup_table: {}".format(file_name, file_name_to_path))
                        sys.exit(1)
                    else: 
                        file_path = file_name_to_path[file_name]
                        if not object_file_boundaries[file_path]:
                            object_file_boundaries[file_path] = object_file_boundary(gd["start_addr"])
        # this pattern finds the address where 
        pattern = re.compile(r"[ \t]*\[[\t ]*(?P<number>[0-9]*)\] \.(?P<section_name>got|bss)[ \t]*(?P<type>NULL|[A-Z_]+)[ \t]*(?P<address>[0-9A-Fa-f]+) (?P<offset>[0-9A-Fa-f]+) (?P<size>[0-9A-Fa-f]+) ")
        for objfile_path in section_info_dict:
            with Popen(["mips64c128-unknown-freebsd13-purecap-readelf", "-S", objfile_path], stdout=PIPE, stderr=PIPE, text=True) as readelf_proc:
                output = readelf_proc.stdout.read()
                tops = [None, None]
                for line in output.split("\n"):
                    m = pattern.match(line)
                    if m:
                        gd = m.groupdict()
                        if gd["section_name"] == "got":
                            tops[0] = hex(int(gd["address"], 16) + int(gd["size"], 16))
                        elif gd["section_name"] == "bss":
                            tops[1] = hex(int(gd["address"], 16) + int(gd["size"], 16))
                object_file_boundaries[objfile_path].update_top(tops)
        return object_file_boundaries

    def dump_object_file_boundaries(self, object_file_boundaries_file:str, section_info_file:str):
        prGreen("Object file boundaries stored in {}".format(object_file_boundaries_file))
        prGreen("Section information stored in {}".format(section_info_file))
        import pickle
        pickle.dump(self.extracted_info["object_file_boundaries"], open(object_file_boundaries_file, "wb"))   
        pickle.dump(self.extracted_info["section_info_dict"], open(section_info_file, "wb"))