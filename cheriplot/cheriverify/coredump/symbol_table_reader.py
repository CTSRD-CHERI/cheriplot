
# read the symbol table and relocation information in all object files
import pickle
import re
from subprocess import Popen, PIPE, TimeoutExpired
from symbol_info import symbol_info
from colour_print import prGreen
from capability import capability

class symbol_table_reader:

    def __init__(self, object_file_boundaries_file: str, section_info_file: str):
        self.extracted_info = dict()
        prGreen("Symbol table reader: object file info read from {}".format(object_file_boundaries_file))
        prGreen("Symbol table reader: section info read from {}".format(section_info_file))
        self.extracted_info["object_file_boundaries"] = pickle.load(open(object_file_boundaries_file, "rb") )
        self.extracted_info["section_info_dict"] = pickle.load(open(section_info_file, "rb") )
        # .bss section is not necessary, remove to avoid confusion
        for k, section_info in self.extracted_info["section_info_dict"].items():
            if "bss" in section_info:
                del section_info["bss"]
        self.object_files = [k for k in self.extracted_info["object_file_boundaries"]]
        self.extracted_info["unknown_symbol_info_table"] = self._generate_unknown_symbol_info_table()
        self.extracted_info["symbol_table_from_object_files"], self.extracted_info["symbol_table_from_object_files_address"] = self._generate_symbol_table_from_object_files()

    # function to find the object file where a cursor is pointing to
    def find_object_file(self, address:int) -> str:
        cap = capability()
        cap.cursor = str(hex(address))
        for k, boundary in self.extracted_info["object_file_boundaries"].items():
            if boundary.check_cursor_pointing_to_objfile(cap):
                return k
        return None

    def find_cap_table(self, address: int):
        # return the section_info and object path if the address is in the .captable section
        for objfile_path, section_info_dict in self.extracted_info["section_info_dict"].items():
            for name, section_info in section_info_dict.items():
                if int(section_info.start_addr, 16) <= address <= int(section_info.end_addr, 16):
                    return objfile_path, section_info
        return None, None

    def find_symbol_at_addr(self, address: int):
        obj_file = self.find_object_file(address)
        if not obj_file:
            return None
        result = None
        if address in self.extracted_info["symbol_table_from_object_files_address"][obj_file]:
            return self.extracted_info["symbol_table_from_object_files_address"][obj_file][address]
        elif address in self.extracted_info["unknown_symbol_info_table"][obj_file]:
            return self.extracted_info["unknown_symbol_info_table"][obj_file][address]
        return None

    def find_symbol_by_name_and_address(self, name: str, address: int):
        obj_file = self.find_object_file(address)
        if not obj_file:
            return None
        if name in self.extracted_info["symbol_table_from_object_files"][obj_file]:
            if address in self.extracted_info["symbol_table_from_object_files"][obj_file][name]:
                return self.extracted_info["symbol_table_from_object_files"][obj_file][name][address]
        return None

    def _generate_unknown_symbol_info_table(self):
        object_files = self.object_files
        object_file_boundaries = self.extracted_info["object_file_boundaries"]
        unknown_symbol_info_table = dict.fromkeys(object_files)
        # format: key: offset + object_file_base -> val: size
        pattern = re.compile(r"[ \t]*(?P<address>0x[0-9a-zA-Z]+) (\((?P<symbol>[a-zA-Z_0-9 ]+)\))?[ \t]*Base: (?P<base>0x[a-zA-Z0-9]+) \((?P<symbol2>[<a-zA-Z_0-9\.> ]+\+[0-9]+)\) Length: (?P<length>[0-9]+) Perms: (?P<permissions>[A-Za-z]+)")
        for object_file in object_files:
            d = {}
            object_file_base = object_file_boundaries[object_file].base
            with Popen(["mips64c128-unknown-freebsd13-purecap-readelf", "--cap-relocs", object_file], stdout=PIPE, stderr=PIPE, text=True) as readelf_proc:
                output = readelf_proc.stdout.read()
                for line in output.split("\n"):
                    m = pattern.match(line)
                    if m:
                        gd = m.groupdict()
                        address = object_file_base + int(gd["base"], 16)
                        if gd["permissions"] == "Constant" or gd["permissions"] == "Object":
                            unknown_symbol_type = "OBJECT"
                        elif gd["permissions"] == "Function":
                            unknown_symbol_type = "FUNC"
                        else:
                            raise ValueError("Unknown type: {}".format(gd["permissions"]))
                        d[address] = symbol_info(int(gd["length"]), unknown_symbol_type, object_file)
            unknown_symbol_info_table[object_file] = d
        return unknown_symbol_info_table
    
    def _generate_symbol_table_from_object_files(self):
        object_file_boundaries = self.extracted_info["object_file_boundaries"]
        symbol_table_from_elf = dict.fromkeys(object_file_boundaries, None)
        symbol_table_from_elf_by_address = dict.fromkeys(object_file_boundaries, None)
        # Construct the model from the libraries
        pattern = re.compile(r"[ \t]*[0-9]+:[ \t]*(?P<address>[0-9a-zA-Z]+)[ \t]+(?P<size>[0-9]+)[ \t]+(?P<type>NOTYPE|FUNC|OBJECT)[ \t]*(?P<bind>[A-Z]+)[ \t]*(?P<visibility>[A-Z]+)[ \t]*(?P<ndx>UND|ABS|[0-9]+)[ \t]+(?P<symbol>.*)")
        # Extract the sizes of the OBJECTs from the libraries and executable
        for objfile_path in object_file_boundaries:
            with Popen(["mips64c128-unknown-freebsd13-purecap-readelf", "-s", objfile_path], stdout=PIPE, stderr=PIPE, text=True) as readelf_proc:
                d = {}
                d_address = {}
                output = readelf_proc.stdout.read()
                object_file_base = object_file_boundaries[objfile_path].base
                for line in output.split("\n"):
                    m = pattern.match(line)
                    if m:
                        gd = m.groupdict()
                        symbol = "{}".format(gd["symbol"])
                        dec_addr = int(gd["address"], 16) + object_file_base
                        if len(symbol):
                            if symbol not in d:
                                d[symbol] = dict()
                            if dec_addr not in d_address:
                                d_address[dec_addr] = dict()
                            symbol_i = symbol_info(int(gd["size"]), gd["type"], objfile_path)
                            d[symbol][dec_addr] = symbol_i
                            d_address[dec_addr][symbol] = symbol_i
                    # else:
                        # print(line)
            symbol_table_from_elf[objfile_path] = d
            symbol_table_from_elf_by_address[objfile_path] = d_address
        return symbol_table_from_elf, symbol_table_from_elf_by_address