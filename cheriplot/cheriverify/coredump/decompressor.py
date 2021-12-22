from abc import ABC, abstractmethod
from capability import capability
import re
from subprocess import Popen, PIPE, TimeoutExpired
from colour_print import prYellow, prGreen

# wrapper for cap_decompress, provide an API to decompress capability and generate a fat pointer capability object
class cap_decompressor(ABC):

    @abstractmethod
    def add_to_buffer(self, pesbt, cursor) -> capability:
        pass

    @abstractmethod
    def decompress(self):
        pass


class cap_cc_decompressor(cap_decompressor):

    def __init__(self, executable_name="decompress_c128_cap"):
        self.executable_name=executable_name
        self.pattern = re.compile(r"Permissions:(?P<permissions>0x[0-9a-zA-Z]+),User Perms:(?P<user_perm>0x[0-9a-fA-F]+),Base:(?P<base>0x[0-9a-fA-F]+),Offset:(?P<offset>0x[0-9a-fA-F]+),Cursor:(?P<cursor>0x[0-9a-fA-F]+),Length:(?P<length>0x[0-9a-fA-F]+),Top:(?P<top>0x[0-9a-fA-F]+),Sealed:(?P<sealed>0|1),OType:(?P<otype>0x[0-9a-fA-F]+) \([A-Za-z_0-9]+\),Flags:(?P<flags>0x[0-9a-fA-F]+),Reserved:(?P<reserved>0x[0-9a-fA-F]+)")
        self.buffer = []

    # return None if decompression is unsuccessful
    def add_to_buffer(self, pesbt, cursor) -> capability:
        self.buffer.append([pesbt, cursor])
    
    def decompress(self):
        decompressed_caps = []
        with Popen([self.executable_name], stderr=PIPE, stdout=PIPE, stdin=PIPE, text=True) as decompress_proc:
            input_str = "".join(["{} {}\n".format(hex_pair[0], hex_pair[1]) for hex_pair in self.buffer])
            outs, errs = decompress_proc.communicate(input_str, timeout=None)
            for line in errs.split("\n"):
                cap = capability()
                m = self.pattern.match(line)
                if m:
                    gd = m.groupdict()
                    try:
                        cap.permissions = gd["permissions"]
                        cap.user_perm = gd["user_perm"]
                        cap.base = gd["base"]
                        cap.offset = gd["offset"]
                        cap.cursor = gd["cursor"]
                        cap.length = int(gd["length"], 16)
                        cap.top = gd["top"]
                        cap.sealed = True if gd["sealed"] == "1" else False
                        cap.otype = gd["otype"]
                        cap.flags = gd["flags"]
                        cap.reserved = gd["reserved"]
                        decompressed_caps.append(cap)
                    except:
                        prRed("Error when reading decompressed capability output!")
                        decompressed_caps.append(None)
                else:
                    # prGreen("Potentially NULL capability: {}".format(line))
                    pass
        # clear the buffer
        del self.buffer
        self.buffer = []
        return decompressed_caps     