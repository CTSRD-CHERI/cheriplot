from capability import capability
from utility import compute_num_ls_zeroes
class object_file_boundary:

    def __init__(self, base: str):
        self.base = int(base, 16)
        self.top = None
        self.sizes = None # there may be multiple valid sizes for an object file(atm, obj file ends at .got or .bss)
        self.alignment_masks = None # alignment masks are used to check the top of capability, for function cap, the difference between the top
    
    def update_top(self, relative_tops: list):
        self.top = []
        self.sizes = []
        self.alignment_masks = []
        for t in relative_tops:
            dec_top = int(t, 16)
            ls_zeroes = compute_num_ls_zeroes(dec_top)
            alignment_mask = "1" * ls_zeroes
            masked_bits = dec_top & int(alignment_mask, 2)
            # if the masked top value is non-zero, force top to satisfy alignment requirement
            if masked_bits:
                dec_top -= masked_bits
                dec_top += int("1" + "0" * ls_zeroes, 2)
            self.alignment_masks.append(alignment_mask)
            self.sizes.append(dec_top)
            self.top.append(dec_top + self.base)

    # check that a capability is within the boundary, the capability must have the same base and one of the top in self.top
    def check_in_bound(self, cap: capability):
        if int(cap.base, 16) != self.base:
            return False
        dec_top = int(cap.top, 16)
        if not any(dec_top <= t for t in self.top):
            return False
        return True

    def check_cursor_pointing_to_objfile(self, cap: capability):
        dec_cursor = int(cap.cursor, 16)
        if dec_cursor >= self.base and any(dec_cursor < t for t in self.top):
            return True
        else:
            return False

    def __repr__(self):
        return "obj boundary -> Base: 0x{}, Top: {}".format(hex(self.base), self.top)

    def __str__(self):
        return "obj boundary -> Base: 0x{}, Top: {}".format(hex(self.base), self.top)