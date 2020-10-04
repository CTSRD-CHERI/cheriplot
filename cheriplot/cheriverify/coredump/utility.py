# count the leading zeroes for length, which is used to calculate the alignment requirement
def count_leading_zero(val):
    binary_str = bin(val)[2:]
    return min(53, 65 - len(binary_str))

def compute_num_ls_zeroes(cap_length):
    e = 52 - count_leading_zero(cap_length)
    return e + 3