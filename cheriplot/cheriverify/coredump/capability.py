# class capability holds the information that we need to validate the capabilities
# If the members in a capability may vary depending across different definitions, 
# this class should be made as an interface, which is also the return type for decompress in cap_decompressor
class capability:

    def __init__(self):
        self.permissions = None
        self.user_perm = None
        self.base = None
        self.offset = None
        self.cursor = None
        self.length = None
        self.top = None
        self.sealed = None
        self.otype = None
        self.flags = None
        self.reserved = None

    def __eq__(self, other):
        if self.base == other.base and self.top == other.top and self.length == other.length:
            return True
        else:
            return False

    def __repr__(self):
        return "Base: {}, Offset: {}, Cursor: {}, Length: {}, Top: {}, Sealed: {}".format(str(self.base), str(self.offset), str(self.cursor), str(self.length), str(self.top), str(self.sealed))

    def __str__(self):
        return "Base: {}, Offset: {}, Cursor: {}, Length: {}, Top: {}, Sealed: {}".format(str(self.base), str(self.offset), str(self.cursor), str(self.length), str(self.top), str(self.sealed))


