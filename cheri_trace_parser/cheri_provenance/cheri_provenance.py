"""

Data structure that represents CHERI capabilities in memory.
The pointers are organised in tree-like structures that express provenance
of pointers via instuctions that derive a capability from a parent, such as
the CSetBounds and CFromPtr instructions.

XXX: notes for me
Should we consider CFromPtr for provenance analysis? it does create a capability
pointing to a memory region, probably more relevant in the hybrid ABI. It should
definetely be considered for tag distribution in memory.
"""

import pickle
import logging

from operator import attrgetter
from io import StringIO
from functools import reduce

logger = logging.getLogger(__name__)

# permission bits
CAP_LOAD = 0x2
CAP_STORE = 0x4
CAP_EXEC = 0x8
# XXXAM: it may be desirable to have a Capability class to represent
# data inside a capability register

class CheriCapNode:
    """
    Record a capability pointer

    This is both an element of the pointer provenance and memory trees
    """

    # instruction that was parsed to create the node
    UNKNOWN = -1
    C_SETBOUNDS = 1
    C_FROMPTR = 2
    C_PTR_SETBOUNDS = 3

    def __init__(self, cr=None):
        self.address = None
        self.base = None
        self.length = None
        self.offset = None
        self.permissions = None
        self.origin = self.UNKNOWN
        self.valid = False
        self.pc = None
        self.is_kernel = False

        if cr:
            self.base = cr.base
            self.length = cr.length
            self.offset = cr.offset
            self.permissions = cr.permissions
            self.valid = cr.valid

        # allocation and deallocation time (if any)
        self.t_alloc = -1
        self.t_free = -1

        # child nodes list
        self.children = []
        self.parent = None

    @property
    def bound(self):
        """
        convenience property to get base + length
        """
        if (self.base is not None and self.length is not None):
            return self.base + self.length
        return None

    def find_node(self, base, length):
        """
        Find node in the subtree with given base and length
        """
        if (self.base is not None and
            self.length is not None and
            self.offset is not None):
            if base == self.base and length == self.length:
                return self
            if (base < self.base or
                self.bound < base + length):
                return None
        for child in self.children:
            node = child.find_node(base, length)
            if node is not None:
                return node
        return None

    def remove(self, node):
        self.children.remove(node)

    def selfremove(self):
        self.parent.remove(self)

    def append(self, node):
        """
        Append node to the subtree, children are sorted
        by t_alloc
        """
        self.children.append(node)
        node.parent = self

    def __iter__(self):
       for child in self.children[:]:
           yield child
           for nextchild in child:
               yield nextchild

    def __bool__(self):
        """
        This prevent calling __len__ when doing boolean comparisons,
        since it is expensive
        """
        return True

    def __len__(self):
        return reduce(lambda length,node: length + len(node),
                      self.children, len(self.children))

    def __str__(self):
        return self.to_str()

    def visit(self, cbk):
        """
        Visit the subtree with a callback
        The callback is invoked for each node to make
        transformations
        """
        for n in self:
            cbk(n)

    def to_str(self, nest=0):
        dump = StringIO()
        addr = self.address if self.address is not None else 0
        base = self.base if self.base is not None else 0
        leng = self.length if self.length is not None else 0
        off = self.offset if self.offset is not None else 0
        pad = "    " * nest
        rwx = ["-", "-", "-"]
        if self.permissions is not None:
            if self.permissions & CAP_LOAD:
                rwx[0] = "r"
            if self.permissions & CAP_STORE:
                rwx[1] = "w"
            if self.permissions & CAP_EXEC:
                rwx[2] = "x"
            if self.permissions == 0:
                rwx = ["r", "w", "x"]
        dump.write("%s[%u @ %x <- b:%x o:%x l:%x p:%s]" %
                   (pad, self.t_alloc, addr, base, off, leng, "".join(rwx)))
        dump.write("(\n")
        for child in self.children:
            dump.write(child.to_str(nest + 1))
            dump.write(",\n")
        dump.write("%s)" % pad)
        return dump.getvalue()

    def check_consistency(self, violations):
        """
        Look for bound monotonicity violations, these
        are errors in the provenance tree build.
        A list of nodes violating the property is filled.
        """
        if (self.base is None or self.length is None):
            # root node
            return
        for child in self.children:
            if (self.base > child.base or
                child.base + child.length > self.base + self.length):
                violations.append(child)
                child.check_consistency(violations)
        return violations

    def check_duplicates(self, duplicates):
        """
        Look for nodes with the same base and length,
        there should be none.
        A list of duplicate nodes is filled with duplicates found.
        """
        for child in self.children:

            def _filter(x):
                if (x.base == child.base and
                    x.length == child.length):
                    return True
                return False
            # inefficient as we may scan duplicates multiple times
            # but in general there should be no duplicates
            dups = [c for c in self.children if _filter(c)]
            if len(dups) > 1:
                duplicates.append(child)
            child.check_duplicates(duplicates)
        return duplicates


class ProvenanceTree(CheriCapNode):
    """
    Tree that maps the provenance of capabilities, the root node is
    the root capability from which the children are created via
    CSetBounds or CFromPtr operations.
    """

    def __init__(self):
        super(ProvenanceTree, self).__init__()
        # map memory address and list of CheriCapNodes at that address
        # for fast search
        self.address_map = {}

    # def append(self, node):
    #     super(ProvenanceTree, self).append(node)
    #     # the root of the tree is not a valid node
    #     # (no capability associated with it)
    #     node.parent = None

    def __str__(self):
        dump = StringIO()
        dump.write("(")
        for child in self.children:
            dump.write(str(child))
            dump.write(",\n")
        dump.write(")")
        return dump.getvalue()


class CachedProvenanceTree(ProvenanceTree):
    """
    Provenance tree that can save and restore itself
    from a pickle file
    """

    def __init__(self):
        super(CachedProvenanceTree, self).__init__()

    def save(self, cache_file):
        with open(cache_file, "wb+") as fd:
            pickle.dump(self, fd, pickle.HIGHEST_PROTOCOL)
        logger.info("Caching provenance tree as %s", cache_file)

    def load(self, cache_file):
        with open(cache_file, "rb") as fd:
            self.__dict__.update(pickle.load(fd).__dict__)
        logger.info("Using cached provenance tree %s", cache_file)
