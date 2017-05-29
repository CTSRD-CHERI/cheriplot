"""
Test the basic behaviour of the provenance trace parser
"""

import pytest
import logging
import tempfile

from cheriplot.provenance import *

from cheriplot.core.test import pct_cap
from tests.provenance.helper import *

logging.basicConfig(level=logging.DEBUG)

# some capabilities that are used in the test
perm = CheriCapPerm.LOAD | CheriCapPerm.STORE
exec_perm = CheriCapPerm.LOAD | CheriCapPerm.EXEC
pcc = pct_cap(0x1000, 0x00, 0x1000, exec_perm)
kcc_default = pct_cap(0x00, 0x00, 0xffffffffffffffff, CheriCapPerm.all())
kdc_default = pct_cap(0x00, 0x00, 0xffffffffffffffff, CheriCapPerm.all())
ddc = pct_cap(0x0, 0x0, 0x10000, perm)
start_cap = pct_cap(0x1000, 0x0, 0x1000, perm)


# common part of the trace used for tests that do not
# require special initialization of the registers
trace_init = (
    # {0x1000}
    ("cmove $c1, $c1", { # vertex 0
        "c1": start_cap,
        "vertex": mk_vertex(start_cap, pc=0, t_alloc=0)
    }),
    (None, { # inferred kcc vertex 1
        "vertex": mk_vertex(kcc_default, pc=0, t_alloc=0)
    }),
    (None, { # inferred kdc vertex 2
        "vertex": mk_vertex(kdc_default, pc=0, t_alloc=0)
    }),
    ("cmove $c31, $c31", { # vertex 3
        "c31": pcc,
        "vertex": mk_vertex(pcc, pc=0, t_alloc=0)
    }),
    ("eret", {}), # mark initialization end
    # {0x100c}
)

trace_sys_mmap = (
    # {0x100c}
    ("lui $v0, 447", {"2": 447}), # mmap code
    # we do not care about the syscall args
    ("syscall", {}),
    # {0x1014}
    ("cincoffset $c1, $kdc, $zero", {"c1": kdc_default}),
    # worker set split here
    # simulate return of mmap(0x1000, 0x1000, ...)
    ("lui $at, 0x1000", {"1": 0x1000}),
    ("csetoffset $c1, $c1, $at", {
        "c1": pct_cap(0x00, 0x1000, 0xffffffffffffffff, CheriCapPerm.all())
    }),
    ("csetbounds $c2, $c1, $at", { # vertex 4
        "c2": pct_cap(0x1000, 0x0, 0x1000, CheriCapPerm.all()),
        "vertex": mk_vertex(pct_cap(0x1000, 0x0, 0x1000, CheriCapPerm.all()),
                            parent=2, origin=CheriNodeOrigin.SETBOUNDS),
    }),
    ("cmove $c3, $c2", {
        "c3": pct_cap(0x1000, 0x0, 0x1000, CheriCapPerm.all())
    }),
    # epcc address should match the expected return
    ("lui $at, 0x14", {"1": 0x14}),
    ("csetoffset $c31, $c31, $at", {
        "c31": pct_cap(0x1000, 0x14, 0x1000, exec_perm)
    }),
    ("eret", {
        # expect the vertex to be used in a syscall ret
        "vertex_call": mk_vertex_call(4, 447, "syscall_ret"),
    }),
)

trace_sys_munmap = (
    # {0x100c}
    ("lui $v0, 73", {"2": 73}), # munmap code
    # simulate munmap arg0
    ("lui $at, 0x1c", {"1": 0x100}),
    # worker set split here
    ("csetbounds $c3, $c1, $at", { # vertex 4
        "c3": pct_cap(0x1000, 0x0, 0x100, perm),
        "vertex": mk_vertex(pct_cap(0x1000, 0x0, 0x100, perm),
                            parent=0, origin=CheriNodeOrigin.SETBOUNDS),
    }),
    # {1014}
    # we do not care about the syscall args
    ("syscall", {
        # expect the vertex to be used in a syscall ret
        "vertex_call": mk_vertex_call(4, 73, "syscall_arg"),
    }),
    # epcc address should match the expected return 0x1014
    ("lui $at, 0x14", {"1": 0x14}),
    ("csetoffset $c31, $c31, $at", {
        "c31": pct_cap(0x1000, 0x14, 0x1000, exec_perm)
    }),
    ("eret", {}),
)

@pytest.mark.timeout(4)
@pytest.mark.parametrize("threads", [1, 2])
@pytest.mark.parametrize("trace", [
    (trace_init, trace_sys_mmap),
    (trace_init, trace_sys_munmap),
])
def test_syscall_simple(trace, threads):
    """Test provenance parser with the simplest trace possible."""

    with tempfile.NamedTemporaryFile() as tmp:
        # setup the mock trace
        w = ProvenanceTraceWriter(tmp.name)
        # multipart traces can be given so that common initialization
        # parts are not repeated
        w.write_trace(trace[0], pc=0x1000)
        for t in trace[1:]:
            w.write_trace(t)

        # get parsed graph
        parser = PointerProvenanceParser(trace_path=tmp.name)
        # force a single thread for this test
        parser.mp.threads = threads
        parser.parse()
        # check the provenance graph model
        pgm = parser.get_model()
        assert_graph_equal(w.pgm.graph, pgm.graph)
