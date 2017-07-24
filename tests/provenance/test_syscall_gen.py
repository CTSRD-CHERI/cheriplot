"""
Test the basic behaviour of the provenance trace parser
"""

import pytest
import logging
import tempfile

from cheriplot.provenance.parser import (
    CheriMipsModelParser, MissingParentError, DereferenceUnknownCapabilityError)
from cheriplot.provenance.model import CheriNodeOrigin, CheriCapPerm

from cheriplot.core.test import pct_cap
from tests.provenance.helper import (
    assert_graph_equal, mk_pvertex, mk_vertex_mem, mk_vertex_deref, mk_cvertex,
    ProvenanceTraceWriter)

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
    ("", { # call graph root
        "cvertex": mk_cvertex(None, vid="call-root")
    }),
    # {0x1000}
    ("cmove $c1, $c1", { # vertex 0
        "c1": start_cap,
        "pvertex": mk_pvertex(start_cap, vid="start")
    }),
    ("cmove $c30, $c30", { # kdc vertex 1
        "c30": kdc_default,
        "pvertex": mk_pvertex(kdc_default, vid="kdc")
    }),
    ("cmove $c31, $c31", { # vertex 2
        "c31": pcc,
        "pvertex": mk_pvertex(pcc, vid="pcc")
    }),
    ("eret", {}), # mark initialization end
    # {0x1010}
)

# trace_sys_mmap = (
#     # {0x1014}
#     ("lui $v0, 447", {"2": 447}), # mmap code
#     # we do not care about the syscall args
#     ("syscall", {"exc": 8}),
#     # {0x101c}
#     ("cincoffset $c1, $kdc, $zero", {"c1": kdc_default}),
#     # worker set split here
#     # simulate return of mmap(0x1000, 0x1000, ...)
#     ("lui $at, 0x1000", {"1": 0x1000}),
#     ("csetoffset $c1, $c1, $at", {
#         "c1": pct_cap(0x00, 0x1000, 0xffffffffffffffff, CheriCapPerm.all())
#     }),
#     ("csetbounds $c2, $c1, $at", { # vertex 3
#         "c2": pct_cap(0x1000, 0x0, 0x1000, CheriCapPerm.all()),
#         "pvertex": mk_pvertex(pct_cap(0x1000, 0x0, 0x1000, CheriCapPerm.all()),
#                               parent="kdc", origin=CheriNodeOrigin.SETBOUNDS,
#                               vid="v1000"),
#     }),
#     ("cmove $c3, $c2", {
#         "c3": pct_cap(0x1000, 0x0, 0x1000, CheriCapPerm.all())
#     }),
#     # epcc address should match the expected return
#     ("lui $at, 0x14", {"1": 0x18}),
#     ("csetoffset $c31, $c31, $at", {
#         "c31": pct_cap(0x1000, 0x18, 0x1000, exec_perm)
#     }),
#     ("eret", {
#         # expect the vertex to be used in a syscall ret
#         "vertex_call": mk_vertex_call("v1000", 447, "syscall_ret"),
#     }),
# )

# trace_sys_munmap = (
#     # {0x100c}
#     ("lui $v0, 73", {"2": 73}), # munmap code
#     # simulate munmap arg0
#     ("lui $at, 0x1c", {"1": 0x100}),
#     # worker set split here
#     ("csetbounds $c3, $c1, $at", { # vertex 3
#         "c3": pct_cap(0x1000, 0x0, 0x100, perm),
#         "pvertex": mk_pvertex(pct_cap(0x1000, 0x0, 0x100, perm),
#                               parent="start", origin=CheriNodeOrigin.SETBOUNDS,
#                               vid="v1000"),
#     }),
#     # {1014}
#     # we do not care about the syscall args
#     ("syscall", {
#         # expect the vertex to be used in a syscall ret
#         "vertex_call": mk_vertex_call("v1000", 73, "syscall_arg"),
#     }),
#     # epcc address should match the expected return 0x1014
#     ("lui $at, 0x14", {"1": 0x14}),
#     ("csetoffset $c31, $c31, $at", {
#         "c31": pct_cap(0x1000, 0x14, 0x1000, exec_perm)
#     }),
#     ("eret", {}),
# )

@pytest.mark.timeout(4)
@pytest.mark.parametrize("threads", [1, 2])
@pytest.mark.parametrize("trace", [
    # (trace_init, trace_sys_mmap),
    # (trace_init, trace_sys_munmap),
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
        parser = CheriMipsModelParser(trace_path=tmp.name, threads=threads)
        parser.parse()
        # check the provenance graph model
        pgm = parser.get_model()
        assert_graph_equal(w.pgm.graph, pgm.graph)
