"""
Test the provenance parser handling of memory accesses.

We check that:

1. capabilities stored in memory are recovered correctly
2. dereferences of capabilities are recorded
3. locations where capabilities are stored are recorded
"""

import pytest
import logging
import tempfile

from cheriplot.provenance.parser import (
    CheriMipsModelParser, MissingParentError, DereferenceUnknownCapabilityError)
from cheriplot.provenance.model import CheriNodeOrigin, CheriCapPerm

from cheriplot.core.test import pct_cap
from tests.provenance.helper import (
    assert_graph_equal, mk_pvertex, mk_vertex_mem, mk_vertex_deref,
    ProvenanceTraceWriter)

logging.basicConfig(level=logging.DEBUG)

# some capabilities used in the tests
perm = CheriCapPerm.LOAD | CheriCapPerm.STORE
pcc = pct_cap(0x1000, 0x0c, 0x1000, CheriCapPerm.LOAD | CheriCapPerm.EXEC)
kcc_default = pct_cap(0x00, 0x00, 0xffffffffffffffff, CheriCapPerm.all())
kdc_default = pct_cap(0x00, 0x00, 0xffffffffffffffff, CheriCapPerm.all())
ddc = pct_cap(0x0, 0x0, 0x10000, perm)
start_cap = pct_cap(0x1000, 0x0, 0x1000, perm)

# Common bit of the test trace initializing registers
#
# ROOT(c1)
# ROOT(kcc) - inferred
# ROOT(kdc) - inferred
# ROOT(pcc)
# 
trace_mem_init = (
    ("cmove $c1, $c1", { # vertex 0
        "c1": start_cap,
        "pvertex": mk_pvertex(start_cap)
    }),
    ("cmove $c29, $c29", { # inferred kcc vertex 1
        "c29": kcc_default,
        "pvertex": mk_pvertex(kcc_default)
    }),
    ("cmove $c30, $c30", { # inferred kdc vertex 2
        "c30": kdc_default,
        "pvertex": mk_pvertex(kdc_default)
    }),
    ("cmove $c31, $c31", { # vertex 3
        "c31": pcc,
        "pvertex": mk_pvertex(pcc)
    }),
    ("eret", {}), # mark initialization end
)

# Generate a capabilities from c1, store it, do other capability operations
# with c1 and restore c1.
# Check the a capability derived from c1 after the restore is attached to
# the correct node.
#
# ROOT(c1) -> v6
#         `-> v5
# ROOT(ddc) - inferred
trace_mem_st_ld = (
    # get ddc
    ("cgetdefault $c2", { # ddc vertex 4
        "c2": ddc,
        "pvertex": mk_pvertex(ddc)
    }),
    # worker set split here
    ("lui $at, 0x100", {"1": 0x100}),
    ("csetoffset $c2, $c2, $at", {"c2": pct_cap(0x0, 0x100, 0x10000, perm)}),
    # store vertex 0 at 0x100
    ("csc $c1, $zero, 0x0($c2)", {
        "c1": start_cap,
        "store": True,
        "mem": 0x100,
        "vertex_mem": mk_vertex_mem(0, 0x100, "store"),
        "vertex_deref": mk_vertex_deref(4, 0x100, True, "store")
    }),
    # create (v4 ddc) -> (v6) and place it in c3
    ("csetbounds $c1, $c2, $at", { # vertex 5
        "c1": pct_cap(0x1000, 0x0, 0x100, perm),
        "pvertex": mk_pvertex(pct_cap(0x1000, 0x0, 0x100, perm),
                              parent=4, origin=CheriNodeOrigin.SETBOUNDS)
    }),
    # reload vertex 0 from 0x100
    ("clc $c1, $zero, 0x0($c2)", {
        "c1": start_cap,
        "load": True,
        "mem": 0x100,
        "vertex_mem": mk_vertex_mem(0, 0x100, "load"),
        "vertex_deref": mk_vertex_deref(4, 0x100, True, "load")
    }),
    # create ([0x100]) -> (v6) that should be (v0) -> (v6)
    ("csetbounds $c1, $c1, $at", { # vertex 6
        "c1": pct_cap(0x1000, 0x0, 0x100, perm),
        "pvertex": mk_pvertex(pct_cap(0x1000, 0x0, 0x100, perm),
                              parent=0, origin=CheriNodeOrigin.SETBOUNDS)
    }),
)

# store multiple capabilities to the same address and check
# the the parser keeps track of the last one correctly
#
# ROOT(c1) -> v5 -> v6
# ROOT(ddc) - inferred
trace_mem_2st_ld = (
    # get ddc
    ("cgetdefault $c2", { # ddc vertex 4
        "c2": ddc,
        "pvertex": mk_pvertex(ddc)
    }),
    ("lui $at, 0x100", {"1": 0x150}),
    ("csetoffset $c2, $c2, $at", {"c2": pct_cap(0x0, 0x150, 0x10000, perm)}),
    # store v0 at 0x150
    ("csc $c1, $zero, 0x0($c2)", {
        "c1": start_cap,
        "store": True,
        "mem": 0x150,
        "vertex_mem": mk_vertex_mem(0, 0x150, "store"),
        "vertex_deref": mk_vertex_deref(4, 0x150, True, "store")
    }),
    # worker set split here
    # create new cap in c1
    ("csetbounds $c1, $c2, $at", { # vertex 5
        "c1": pct_cap(0x1000, 0x0, 0x150, perm),
        "pvertex": mk_pvertex(pct_cap(0x1000, 0x0, 0x150, perm),
                              parent=4, origin=CheriNodeOrigin.SETBOUNDS)
    }),
    # store v5 at 0x150
    ("csc $c1, $zero, 0x0($c2)", {
        "c1": start_cap,
        "store": True,
        "mem": 0x150,
        "vertex_mem": mk_vertex_mem(5, 0x150, "store"),
        "vertex_deref": mk_vertex_deref(4, 0x150, True, "store")
    }),
    # clobber c1
    ("cmove $c1, $c2", {"c1": pct_cap(0x0, 0x150, 0x10000, perm)}),
    # load v5 from 0x150
    ("clc $c1, $zero, 0x0($c2)", {
        "c1": pct_cap(0x1000, 0x0, 0x150, perm),
        "load": True,
        "mem": 0x150,
        "vertex_mem": mk_vertex_mem(5, 0x150, "load"),
        "vertex_deref": mk_vertex_deref(4, 0x150, True, "load")
    }),
    # derive loaded cap and make sure that the node parent is v5
    ("lui $at, 0x100", {"1": 0x100}),
    ("csetbounds $c1, $c2, $at", { # vertex 6
        "c1": pct_cap(0x1000, 0x0, 0x150, perm),
        "pvertex": mk_pvertex(pct_cap(0x1000, 0x0, 0x150, perm),
                              parent=4, origin=CheriNodeOrigin.SETBOUNDS)
    }),
)

# A root node is created when loading a capability from
# a previously unseen location.
#
# ROOT(v4)
trace_mem_st_ld_root = (
    # split worker set here
    ("clc $c2, $zero, 0x700($c1)", { # vertex 4
        "c2": pct_cap(0x2000, 0x0, 0x1000, perm),
        "pvertex": mk_pvertex(pct_cap(0x2000, 0x0, 0x1000, perm)),
        "load": True,
        "mem": 0x1700,
        "vertex_deref": mk_vertex_deref(0, 0x1700, True, "load"),
        "vertex_mem": mk_vertex_mem(4, 0x1700, "load"),
    }),
    ("csc $c4, $zero, 0xf00($c1)", { # vertex 5
        "c4": pct_cap(0x8000, 0x100, 0x2000, perm),
        "pvertex": mk_pvertex(pct_cap(0x8000, 0x100, 0x2000, perm)),
        "store": True,
        "mem": 0x1f00,
        "vertex_deref": mk_vertex_deref(0, 0x1f00, True, "store"),
        "vertex_mem": mk_vertex_mem(5, 0x1f00, "store")
    }),
    # pad to make the working set of workers to split at the marked point
    ("nop", {}), ("nop", {}), ("nop", {}),
)

# invalid cap ld/st do not propagate nodes nor creates roots
#
trace_mem_st_ld_invalid = (
    # split worker set here
    ("clc $c2, $zero, 0x800($c1)", {
        "c2": pct_cap(0xbadadd12, 0xbad, 0x1000, 0xbaad, valid=False),
        "load": True,
        "mem": 0x1800,
        "vertex_deref": mk_vertex_deref(0, 0x1800, True, "load")
    }),
    ("csc $c2, $zero, 0x800($c1)", {
        "c2": pct_cap(0xbadadd12, 0xbad, 0x1000, 0xbaad, valid=False),
        "load": True,
        "mem": 0x1800,
        "vertex_deref": mk_vertex_deref(0, 0x1800, True, "load")
    }),
    # pad to make the working set of workers to split at the marked point
    ("nop", {}), ("nop", {}), ("nop", {}),
)

# deref unknown register should give an error
trace_mem_deref_unknown_cap = (
    ("clc $c1, $zero, 0x0($c4)", {
        "c1": pct_cap(0xfa11, 0x0, 0x1000, 0xfa11),
        "load": True,
        "mem": 0xfa11add12
    }),
)

trace_mem_deref_unknown_reg = (
    ("cld $v0, $zero, 0x0($c4)", {
        "2": 0xfa11ed,
        "load": True,
        "mem": 0xfa11add12
    }),
)

# test for the subgraph merge logic with
# v0 - - > Dummy -> ROOT(v5)
#               `-> v4
# with dereference/store data to check it is propagated correctly.
# Trace init is repeated because we need to control the exact
# number of instruction to make the workers split the trace
# at the intended point.
trace_mem_mp_deref_merge = (
    # split worker set here
    # derive something from c1 (which is a dummy vertex in worker 2)
    ("lui $at, 0x100", {"1": 0x100}),
    ("csetbounds $c2, $c1, $at", { # vertex 4
        "c2": pct_cap(0x1000, 0x0, 0x100, perm),
        "pvertex": mk_pvertex(pct_cap(0x1000, 0x0, 0x100, perm),
                              parent=0, origin=CheriNodeOrigin.SETBOUNDS),
    }),
    # dereference and store c1 so that the dummy vertex takes some
    # data to propagate to v0
    ("csc $c1, $zero, 0x0($c1)", {
        "c1": start_cap,
        "mem": 0x1000,
        "store": True,
        "vertex_deref": mk_vertex_deref(0, 0x1000, True, "store"),
        "vertex_mem": mk_vertex_mem(0, 0x1000, "store"),
    }),
    # create a root that goes in c1
    ("cgetdefault $c1", { # vertex 5
        "c1": ddc,
        "pvertex": mk_pvertex(ddc)
    }),
    # pad to make the working set of workers to split at the marked point
    ("nop", {}),
)

# Test subgraph merge logic for memory-propagated graph vertices.
# A vertex is stored in worker-1 and loaded from worker-2 to make
# sure that anything generated in worker-2 from the loaded vertex
# is correctly attached to the original vertex in worker-1.
#
# Trace init is repeated because we need to control the exact
# number of instruction to make the workers split the trace
# at the intended point.
trace_mem_mp_vertex_map = (
    # store c1 in memory
    ("csc $c1, $zero, 0x0($c1)", {
        "c1": start_cap,
        "store": True,
        "mem": 0x1000,
        "vertex_deref": mk_vertex_deref(0, 0x1000, True, "store"),
        "vertex_mem": mk_vertex_mem(0, 0x1000, "store"),
    }),
    # split worker set here
    ("clc $c2, $zero, 0x0($c1)", {
        "c2": start_cap,
        "load": True,
        "mem": 0x1000,
        "vertex_deref": mk_vertex_deref(0, 0x1000, True, "load"),
        "vertex_mem": mk_vertex_mem(0, 0x1000, "load"),
    }),
    ("lui $at, 0x100", {"1": 0x100}),
    ("csetbounds $c3, $c2, $at", { # vertex 4
        "c3": pct_cap(0x1000, 0x0, 0x100, perm),
        "pvertex": mk_pvertex(pct_cap(0x1000, 0x0, 0x100, perm),
                              parent=0, origin=CheriNodeOrigin.SETBOUNDS),
    }),
    # pad to make the working set of workers to split at the marked point
    ("nop", {}), ("nop", {}), ("nop", {}), ("nop", {}),
)

@pytest.mark.timeout(4)
@pytest.mark.parametrize("threads", [1, 2])
@pytest.mark.parametrize("trace", [
    (trace_mem_init, trace_mem_st_ld),
    (trace_mem_init, trace_mem_2st_ld),
    (trace_mem_init, trace_mem_st_ld_root),
    (trace_mem_init, trace_mem_st_ld_invalid),
    (trace_mem_init, trace_mem_mp_deref_merge,),
    (trace_mem_init, trace_mem_mp_vertex_map,),
])
def test_mem_tracking(trace, threads):
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

@pytest.mark.skip(reason="Need to decide what to do in those cases now")
@pytest.mark.timeout(4)
@pytest.mark.parametrize("threads", [1])
@pytest.mark.parametrize("trace,exc_type", [
    ((trace_mem_init, trace_mem_deref_unknown_cap),
     DereferenceUnknownCapabilityError),
    ((trace_mem_init, trace_mem_deref_unknown_reg),
     DereferenceUnknownCapabilityError),
])
def test_mem_errors(trace, exc_type, threads):
    """
    Test expected failure conditions where 
    the parser should throw an error.
    """

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
        with pytest.raises(exc_type) as excinfo:
            parser.parse()
