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
    assert_graph_equal, mk_pvertex, mk_vertex_mem, mk_vertex_deref, mk_cvertex,
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
    ("", { # call graph root
        "cvertex": mk_cvertex(None, vid="call-root")
    }),
    ("cmove $c1, $c1", { # vertex 0
        "c1": start_cap,
        "pvertex": mk_pvertex(start_cap, vid="start")
    }),
    ("cmove $c29, $c29", { # inferred kcc vertex 1
        "c29": kcc_default,
        "pvertex": mk_pvertex(kcc_default, vid="kcc")
    }),
    ("cmove $c30, $c30", { # inferred kdc vertex 2
        "c30": kdc_default,
        "pvertex": mk_pvertex(kdc_default, vid="kdc")
    }),
    ("cmove $c31, $c31", { # vertex 3
        "c31": pcc,
        "pvertex": mk_pvertex(pcc, vid="pcc")
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
        "pvertex": mk_pvertex(ddc, vid="ddc")
    }),
    # worker set split here
    ("lui $at, 0x100", {"1": 0x100}),
    ("csetoffset $c2, $c2, $at", {"c2": pct_cap(0x0, 0x100, 0x10000, perm)}),
    # store vertex 0 at 0x100
    ("csc $c1, $zero, 0x0($c2)", {
        "c1": start_cap,
        "store": True,
        "mem": 0x100,
        "vertex_mem": mk_vertex_mem("start", 0x100, "store"),
        "vertex_deref": mk_vertex_deref("ddc", 0x100, True, "store")
    }),
    # create (v4 ddc) -> (v6) and place it in c3
    ("csetbounds $c1, $c2, $at", { # vertex 5
        "c1": pct_cap(0x1000, 0x0, 0x100, perm),
        "pvertex": mk_pvertex(pct_cap(0x1000, 0x0, 0x100, perm),
                              parent="ddc", origin=CheriNodeOrigin.SETBOUNDS,
                              vid="ddc_setbounds")
    }),
    # reload vertex 0 from 0x100
    ("clc $c1, $zero, 0x0($c2)", {
        "c1": start_cap,
        "load": True,
        "mem": 0x100,
        "vertex_mem": mk_vertex_mem("start", 0x100, "load"),
        "vertex_deref": mk_vertex_deref("ddc", 0x100, True, "load"),
        "pfree": "ddc_setbounds",
    }),
    # create ([0x100]) -> (v6) that should be (v0) -> (v6)
    ("csetbounds $c1, $c1, $at", { # vertex 6
        "c1": pct_cap(0x1000, 0x0, 0x100, perm),
        "pvertex": mk_pvertex(pct_cap(0x1000, 0x0, 0x100, perm),
                              parent="start", origin=CheriNodeOrigin.SETBOUNDS),
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
        "pvertex": mk_pvertex(ddc, vid="ddc")
    }),
    ("lui $at, 0x200", {"1": 0x200}),
    ("csetoffset $c2, $c2, $at", {"c2": pct_cap(0x0, 0x200, 0x10000, perm)}),
    # store v0 at 0x200
    ("csc $c1, $zero, 0x0($c2)", {
        "c1": start_cap,
        "store": True,
        "mem": 0x200,
        "vertex_mem": mk_vertex_mem("start", 0x200, "store"),
        "vertex_deref": mk_vertex_deref("ddc", 0x200, True, "store")
    }),
    # worker set split here
    # create new cap in c1
    ("csetbounds $c1, $c2, $at", { # vertex 5
        "c1": pct_cap(0x1000, 0x0, 0x150, perm),
        "pvertex": mk_pvertex(pct_cap(0x1000, 0x0, 0x150, perm),
                              parent="ddc", origin=CheriNodeOrigin.SETBOUNDS,
                              vid="v1000")
    }),
    # store v5 at 0x200
    ("csc $c1, $zero, 0x0($c2)", {
        "c1": start_cap,
        "store": True,
        "mem": 0x200,
        "vertex_mem": mk_vertex_mem("v1000", 0x200, "store"),
        "vertex_deref": mk_vertex_deref("ddc", 0x200, True, "store"),
        "vertex_mem_overwrite": mk_vertex_mem("start", 0x200, "delete"),
        "pfree": "start",
    }),
    # clobber c1
    ("cmove $c1, $c2", {"c1": pct_cap(0x0, 0x150, 0x10000, perm)}),
    # load v5 from 0x200
    ("clc $c1, $zero, 0x0($c2)", {
        "c1": pct_cap(0x1000, 0x0, 0x150, perm),
        "load": True,
        "mem": 0x200,
        "vertex_mem": mk_vertex_mem("v1000", 0x200, "load"),
        "vertex_deref": mk_vertex_deref("ddc", 0x200, True, "load")
    }),
    # derive loaded cap and make sure that the node parent is v5
    ("lui $at, 0x100", {"1": 0x100}),
    ("csetbounds $c1, $c2, $at", { # vertex 6
        "c1": pct_cap(0x1000, 0x0, 0x150, perm),
        "pvertex": mk_pvertex(pct_cap(0x1000, 0x0, 0x150, perm),
                              parent="ddc", origin=CheriNodeOrigin.SETBOUNDS)
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
        "pvertex": mk_pvertex(pct_cap(0x2000, 0x0, 0x1000, perm), vid="v2000"),
        "load": True,
        "mem": 0x1700,
        "vertex_deref": mk_vertex_deref("start", 0x1700, True, "load"),
        "vertex_mem": mk_vertex_mem("v2000", 0x1700, "load"),
    }),
    ("csc $c4, $zero, 0xf00($c1)", { # vertex 5
        "c4": pct_cap(0x8000, 0x100, 0x2000, perm),
        "pvertex": mk_pvertex(pct_cap(0x8000, 0x100, 0x2000, perm), vid="v8000"),
        "store": True,
        "mem": 0x1f00,
        "vertex_deref": mk_vertex_deref("start", 0x1f00, True, "store"),
        "vertex_mem": mk_vertex_mem("v8000", 0x1f00, "store")
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
        "vertex_deref": mk_vertex_deref("start", 0x1800, True, "load")
    }),
    ("csc $c2, $zero, 0x800($c1)", {
        "c2": pct_cap(0xbadadd12, 0xbad, 0x1000, 0xbaad, valid=False),
        "load": True,
        "mem": 0x1800,
        "vertex_deref": mk_vertex_deref("start", 0x1800, True, "load")
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
                              parent="start", origin=CheriNodeOrigin.SETBOUNDS),
    }),
    # dereference and store c1 so that the dummy vertex takes some
    # data to propagate to v0
    ("csc $c1, $zero, 0x0($c1)", {
        "c1": start_cap,
        "mem": 0x1000,
        "store": True,
        "vertex_deref": mk_vertex_deref("start", 0x1000, True, "store"),
        "vertex_mem": mk_vertex_mem("start", 0x1000, "store"),
    }),
    # create a root that goes in c1
    ("cgetdefault $c1", { # vertex 5
        "c1": ddc,
        "pvertex": mk_pvertex(ddc, vid="ddc")
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
        "vertex_deref": mk_vertex_deref("start", 0x1000, True, "store"),
        "vertex_mem": mk_vertex_mem("start", 0x1000, "store"),
    }),
    # split worker set here
    ("clc $c2, $zero, 0x0($c1)", {
        "c2": start_cap,
        "load": True,
        "mem": 0x1000,
        "vertex_deref": mk_vertex_deref("start", 0x1000, True, "load"),
        "vertex_mem": mk_vertex_mem("start", 0x1000, "load"),
    }),
    ("lui $at, 0x100", {"1": 0x100}),
    ("csetbounds $c3, $c2, $at", { # vertex 4
        "c3": pct_cap(0x1000, 0x0, 0x100, perm),
        "pvertex": mk_pvertex(pct_cap(0x1000, 0x0, 0x100, perm),
                              parent="start", origin=CheriNodeOrigin.SETBOUNDS),
    }),
    # pad to make the working set of workers to split at the marked point
    ("nop", {}), ("nop", {}), ("nop", {}), ("nop", {}),
)

# Test memory overwrite event
# DELETE events should be issued to the vertex that is removed from a memory location
trace_mem_overwrite = (
    ("cmove $c2, $c2", {
        "c2": pct_cap(0x2000, 0x0, 0x1000, perm),
        "pvertex": mk_pvertex(pct_cap(0x2000, 0x0, 0x1000, perm), vid="v2000")
    }),
    ("cmove $c3, $c3", {
        "c3": pct_cap(0x3000, 0x0, 0x1000, perm),
        "pvertex": mk_pvertex(pct_cap(0x3000, 0x0, 0x1000, perm), vid="v3000")
    }),
    ("csc $c2, $zero, 0x0($c1)", {
        "store": True,
        "mem": 0x1000,
        "vertex_deref": mk_vertex_deref("start", 0x1000, True, "store"),
        "vertex_mem": mk_vertex_mem("v2000", 0x1000, "store"),
    }),
    ("lui $at, 0x1000", {"1": 0x1000}),
    ("lui $v0, 0x0", {"2": 0x0}),
    ("sb $v0, 0x0($at)", {
        "store": True,
        "mem": 0x1000,
        "vertex_mem_overwrite": mk_vertex_mem("v2000", 0x1000, "delete"),
    }),
    ("csc $c2, $zero, 0x0($c1)", {
        "store": True,
        "mem": 0x1000,
        "vertex_deref": mk_vertex_deref("start", 0x1000, True, "store"),
        "vertex_mem": mk_vertex_mem("v2000", 0x1000, "store"),
    }),
    ("csc $c3, $zero, 0x0($c1)", {
        "store": True,
        "mem": 0x1000,
        "vertex_deref": mk_vertex_deref("start", 0x1000, True, "store"),
        "vertex_mem": mk_vertex_mem("v3000", 0x1000, "store"),
        "vertex_mem_overwrite": mk_vertex_mem("v2000", 0x1000, "delete"),
    }),
)

# Test memory overwrite events for unaligned accesses and
# across subgraph merge
trace_mem_mp_overwrite = (
    ("", {
        "cvertex": mk_cvertex(None, vid="call-root"),
    }),
    ("cmove $c1, $c1", {
        "c1": pct_cap(0x10, 0x0, 0x100, perm),
        "pvertex": mk_pvertex(pct_cap(0x10, 0x0, 0x100, perm), vid="v10"),
    }),
    ("cmove $c2, $c2", {
        "c2": pct_cap(0x20, 0x0, 0x100, perm),
        "pvertex": mk_pvertex(pct_cap(0x20, 0x0, 0x100, perm), vid="v20"),
    }),
    ("cmove $c3, $c3", {
        "c2": pct_cap(0x0, 0x0, 0xf000, perm),
        "pvertex": mk_pvertex(pct_cap(0x0, 0x0, 0xf000, perm), vid="target"),
    }),
    ("lui $at, 0x1000", {"1": 0x1000}),
    ("csc $c1, $zero, 0x0($c3)", {
        "store": True,
        "mem": 0x0,
        "vertex_deref": mk_vertex_deref("target", 0x0, True, "store"),
        "vertex_mem": mk_vertex_mem("v10", 0x0, "store"),
    }),
    ("csc $c2, $at, 0x0($c3)", {
        "store": True,
        "mem": 0x1000,
        "vertex_deref": mk_vertex_deref("target", 0x1000, True, "store"),
        "vertex_mem": mk_vertex_mem("v20", 0x1000, "store"),
    }),
    # worker set split here
    ("csd $at, $zero, 0x0($c3)", {
        "store": True,
        "mem": 0x0,
        "vertex_deref": mk_vertex_deref("target", 0x0, False, "store"),
        "vertex_mem_overwrite": mk_vertex_mem("v10", 0x0, "delete"),
    }),
    ("sb $at, 0x1005($at)", {
        "store": True,
        "mem": 0x1005,
        "vertex_mem_overwrite": mk_vertex_mem("v20", 0x1000, "delete"),
    }),
    # pad to make the worker set split at the marked point
    ("nop", {}), ("nop", {}), ("nop", {}), ("nop", {}),
)

# Test t_free with memory overwrite
# t_free should be set to the original vertex across the subgraph boundary
trace_mem_mp_out_of_scope = (
    ("", {
        "cvertex": mk_cvertex(None, vid="call-root"),
    }),
    ("cmove $c1, $c1", {
        "c1": pct_cap(0x10, 0x0, 0x100, perm),
        "pvertex": mk_pvertex(pct_cap(0x10, 0x0, 0x100, perm), vid="v10"),
    }),
    ("cmove $c2, $c2", {
        "c2": pct_cap(0x20, 0x0, 0x100, perm),
        "pvertex": mk_pvertex(pct_cap(0x20, 0x0, 0x100, perm), vid="v20"),
    }),
    ("cmove $c3, $c3", {
        "c3": pct_cap(0x0, 0x0, 0xf000, perm),
        "pvertex": mk_pvertex(pct_cap(0x0, 0x0, 0xf000, perm), vid="target"),
    }),
    ("lui $at, 0x1000", {"1": 0x1000}),
    ("csc $c1, $zero, 0x0($c3)", {
        "store": True,
        "mem": 0x0,
        "vertex_deref": mk_vertex_deref("target", 0x0, True, "store"),
        "vertex_mem": mk_vertex_mem("v10", 0x0, "store"),
    }),
    ("csc $c2, $at, 0x0($c3)", {
        "store": True,
        "mem": 0x1000,
        "vertex_deref": mk_vertex_deref("target", 0x1000, True, "store"),
        "vertex_mem": mk_vertex_mem("v20", 0x1000, "store"),
    }),
    # remove the vertices from the register file
    ("cmove $c2, $c3", {
        "c2": pct_cap(0x0, 0x0, 0xf000, perm),
    }),
    ("cmove $c1, $c3", {
        "c1": pct_cap(0x0, 0x0, 0xf000, perm),
    }),
    # worker set split here
    # remove vertices from memory, they should be also marked in t_free
    ("csd $at, $zero, 0x0($c3)", {
        "store": True,
        "mem": 0x0,
        "vertex_deref": mk_vertex_deref("target", 0x0, False, "store"),
        "vertex_mem_overwrite": mk_vertex_mem("v10", 0x0, "delete"),
        "pfree": "v10",
    }),
    ("sb $at, 0x1005($at)", {
        "store": True,
        "mem": 0x1005,
        "vertex_mem_overwrite": mk_vertex_mem("v20", 0x1000, "delete"),
        "pfree": "v20",
    }),
    # pad to make the worker set split at the marked point
    ("nop", {}), ("nop", {}),
)

# Test t_free with memory overwrite
# the second subgraph would set t_free because a vertex is deleted there
# but globally it is still available
trace_mem_mp_in_scope = (
    ("", {
        "cvertex": mk_cvertex(None, vid="call-root"),
    }),
    ("cmove $c1, $c1", {
        "c1": pct_cap(0x10, 0x0, 0x100, perm),
        "pvertex": mk_pvertex(pct_cap(0x10, 0x0, 0x100, perm), vid="v10"),
    }),
    ("cmove $c3, $c3", {
        "c3": pct_cap(0x0, 0x0, 0xf000, perm),
        "pvertex": mk_pvertex(pct_cap(0x0, 0x0, 0xf000, perm), vid="target"),
    }),
    ("lui $at, 0x1000", {"1": 0x1000}),
    ("csc $c1, $zero, 0x0($c3)", {
        "store": True,
        "mem": 0x0,
        "vertex_deref": mk_vertex_deref("target", 0x0, True, "store"),
        "vertex_mem": mk_vertex_mem("v10", 0x0, "store"),
    }),
    # worker set split here
    ("csc $c1, $at, 0x0($c3)", {
        "store": True,
        "mem": 0x1000,
        "vertex_deref": mk_vertex_deref("target", 0x1000, True, "store"),
        "vertex_mem": mk_vertex_mem("v10", 0x1000, "store"),
    }),
    # remove the vertices from the register file
    ("cmove $c1, $c3", {
        "c1": pct_cap(0x0, 0x0, 0xf000, perm),
    }),
    ("csd $at, $at, 0x0($c3)", {
        "store": True,
        "mem": 0x1000,
        "vertex_deref": mk_vertex_deref("target", 0x1000, False, "store"),
        "vertex_mem_overwrite": mk_vertex_mem("v10", 0x1000, "delete"),
    }),
    # pad to make the worker set split at the marked point
    ("nop", {}),
)

@pytest.mark.timeout(5)
@pytest.mark.parametrize("threads", [1, 2])
@pytest.mark.parametrize("trace", [
    (trace_mem_init, trace_mem_st_ld),
    (trace_mem_init, trace_mem_2st_ld),
    (trace_mem_init, trace_mem_st_ld_root),
    (trace_mem_init, trace_mem_st_ld_invalid),
    (trace_mem_init, trace_mem_mp_deref_merge,),
    (trace_mem_init, trace_mem_mp_vertex_map,),
    (trace_mem_init, trace_mem_overwrite,),
    (trace_mem_mp_overwrite,),
    (trace_mem_mp_out_of_scope,),
    (trace_mem_mp_in_scope,),
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
