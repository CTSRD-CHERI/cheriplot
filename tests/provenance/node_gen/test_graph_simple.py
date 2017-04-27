"""
Test the basic behaviour of the provenance trace parser
"""

import pytest
import logging
import tempfile

from unittest import mock
from cheriplot.provenance import (
    PointerProvenanceParser, CheriNodeOrigin, CheriCapPerm, MissingParentError)

from cheriplot.core.test import pct_cap
from tests.provenance.helper import (
    assert_graph_equal, mk_vertex, ProvenanceTraceWriter)

logging.basicConfig(level=logging.DEBUG)

# some capabilities that are used in the test
perm = CheriCapPerm.LOAD | CheriCapPerm.STORE
pcc = pct_cap(0x1000, 0x0c, 0x1000, CheriCapPerm.LOAD | CheriCapPerm.EXEC)
kcc_default = pct_cap(0x00, 0x00, 0xffffffffffffffff, CheriCapPerm.all())
kdc_default = pct_cap(0x00, 0x00, 0xffffffffffffffff, CheriCapPerm.all())
kcc = pct_cap(0x00, 0xcc, 0xffffffff, CheriCapPerm.all())
kdc = pct_cap(0x00, 0xdc, 0xffffffff, CheriCapPerm.all())
ddc = pct_cap(0x0, 0x0, 0x10000, perm)
start_cap = pct_cap(0x1000, 0x0, 0x1000, perm)
ptr_cap = pct_cap(0x1000, 0x100, 0x1000, perm)
bound_cap = pct_cap(0x1100, 0x0, 0x100, perm)
perm_cap = pct_cap(0x1100, 0x0, 0x100, CheriCapPerm.STORE)

# generate the following expected tree
# ROOT -> P -> A
#          \
#           -> B
# ROOT(pcc)
# ROOT(kcc - inferred)
# ROOT(kdc - inferred)
#
# Notable behaviour:
# Root vertices are expected to have pc = 0 and creation time = 0
# when they are initialized from the initial register set.
trace_infer_kcc_kdc = (
    # NOTE: initialization must be in register-number order if we want to keep
    # ROOT ordering in the graph.
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
    ("lui $at, 0x100", {"1": 0x100}),
    ("cfromptr $c2, $c1, $at", { # vertex 4
        "c2": ptr_cap,
        "vertex": mk_vertex(ptr_cap, 0, CheriNodeOrigin.FROMPTR)
    }),
    ("daddiu $at, $at, 0x100", {"1": 0x200}),
    ("csetbounds $c1, $c2, $at", { # vertex 5
        "c1": bound_cap,
        "vertex": mk_vertex(bound_cap, 4, CheriNodeOrigin.SETBOUNDS)
    }),
    ("lui $at, 0x0c", {"1": 0x08}),
    ("candperm $c2, $c2, $at", { # vertex 6
        "c2": perm_cap,
        "vertex": mk_vertex(perm_cap, 4, CheriNodeOrigin.ANDPERM)
    })
)

# generate the following expected tree
# ROOT -> P -> A
#          \
#           -> B
# ROOT(pcc)
# ROOT(kcc)
# ROOT(kdc)
trace_explicit_kcc_kdc = (
    ("cmove $c1, $c1", { # vertex 0
        "c1": start_cap,
        "vertex": mk_vertex(start_cap, pc=0, t_alloc=0)
    }),
    ("cmove $c29, $c30", { # kcc vertex 1
        "c29": kcc,
        "vertex": mk_vertex(kcc, pc=0, t_alloc=0)
    }),
    ("cmove $c30, $c30", { # kdc vertex 2
        "c30": kdc,
        "vertex": mk_vertex(kdc, pc=0, t_alloc=0)
    }),
    ("cmove $c31, $c31", { # vertex 3
        "c31": pcc,
        "vertex": mk_vertex(pcc, pc=0, t_alloc=0)
    }),
    ("eret", {}),
    ("lui $at, 0x100", {"1": 0x100}),
    ("cfromptr $c2, $c1, $at", { # vertex 4
        "c2": ptr_cap,
        "vertex": mk_vertex(ptr_cap, 0, CheriNodeOrigin.FROMPTR)
    }),
    ("daddiu $at, $at, 0x100", {"1": 0x200}),
    ("csetbounds $c1, $c2, $at", { # vertex 5
        "c1": bound_cap,
        "vertex": mk_vertex(bound_cap, 4, CheriNodeOrigin.SETBOUNDS)
    }),
    ("lui $at, 0x0c", {"1": 0x08}),
    ("candperm $c2, $c2, $at", { # vertex 6
        "c2": perm_cap,
        "vertex": mk_vertex(perm_cap, 4, CheriNodeOrigin.ANDPERM)
    })
)

# invalid trace test: try to generate a provenance node from
# an uninitialized register.
# UNK -> P
trace_invalid_derive_from_unknown = (
    ("cmove $c31, $c31", { # pcc is always loaded after eret
        "c31": pcc,
        "vertex": mk_vertex(pcc)
    }),
    ("eret", {}),
    ("lui $at, 0x100", {"1": 0x100}),
    ("cfromptr $c2, $c1, $at", { # trigger error
        "c2": ptr_cap})
)

# invalid trace test: missing pcc in initial register set.
# EPCC is never set before returning to userspace.
trace_invalid_missing_initial_epcc = (
    ("eret", {}), # trigger error when tyring to load epcc in pcc
)

# generate trace to check that the parser keeps track of
# special registers correctly.
#
# The following provenance relationships are checked:
# i) in normal conditions cgetpcc gives the initial pcc node
# ii) during an exception/syscall cgetpcc gives kcc
# iii) during an exception/syscall epcc is the initial pcc
#
# ROOT(kcc) -> B (v3)
#          `-> B (v6)
# ROOT(kdc_default)
# ROOT(pcc) -> B (v3)
#          `-> B (v5)
trace_pcc_epcc_tracking = (
    ("cmove $c29, $c30", { # kcc vertex 0
        "c29": kcc,
        "vertex": mk_vertex(kcc, pc=0, t_alloc=0)
    }),
    (None, { # kdc vertex 1
        "vertex": mk_vertex(kdc_default, pc=0, t_alloc=0)
    }),
    ("cmove $c31, $c31", { # vertex 2 (pcc vertex)
        "c31": pcc,
        "vertex": mk_vertex(pcc, pc=0, t_alloc=0)
    }),
    ("eret", {}),
    # derive capability from pcc vertex
    ("cgetpcc $c1", {"c1": pcc}),
    ("lui $at, 0x300", {"1": 0x300}),
    ("csetoffset $c1, $c1, $at", {
        "c1": pct_cap(0x1000, 0x300, 0x1000,
                      CheriCapPerm.LOAD | CheriCapPerm.EXEC)
    }),
    ("lui $at, 0x100", {"1": 0x100}),
    ("csetbounds $c2, $c1, $at", { # vertex 3 (pcc) -> (v3)
        "c2": pct_cap(0x300, 0x0, 0x100, CheriCapPerm.LOAD | CheriCapPerm.EXEC),
        "vertex": mk_vertex(
            pct_cap(0x300, 0x0, 0x100, CheriCapPerm.LOAD | CheriCapPerm.EXEC),
            parent=2, origin=CheriNodeOrigin.SETBOUNDS)        
    }),
    # trigger exception, check that pcc-derived capabilities
    # are appended to kcc.
    # We do not care about the correctness of the exception
    # code/handling, just the fact that an exception happened
    # because it is the only thing that matters for provenance
    # tracking.
    ("cjr $c2", {"exc": 1}),
    ("nop", {}),
    ("cgetpcc $c1", {"c1": kcc}),
    ("lui $at, 0x400", {"1": 0x400}),
    ("csetoffset $c1, $c1, $at", {
        "c1": pct_cap(0x1000, 0x400, 0x1000, CheriCapPerm.all())
    }),
    ("lui $at, 0x100", {"1": 0x100}),
    ("csetbounds $c2, $c1, $at", { # vertex 4 (kcc) -> (v4)
        "c2": pct_cap(0x400, 0x0, 0x100, CheriCapPerm.all()),
        "vertex": mk_vertex(
            pct_cap(0x400, 0x0, 0x100, CheriCapPerm.all()),
            parent=0, origin=CheriNodeOrigin.SETBOUNDS)
    }),
    # there is confusion here, c31 should be the c2 from cjr or pcc pointing
    # to cjr?
    # it depends on how exceptions can happen with cjr
    # TLB load on the first instruction -> pcc already updated
    # TLB load on the delay slot instruction fetch -> pcc not updated
    ("csetbounds $c2, $c31, $at", { # vertex 5 (pcc) -> (v5)
        "c2": pct_cap(0x0c, 0x0, 0x100, CheriCapPerm.LOAD | CheriCapPerm.EXEC),
        "vertex": mk_vertex(
            pct_cap(0x0c, 0x0, 0x100, CheriCapPerm.LOAD | CheriCapPerm.EXEC),
            parent=2, origin=CheriNodeOrigin.SETBOUNDS)
    }),
    # nested interrupt
    ("ld $2, 0($1)", {"exc": 0}),
    ("cgetpcc $c1", {"c1": kcc}),
    ("lui $at, 0x400", {"1": 0x500}),
    ("csetoffset $c1, $c1, $at", {
        "c1": pct_cap(0x1000, 0x500, 0x1000, CheriCapPerm.all())
    }),
    ("lui $at, 0x400", {"1": 0x100}),
    ("csetbounds $c2, $c1, $at", { # vertex 6 (kcc) -> (v6)
        "c2": pct_cap(0x500, 0x0, 0x100, CheriCapPerm.all()),
        "vertex": mk_vertex(
            pct_cap(0x500, 0x0, 0x100, CheriCapPerm.all()),
            parent=0, origin=CheriNodeOrigin.SETBOUNDS)
    }),
)

# generate trace to check that kdc and ddc
# provenance is tracked correctly in exceptions.
# The rest of kdc/ddc interactions should be automatically
# preserved by entries in the trace? is this so?
#
# ROOT(ddc) -> B
trace_ddc = (
    ("cmove $c0, $c0", { # ddc vertex 0
        "c0": ddc,
        "vertex": mk_vertex(ddc, pc=0, t_alloc=0)
    }),
    (None, { # kcc vertex 1
        "vertex": mk_vertex(kcc_default, pc=0, t_alloc=0)
    }),
    (None, { # kdc vertex 2
        "vertex": mk_vertex(kdc_default, pc=0, t_alloc=0)
    }),
    ("cmove $c31, $c31", { # vertex 3 (pcc vertex)
        "c31": pcc,
        "vertex": mk_vertex(pcc, pc=0, t_alloc=0)
    }),
    ("eret", {}),
    # derive capability from ddc vertex
    ("cgetdefault $c1", {"c1": ddc}),
    ("lui $at, 0x300", {"1": 0x300}),
    ("csetoffset $c1, $c1, $at", {
        "c1": pct_cap(0x0, 0x300, 0x10000,
                      CheriCapPerm.LOAD | CheriCapPerm.EXEC)
    }),
    ("lui $at, 0x100", {"1": 0x100}),
    ("csetbounds $c2, $c1, $at", { # vertex 4
        "c2": pct_cap(0x300, 0x0, 0x100, CheriCapPerm.LOAD | CheriCapPerm.EXEC),
        "vertex": mk_vertex(
            pct_cap(0x300, 0x0, 0x100, CheriCapPerm.LOAD | CheriCapPerm.EXEC),
            parent=0, origin=CheriNodeOrigin.SETBOUNDS)        
    }),
)


@pytest.mark.parametrize("trace", [
    trace_infer_kcc_kdc,
    trace_explicit_kcc_kdc,
    trace_pcc_epcc_tracking, # xfail due to unresolved issue
    trace_ddc,
])
def test_nodegen_simple(trace):
    """Test provenance parser with the simplest trace possible."""

    with tempfile.NamedTemporaryFile() as tmp:
        # setup the mock trace
        w = ProvenanceTraceWriter(tmp.name)
        w.write_trace(trace, pc=0x1000)

        # get parsed graph
        parser = PointerProvenanceParser(trace_path=tmp.name)
        parser.parse()
        # check the provenance graph model
        pgm = parser.get_model()
        assert_graph_equal(w.pgm.graph, pgm)

@pytest.mark.parametrize("trace,exc_type", [
    (trace_invalid_derive_from_unknown, MissingParentError),
    (trace_invalid_missing_initial_epcc, ValueError)
])
def test_nodegen_errors(trace, exc_type):
    """
    Test expected failure conditions where 
    the parser should throw an error.
    """

    with tempfile.NamedTemporaryFile() as tmp:
        # setup the mock trace
        w = ProvenanceTraceWriter(tmp.name)
        w.write_trace(trace, pc=0x1000)

        # get parsed graph
        parser = PointerProvenanceParser(trace_path=tmp.name)
        with pytest.raises(exc_type) as excinfo:
            parser.parse()
