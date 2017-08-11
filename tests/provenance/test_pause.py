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
from tests.provenance.fixtures import pgm
from tests.provenance.helper import (
    assert_graph_equal, mk_pvertex, mk_cvertex, ProvenanceTraceWriter,
    mk_vertex_mem, mk_vertex_deref, mk_cvertex_visible)

logging.basicConfig(level=logging.DEBUG)

# some capabilities that are used in the test
perm = CheriCapPerm.LOAD | CheriCapPerm.STORE
exec_perm = CheriCapPerm.LOAD | CheriCapPerm.EXEC
pcc = pct_cap(0x1000, 0x0c, 0x1000, exec_perm)
kcc = pct_cap(0x00, 0xcc, 0xffffffff, CheriCapPerm.all())
kdc = pct_cap(0x00, 0xdc, 0xffffffff, CheriCapPerm.all())
ddc = pct_cap(0x0, 0x0, 0x10000, perm)
start_cap = pct_cap(0x1000, 0x0, 0x1000, perm)
ptr_cap = pct_cap(0x1000, 0x100, 0x1000, perm)
bound_cap = pct_cap(0x1100, 0x0, 0x100, perm)

# test pause switch based on 0x1d1d NOP
trace_pause_resume = (
    ("", { # call graph root
        "cvertex": mk_cvertex(None, vid="call-root")
    }),
    ("cmove $c1, $c1", { # vertex 0
        "c1": start_cap,
        "pvertex": mk_pvertex(start_cap, vid="start")
    }),
    ("cmove $c29, $c29", { # kcc vertex 1
        "c29": kcc,
        "pvertex": mk_pvertex(kcc, vid="kcc")
    }),
    ("cmove $c30, $c30", { # kdc vertex 2
        "c30": kdc,
        "pvertex": mk_pvertex(kdc, vid="kdc")
    }),
    ("cmove $c31, $c31", { # vertex 3
        "c31": pcc,
        "pvertex": mk_pvertex(pcc, vid="pcc")
    }),
    ("lui $4, 0xfabc", {"4": 0xfabc}),
    ("lui $zero, 0x1d1d", {"0": 0x1d1d}),
    ("dadd $zero, $zero, $4", {"0": 0xfabc}),
    ("nop", {}),
    ("lui $zero, 0xdead", {"0": 0xdead}),
    ("nop", {}),
    ("lui $4, 0xbad0", {"4": 0xbad0}),
    ("lui $zero, 0x1d1d", {"0": 0x1d1d}),
    ("dadd $zero, $zero, $4", {"0": 0xbad0}),
    # these should not be created
    ("cfromptr $c2, $c1, $at", {
        "c2": ptr_cap,
    }),
    ("daddiu $at, $at, 0x100", {"1": 0x200}),
    ("csetbounds $c3, $c2, $at", {
        "c3": bound_cap,
    }),
    ("lui $4, 0xbad0", {"4": 0xbad0}),
    ("lui $zero, 0x1d1d", {"0": 0x1d1d}),
    ("dadd $zero, $zero, $4", {"0": 0xbad0}),
    ("nop", {}),
    ("lui $zero, 0xdead", {"0": 0xdead}),
    ("nop", {}),
    ("lui $4, 0xfabc", {"4": 0xfabc}),
    ("lui $zero, 0x1d1d", {"0": 0x1d1d}),
    ("dadd $zero, $zero, $4", {"0": 0xfabc}),
    # re enable
    
    ("lui $at, 0x0c", {"1": 0x08}),
    ("candperm $c2, $c1, $at", {
        "c2": pct_cap(0x1000, 0x0, 0x1000, CheriCapPerm.STORE),
        "pvertex": mk_pvertex(
            pct_cap(0x1000, 0x0, 0x1000, CheriCapPerm.STORE),
            vid="perm", origin=CheriNodeOrigin.ANDPERM, parent="start"),
    })
)

@pytest.mark.timeout(10)
@pytest.mark.parametrize("threads", [1, ])
@pytest.mark.parametrize("trace", [
    (trace_pause_resume,),
])
def test_nodegen_simple(pgm, trace, threads):
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
        parser = CheriMipsModelParser(pgm, trace_path=tmp.name, threads=threads)
        parser.parse()
        assert_graph_equal(w.pgm.graph, pgm.graph)
