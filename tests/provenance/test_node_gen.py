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
    assert_graph_equal, mk_pvertex, mk_cvertex, ProvenanceTraceWriter)

logging.basicConfig(level=logging.DEBUG)

# some capabilities that are used in the test
perm = CheriCapPerm.LOAD | CheriCapPerm.STORE
exec_perm = CheriCapPerm.LOAD | CheriCapPerm.EXEC
pcc = pct_cap(0x1000, 0x0c, 0x1000, exec_perm)
kcc_default = pct_cap(0x00, 0x00, 0xffffffffffffffff, CheriCapPerm.all())
kdc_default = pct_cap(0x00, 0x00, 0xffffffffffffffff, CheriCapPerm.all())
kcc = pct_cap(0x00, 0xcc, 0xffffffff, CheriCapPerm.all())
kdc = pct_cap(0x00, 0xdc, 0xffffffff, CheriCapPerm.all())
ddc = pct_cap(0x0, 0x0, 0x10000, perm)
start_cap = pct_cap(0x1000, 0x0, 0x1000, perm)
ptr_cap = pct_cap(0x1000, 0x100, 0x1000, perm)
bound_cap = pct_cap(0x1100, 0x0, 0x100, perm)
perm_cap = pct_cap(0x1100, 0x0, 0x100, CheriCapPerm.STORE)

# common part of the trace used for tests that do not
# require special initialization of the registers
trace_init = (
    ("", { # call graph root
        "cvertex": mk_cvertex(None, vid="call-root")
    }),
    ("cmove $c1, $c1", { # vertex 0
        "c1": start_cap,
        "pvertex": mk_pvertex(start_cap, vid="start")
    }),
    ("cmove $c29, $c29", { # kcc vertex 1
        "c29": kcc_default,
        "pvertex": mk_pvertex(kcc_default, vid="kcc")
    }),
    ("cmove $c30, $c30", { # kdc vertex 2
        "c30": kdc_default,
        "pvertex": mk_pvertex(kdc_default, vid="kdc")
    }),
    ("cmove $c31, $c31", { # vertex 3
        "c31": pcc,
        "pvertex": mk_pvertex(pcc, vid="pcc")
    }),
    ("eret", {}), # mark initialization end
)

# generate the following expected tree
# ROOT -> P -> A
#          \
#           -> B
# ROOT(pcc)
# ROOT(kcc)
# ROOT(kdc)
trace_explicit_kcc_kdc = (
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
    ("eret", {}),
    # worker set split here
    ("lui $at, 0x100", {"1": 0x100}),
    ("cfromptr $c2, $c1, $at", { # vertex 4
        "c2": ptr_cap,
        "pvertex": mk_pvertex(ptr_cap, "start", CheriNodeOrigin.FROMPTR, vid="pv4")
    }),
    ("daddiu $at, $at, 0x100", {"1": 0x200}),
    ("csetbounds $c1, $c2, $at", { # vertex 5
        "c1": bound_cap,
        "pvertex": mk_pvertex(bound_cap, "pv4", CheriNodeOrigin.SETBOUNDS),
        "pfree": "start",
    }),
    ("lui $at, 0x0c", {"1": 0x08}),
    ("candperm $c2, $c2, $at", { # vertex 6
        "c2": perm_cap,
        "pvertex": mk_pvertex(perm_cap, "pv4", CheriNodeOrigin.ANDPERM),
        "pfree": "pv4",
    })
)

# generate trace to check that the parser keeps track of
# special registers correctly.
#
# The following provenance relationships are checked:
# i) in normal conditions cgetpcc gives the initial pcc node
# ii) during an exception/syscall cgetpcc gives kcc
# iii) during an exception/syscall epcc is the initial pcc
#
# ROOT(kcc) -> B (v400)
#          `-> B (v500)
# ROOT(kdc_default)
# ROOT(pcc) -> B (v300)
#          `-> B (v0c)
trace_pcc_epcc_tracking = (
    ("", { # call graph root
        "cvertex": mk_cvertex(None, vid="call-root")
    }),
    ("cmove $c29, $c29", { # kcc vertex 0
        "c29": kcc,
        "pvertex": mk_pvertex(kcc, vid="kcc")
    }),
    ("cmove $c30, $c30", { # kdc vertex 1
        "c30": kdc_default,
        "pvertex": mk_pvertex(kdc_default, vid="kdc")
    }),
    ("cmove $c31, $c31", { # vertex 2 (pcc vertex)
        "c31": pcc,
        "pvertex": mk_pvertex(pcc, vid="pcc")
    }),
    ("eret", {}),
    # derive capability from pcc vertex
    ("cgetpcc $c1", {"c1": pcc}),
    ("lui $at, 0x300", {"1": 0x300}),
    ("csetoffset $c1, $c1, $at", {
        "c1": pct_cap(0x1000, 0x300, 0x1000, exec_perm)
    }),
    ("lui $at, 0x100", {"1": 0x100}),
    ("csetbounds $c2, $c1, $at", { # vertex 3 (pcc) -> (v3)
        "c2": pct_cap(0x300, 0x0, 0x100, exec_perm),
        "pvertex": mk_pvertex(
            pct_cap(0x300, 0x0, 0x100, exec_perm),
            parent="pcc", origin=CheriNodeOrigin.SETBOUNDS,
            vid="v300")
    }),
    # trigger exception, check that pcc-derived capabilities
    # are appended to kcc.
    # We do not care about the correctness of the exception
    # code/handling, just the fact that an exception happened
    # because it is the only thing that matters for provenance
    # tracking.
    #
    ("cjr $c2", {"exc": 1}),
    ("nop", {}),
    # $at is set to the cjr address
    # required to correctly set epcc
    ("dmfc0 $at, $8", {"1": 0x1024}), # badvaddr = pc of cjr
    ("cgetpcc $c1", {"c1": kcc}),
    ("lui $at, 0x400", {"1": 0x400}),
    ("csetoffset $c1, $c1, $at", {
        "c1": pct_cap(0x1000, 0x400, 0x1000, CheriCapPerm.all())
    }),
    ("lui $at, 0x100", {"1": 0x100}),
    ("csetbounds $c2, $c1, $at", { # vertex 4 (kcc) -> (v4)
        "c2": pct_cap(0x400, 0x0, 0x100, CheriCapPerm.all()),
        "pvertex": mk_pvertex(
            pct_cap(0x400, 0x0, 0x100, CheriCapPerm.all()),
            parent="kcc", origin=CheriNodeOrigin.SETBOUNDS,
            vid="v400"),
        "pfree": "v300",
    }),
    # c31 here should be the pcc, NOT updated with the content of c2
    # after cjr
    # it depends on how exceptions can happen with cjr
    # TLB load on the first instruction -> pcc already updated
    # TLB load on the delay slot instruction fetch -> pcc not updated
    ("csetbounds $c2, $c31, $at", { # vertex 5 (pcc) -> (v5)
        "c2": pct_cap(0x0c, 0x0, 0x100, exec_perm),
        "pvertex": mk_pvertex(
            pct_cap(0x0c, 0x0, 0x100, exec_perm),
            parent="pcc", origin=CheriNodeOrigin.SETBOUNDS,
            vid="v0c"),
        "pfree": "v400",
    }),
    # nested interrupt
    ("ld $2, 0($1)", {
        "exc": 0,
        "pfree": "pcc", # the second exception replaces c31 again
    }),
    ("cgetpcc $c1", {"c1": kcc}),
    ("lui $at, 0x400", {"1": 0x500}),
    ("csetoffset $c1, $c1, $at", {
        "c1": pct_cap(0x1000, 0x500, 0x1000, CheriCapPerm.all())
    }),
    ("lui $at, 0x400", {"1": 0x100}),
    ("csetbounds $c2, $c1, $at", { # vertex 6 (kcc) -> (v6)
        "c2": pct_cap(0x500, 0x0, 0x100, CheriCapPerm.all()),
        "pvertex": mk_pvertex(
            pct_cap(0x500, 0x0, 0x100, CheriCapPerm.all()),
            parent="kcc", origin=CheriNodeOrigin.SETBOUNDS,
            vid="v500"),
        "pfree": "v0c"
    }),
)

# generate trace to check that kdc and ddc
# provenance is tracked correctly in exceptions.
# The rest of kdc/ddc interactions should be automatically
# preserved by entries in the trace? is this so?
#
# ROOT(ddc) -> B
trace_ddc = (
    ("", { # call graph root
        "cvertex": mk_cvertex(None, vid="call-root")
    }),
    ("cmove $c0, $c0", { # ddc vertex 0
        "c0": ddc,
        "pvertex": mk_pvertex(ddc, vid="ddc")
    }),
    ("cmove $c29, $c29", { # kcc vertex 1
        "c29": kcc_default,
        "pvertex": mk_pvertex(kcc_default, vid="kcc")
    }),
    ("cmove $c30, $c30", { # kdc vertex 2
        "c30": kdc_default,
        "pvertex": mk_pvertex(kdc_default, vid="kdc")
    }),
    ("cmove $c31, $c31", { # vertex 3 (pcc vertex)
        "c31": pcc,
        "pvertex": mk_pvertex(pcc, vid="pcc")
    }),
    ("eret", {}),
    # derive capability from ddc vertex
    ("cgetdefault $c1", {"c1": ddc}),
    ("lui $at, 0x300", {"1": 0x300}),
    ("csetoffset $c1, $c1, $at", {
        "c1": pct_cap(0x0, 0x300, 0x10000, exec_perm)
    }),
    ("lui $at, 0x100", {"1": 0x100}),
    ("csetbounds $c2, $c1, $at", { # vertex 4
        "c2": pct_cap(0x300, 0x0, 0x100, exec_perm),
        "pvertex": mk_pvertex(
            pct_cap(0x300, 0x0, 0x100, exec_perm),
            parent="ddc", origin=CheriNodeOrigin.SETBOUNDS)
    }),
)

# Check that multiprocess parsing correctly merges vertices that
# are moved from one register to another.
# Also check that the single-process parser can do the same.
#
# generate:
# worker-1:
# ROOT(pcc), ROOT(kcc), ROOT(kdc), ROOT(c1)
# worker-2:
# DUMMY(c1) -> ROOT(pcc)
#          `-> B
# expect:
# ROOT(pcc)
# ROOT(kcc)
# ROOT(kdc)
# ROOT(ddc) -> B
#          `-> B
trace_mp_move_and_setbounds = (
    ("nop", {}),
    # split worker's set here
    ("cmove $c2, $c1", {
        "c2": start_cap
    }),
    # this makes a DUMMY(c1) -> ROOT(c1) in worker #2
    ("cgetpcc $c1", {
        "c1": pcc,
    }),
    # this makes DUMMY(c2) -> v4
    ("lui $at, 0x100", {"1": 0x100}),
    ("csetbounds $c1, $c2, $at", { # vertex 4
        "c1": pct_cap(0x1000, 0x00, 0x100, perm),
        "pvertex": mk_pvertex(pct_cap(0x1000, 0x00, 0x100, perm),
                              parent="start", origin=CheriNodeOrigin.SETBOUNDS),
    }),
)

# Test capability branch with exception at worker set boundary.
# This checks that the state of the CapabilityBranchSubparser
# is correctly preserved when merging.
#
# expect:
# ROOT(pcc) -> v4 -> v5
#
# the possible error condition if the feature tested does not work
# would be:
# ROOT(pcc) -> v4
#          `-> v5
trace_mp_cjr_exception_pcc_update = (
    ("lui $at, 0x100", {"1": 0x100}),
    ("cgetpccsetoffset $c2, $at", {
        "c2": pct_cap(0x1000, 0x100, 0x1000, exec_perm)
    }),
    ("csetbounds $c2, $c2, $at", { # vertex 4
        "c2": pct_cap(0x100, 0x0, 0x100, exec_perm),
        "pvertex": mk_pvertex(pct_cap(0x100, 0x0, 0x100, exec_perm),
                              parent="pcc", origin=CheriNodeOrigin.SETBOUNDS,
                              vid="expected_pcc")
    }),
    ("cjr $c2", {
        "exc": 1,
        "pfree": "pcc",
    }),
    ("nop", {}),
    # worker set split here
    ("dmfc0 $at, $8", {"1": 0x100}), # badvaddr = target of cjr
    # c31 here should be the pcc, updated with the content of c2
    # after cjr
    ("lui $at, 0x0c", {"1": 0x0c}),
    ("csetbounds $c2, $c31, $at", { # vertex 5 (v4) -> (v5)
        "c2": pct_cap(0x100, 0x0, 0x0c, exec_perm),
        "pvertex": mk_pvertex(
            pct_cap(0x100, 0x0, 0x0c, exec_perm),
            parent="expected_pcc", origin=CheriNodeOrigin.SETBOUNDS)
    }),
    # pad so that the worker set is split at the marked point
    ("nop", {}), ("nop", {}), ("nop", {}), ("nop", {}),
    ("nop", {}), ("nop", {}), ("nop", {}),
)

# Test capability branch with exception at worker set boundary.
# This checks that the state of the CapabilityBranchSubparser
# is correctly preserved when merging.
#
# expect:
# ROOT(pcc) -> v4
#          `-> v5
trace_mp_cjr_exception_pcc_unchanged = (
    ("lui $at, 0x100", {"1": 0x100}),
    ("cgetpccsetoffset $c2, $at", {
        "c2": pct_cap(0x1000, 0x100, 0x1000, exec_perm)
    }),
    ("csetbounds $c2, $c2, $at", { # vertex 4
        "c2": pct_cap(0x100, 0x0, 0x100, exec_perm),
        "pvertex": mk_pvertex(pct_cap(0x100, 0x0, 0x100, exec_perm),
                              parent="pcc", origin=CheriNodeOrigin.SETBOUNDS,
                              vid="v100")
    }),
    ("cjr $c2", {"exc": 1}),
    ("nop", {}),
    # worker set split here
    ("dmfc0 $at, $8", {"1": 0x1024}), # badvaddr = address of cjr (delay slot)
    # c31 here should be the pcc, NOT updated with the content of c2
    # after cjr
    ("lui $at, 0x0c", {"1": 0x0c}),
    ("csetbounds $c2, $c31, $at", { # vertex 5 (v3) -> (v5)
        "c2": pct_cap(0x100, 0x0, 0x0c, exec_perm),
        "pvertex": mk_pvertex(
            pct_cap(0x100, 0x0, 0x0c, exec_perm),
            parent="pcc", origin=CheriNodeOrigin.SETBOUNDS),
        "pfree": "v100",
    }),
    # pad so that the worker set is split at the marked point
    ("nop", {}), ("nop", {}), ("nop", {}), ("nop", {}),
    ("nop", {}), ("nop", {}), ("nop", {}),
)

# Check that root vertices are created for cpreg assignments
# correctly.
# when a register is set, both source and destination should be
# checked for the possibility to assing a valid vertex when none
# is present.
trace_cpreg_set = (
    ("", { # call graph root
        "cvertex": mk_cvertex(None, vid="call-root")
    }),
    ("csetdefault $c1", { # vertex 0
        "c1": pct_cap(0x1000, 0x0, 0x1000, perm),
        "pvertex": mk_pvertex(pct_cap(0x1000, 0x0, 0x1000, perm), vid="ddc")
    }),
    ("csetepcc $c2", { # vertex 1
        "c2": pct_cap(0x2000, 0x0, 0x1000, perm),
        "pvertex": mk_pvertex(pct_cap(0x2000, 0x0, 0x1000, perm), vid="epcc")
    }),
    ("csetkcc $c3", { # vertex 2
        "c3": pct_cap(0x3000, 0x0, 0x1000, perm),
        "pvertex": mk_pvertex(pct_cap(0x3000, 0x0, 0x1000, perm), vid="kcc")
    }),
    # XXX this crashes the assembler?
    # ("csetkdc $c4", {
    #     "c4": pct_cap(0x4000, 0x0, 0x1000, perm),
    #     "pvertex": mk_pvertex(pct_cap(0x4000, 0x0, 0x1000, perm))
    # }),
    ("lui $at, 0x100", {"1": 0x100}),
    ("csetbounds $c5, $c1, $at", { # vertex 3
        "c3": pct_cap(0x1000, 0x0, 0x100, perm),
        "pvertex": mk_pvertex(pct_cap(0x1000, 0x0, 0x100, perm),
                              parent="ddc", origin=CheriNodeOrigin.SETBOUNDS)
    }),
    ("csetbounds $c6, $c2, $at", { # vertex 4
        "c6": pct_cap(0x2000, 0x0, 0x100, perm),
        "pvertex": mk_pvertex(pct_cap(0x2000, 0x0, 0x100, perm),
                              parent="epcc", origin=CheriNodeOrigin.SETBOUNDS),
    }),
    ("csetbounds $c7, $c3, $at", { # vertex 5
        "c7": pct_cap(0x3000, 0x0, 0x100, perm),
        "pvertex": mk_pvertex(pct_cap(0x3000, 0x0, 0x100, perm),
                              parent="kcc", origin=CheriNodeOrigin.SETBOUNDS)
    }),
)

# see trace_cpreg_get
trace_cpreg_get = (
    ("", { # call graph root
        "cvertex": mk_cvertex(None, vid="call-root")
    }),
    ("cgetdefault $c1", { # vertex 0
        "c1": pct_cap(0x1000, 0x0, 0x1000, perm),
        "pvertex": mk_pvertex(pct_cap(0x1000, 0x0, 0x1000, perm), vid="ddc")
    }),
    ("cgetepcc $c2", { # vertex 1
        "c2": pct_cap(0x2000, 0x0, 0x1000, perm),
        "pvertex": mk_pvertex(pct_cap(0x2000, 0x0, 0x1000, perm), vid="epcc")
    }),
    ("cgetkcc $c3", { # vertex 2
        "c3": pct_cap(0x3000, 0x0, 0x1000, perm),
        "pvertex": mk_pvertex(pct_cap(0x3000, 0x0, 0x1000, perm), vid="kcc")
    }),
    # XXX this crashes the assembler?
    # ("cgetkdc $c4", {
    #     "c4": pct_cap(0x4000, 0x0, 0x1000, perm),
    #     "pvertex": mk_pvertex(pct_cap(0x4000, 0x0, 0x1000, perm))
    # }),
    ("cgetpcc $c5", { # vertex 3
        "c5": pct_cap(0x5000, 0x0, 0x1000, perm),
        "pvertex": mk_pvertex(pct_cap(0x5000, 0x0, 0x1000, perm), vid="pcc")
    }),
    ("lui $at, 0x100", {"1": 0x100}),
    # worker set split here
    ("csetbounds $c6, $c0, $at", { # vertex 4
        "c6": pct_cap(0x1000, 0x0, 0x100, perm),
        "pvertex": mk_pvertex(pct_cap(0x1000, 0x0, 0x100, perm),
                              parent="ddc", origin=CheriNodeOrigin.SETBOUNDS)
    }),
    ("csetbounds $c7, $c31, $at", { # vertex 5
        "c7": pct_cap(0x2000, 0x0, 0x100, perm),
        "pvertex": mk_pvertex(pct_cap(0x2000, 0x0, 0x100, perm),
                              parent="epcc", origin=CheriNodeOrigin.SETBOUNDS)
    }),
    ("csetbounds $c8, $c29, $at", { # vertex 6
        "c8": pct_cap(0x3000, 0x0, 0x100, perm),
        "pvertex": mk_pvertex(pct_cap(0x3000, 0x0, 0x100, perm),
                              parent="kcc", origin=CheriNodeOrigin.SETBOUNDS)
    }),
    ("cgetpcc $c9", {
        "c7": pct_cap(0x5000, 0x0, 0x1000, perm),
    }),
    ("csetbounds $c10, $c9, $at", { # vertex 7
        "c10": pct_cap(0x5000, 0x0, 0x100, perm),
        "pvertex": mk_pvertex(pct_cap(0x5000, 0x0, 0x100, perm),
                              parent="pcc", origin=CheriNodeOrigin.SETBOUNDS)
    }),
)

# check that capability register contents are propagated properly
# when using cheri instructions
trace_cap_propagate_setoffset = (
    ("", { # call graph root
        "cvertex": mk_cvertex(None, vid="call-root")
    }),
    ("cmove $c1, $c1", { # vertex 0
        "c1": start_cap,
        "pvertex": mk_pvertex(start_cap, vid="start")
    }),
    ("lui $at, 0x100", {"1": 0x100}),
    # working set split here
    ("csetoffset $c2, $c1, $at", {
        "c2": pct_cap(0x1000, 0x100, 0x1000, perm),
    }),
    ("csetbounds $c2, $c2, $at", { # vertex 1
        "c2": pct_cap(0x1100, 0x0, 0x100, perm),
        "pvertex": mk_pvertex(pct_cap(0x1100, 0x0, 0x100, perm),
                              parent="start", origin=CheriNodeOrigin.SETBOUNDS),
    }),
)

# check that capability register contents are propagated properly
# when using cheri instructions
trace_cap_propagate_incoffset = (
    ("", { # call graph root
        "cvertex": mk_cvertex(None, vid="call-root")
    }),
    ("cmove $c1, $c1", { # vertex 0
        "c1": start_cap,
        "pvertex": mk_pvertex(start_cap, vid="start")
    }),
    ("lui $at, 0x100", {"1": 0x100}),
    # working set split here
    ("cincoffset $c2, $c1, $at", {
        "c2": pct_cap(0x1000, 0x100, 0x1000, perm),
    }),
    ("csetbounds $c2, $c2, $at", { # vertex 1
        "c2": pct_cap(0x1100, 0x0, 0x100, perm),
        "pvertex": mk_pvertex(pct_cap(0x1100, 0x0, 0x100, perm),
                              parent="start", origin=CheriNodeOrigin.SETBOUNDS),
    }),
)

# invalid trace test: try to generate a provenance node from
# an uninitialized register.
# This is only detected with 2+ threads because the mismatch
# can not be detected when merging the trace beginning since
# there is nothing to compare to in the previous merge step.
# UNK -> P
trace_invalid_derive_from_unknown = (
    ("", { # call graph root
        "cvertex": mk_cvertex(None)
    }),
    ("cmove $c31, $c31", { # pcc is always loaded after eret
        "c31": pcc,
        "pvertex": mk_pvertex(pcc)
    }),
    ("eret", {}),
    ("lui $at, 0x100", {"1": 0x100}),
    ("cfromptr $c2, $c1, $at", { # trigger error
        "c2": ptr_cap})
)

# csetoffset invalid cap root
# Try to create a root from an invalid capability in csetoffset
trace_invalid_root_from_arith = (
    ("", { # call graph root
        "cvertex": mk_cvertex(None)
    }),
    ("csetoffset $c13, $c13, $5", {
        "c13": pct_cap(0x0, 0xffffffffffffff9c, 0x0, 0, valid=False),
    }),
    ("cmove $c14, $c14", {
        "c13": pct_cap(0x0, 0xdeadbeef, 0x0, 0, valid=False),
    }),
)

@pytest.mark.timeout(4)
@pytest.mark.parametrize("threads", [1, 2])
@pytest.mark.parametrize("trace", [
    (trace_init, trace_mp_move_and_setbounds),
    (trace_init, trace_mp_cjr_exception_pcc_update),
    (trace_init, trace_mp_cjr_exception_pcc_unchanged),
    (trace_explicit_kcc_kdc,),
    (trace_pcc_epcc_tracking,),
    (trace_ddc,),
    (trace_cpreg_set,),
    (trace_cpreg_get,),
    (trace_cap_propagate_setoffset,),
    (trace_cap_propagate_incoffset,),
    (trace_invalid_root_from_arith,),
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

@pytest.mark.timeout(4)
@pytest.mark.parametrize("threads", [2])
@pytest.mark.parametrize("trace,exc_type", [
    (trace_invalid_derive_from_unknown, MissingParentError),
])
def test_nodegen_errors(pgm, trace, exc_type, threads):
    """
    Test expected failure conditions where 
    the parser should throw an error.
    """

    with tempfile.NamedTemporaryFile() as tmp:
        # setup the mock trace
        w = ProvenanceTraceWriter(tmp.name)
        w.write_trace(trace, pc=0x1000)

        # get parsed graph
        parser = CheriMipsModelParser(pgm, trace_path=tmp.name, threads=threads)
        with pytest.raises(exc_type) as excinfo:
            parser.parse()
