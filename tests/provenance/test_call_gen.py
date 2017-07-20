"""
Test the basic behaviour of the provenance trace parser
"""

import pytest
import logging
import tempfile

from cheriplot.provenance.parser import (
    CheriMipsModelParser, MissingParentError, DereferenceUnknownCapabilityError,
    UnexpectedOperationError)
from cheriplot.provenance.model import (
    CheriNodeOrigin, CheriCapPerm, EdgeOperation)

from cheriplot.core.test import pct_cap
from tests.provenance.helper import (
    assert_graph_equal, mk_pvertex, mk_cvertex, mk_cvertex_ret, mk_vertex_deref,
    mk_cvertex_visible, ProvenanceTraceWriter)

logging.basicConfig(level=logging.DEBUG)

perm = CheriCapPerm.EXEC | CheriCapPerm.LOAD
perm_rw = CheriCapPerm.LOAD | CheriCapPerm.STORE
target_cap = pct_cap(0xc000, 0x0, 0x10000, perm)
link_cap = pct_cap(0x1000, 0x0, 0x10000, perm)
ret_cap = pct_cap(0xf000, 0x0, 0x1000, perm)
# some function addresses
fn_a = pct_cap(0x10000, 0x0, 0xf000, perm)
fn_b = pct_cap(0x20000, 0x0, 0xf000, perm)
fn_c = pct_cap(0x30000, 0x0, 0xf000, perm)
fn_d = pct_cap(0x40000, 0x0, 0xd000, perm)
fn_e = pct_cap(0xf0000, 0x0, 0x3000, perm)
# some capabilities
pcc = pct_cap(0x1000, 0x00, 0x1000, perm)
kcc_default = pct_cap(0x00, 0x00, 0xffffffffffffffff, CheriCapPerm.all())
kdc_default = pct_cap(0x00, 0x00, 0xffffffffffffffff, CheriCapPerm.all())
ddc = pct_cap(0x0, 0x0, 0x10000, perm_rw)
start_cap = pct_cap(0x1000, 0x0, 0x1000, perm_rw)

# Trace with a single call
trace_cap_call = (0x1000, (
    ("", {
        "cvertex": mk_cvertex(None, vid="call-root")
    }),
    ("cmove $c1, $c1", {
        "c1": target_cap,
        "pvertex": mk_pvertex(target_cap, vid="target")
    }),
    ("cjalr $c1, $c17", {
        "c17": link_cap,
        "pvertex": mk_pvertex(link_cap, vid="link"),
        "cvertex": mk_cvertex(
            0xc000,
            parent="call-root",
            vid="call",
            visible=[
                mk_cvertex_visible("target", 0x0, 1),
                mk_cvertex_visible("link", 0x0, 17),
            ])
    }),
    ("nop", {}),
    ("cjr $c17", {
        # "call" vertex return is set to this instruction time/addr
        "cret": mk_cvertex_ret("call")
    }),
))

# Trace with a more complex call graph that have
# multiple call and returns.
# The trace is split in multiple chunks depending on base address
# to make the calls agree with the pc value in the trace.
# <root> -> f_a -> f_b
#        -> f_c -> f_d
#               -> f_e
trace_cap_return_0x1000 = (0x1000, (
    ("", {
        "cvertex": mk_cvertex(None, vid="call-root")
    }),
    # 0x1000
    ("cmove $c1, $c1", {
        "c1": fn_a,
        "pvertex": mk_pvertex(fn_a, vid="cap-fn_a"),
    }),
    ("cjalr $c1, $c17", {
        "c17": pct_cap(0x1000, 0x0c, 0xf000, perm),
        "pvertex": mk_pvertex(pct_cap(0x1000, 0x0c, 0xf000, perm), vid="pcc"),
        "cvertex": mk_cvertex(
            0x10000,
            parent="call-root",
            vid="call-f_a",
            visible=[
                mk_cvertex_visible("cap-fn_a", 0x0, 1),
                mk_cvertex_visible("pcc", 0x0c, 17),
            ]),
    }),
    ("nop", {}),
))
trace_cap_return_0x10000 = (0x10000, (
    ("cmove $c1, $c2", {
        "c1": fn_b,
        "pvertex": mk_pvertex(fn_b, vid="cap-fn_b"),
    }),
    ("cjalr $c1, $c10", {
        "c10": pct_cap(0x10000, 0x0c, 0xf000, perm),
        "cvertex": mk_cvertex(
            0x20000,
            parent="call-f_a",
            vid="call-f_b",
            visible=[
                mk_cvertex_visible("cap-fn_b", 0x0, 1),
                mk_cvertex_visible("cap-fn_a", 0x0c, 10),
                mk_cvertex_visible("pcc", 0x0c, 17),
            ]),
    }),
    ("nop", {}),
))
trace_cap_return_0x20000 = (0x20000, (
    ("nop", {}),
    ("cjr $c10", {
        "cret": mk_cvertex_ret("call-f_b"),
    }),
    ("nop", {}),
))
trace_cap_return_0x1000c = (0x1000c, (
    ("cjr $c17", {
        "cret": mk_cvertex_ret("call-f_a"),
    }),
    ("nop", {}),
))
trace_cap_return_0x100c = (0x100c, (
    ("cmove $c1, $c6", {
        "c1": fn_c,
        "pvertex": mk_pvertex(fn_c, vid="cap-fn_c"),
    }),
    ("cjalr $c1, $c17", {
        "c17": pct_cap(0x1000, 0x18, 0xf000, perm),
        "cvertex": mk_cvertex(
            0x30000,
            parent="call-root",
            vid="call-f_c",
            visible=[
                mk_cvertex_visible("cap-fn_c", 0x0, 1),
                mk_cvertex_visible("pcc", 0x18, 17),
                mk_cvertex_visible("cap-fn_a", 0x0c, 10),
            ])
    }),
    ("nop", {}),
))
trace_cap_return_0x30000 = (0x30000, (
    ("cmove $c1, $c4", {
        "c4": fn_d,
        "pvertex": mk_pvertex(fn_d, vid="cap-fn_d"),
    }),
    ("cjalr $c1, $c10", {
        "c10": pct_cap(0x30000, 0x0c, 0xf000, perm),
        "cvertex": mk_cvertex(
            0x40000,
            parent="call-f_c",
            vid="call-f_d",
            visible=[
                mk_cvertex_visible("cap-fn_d", 0x0, 1),
                mk_cvertex_visible("cap-fn_c", 0x0c, 10),
                mk_cvertex_visible("pcc", 0x18, 17),
            ]),
    }),
    ("nop", {}),
))
trace_cap_return_0x40000 = (0x40000, (
    ("nop", {}),
    ("cjr $c10", {
        "cret": mk_cvertex_ret("call-f_d"),
    }),
    ("nop", {}),
))
trace_cap_return_0x3000c = (0x3000c, (
    ("cmove $c1, $c5", {
        "c4": fn_e,
        "pvertex": mk_pvertex(fn_e, vid="cap-fn_e"),
    }),
    ("cjalr $c1, $c10", {
        "c10": pct_cap(0x30000, 0x18, 0xf000, perm),
        "cvertex": mk_cvertex(
            0xf0000,
            parent="call-f_c",
            vid="call-f_e",
            visible=[
                mk_cvertex_visible("cap-fn_e", 0x0, 1),
                mk_cvertex_visible("cap-fn_c", 0x18, 10),
                mk_cvertex_visible("pcc", 0x18, 17),
            ]),
    }),
    ("nop", {}),
))

# Only valid return addresses pop from the call stack
# if a cjr goes to some other place do not treat it
# as a return.
trace_cjr_to_unexpected_addr_0x1000 = (0x1000, (
    ("", {
        "cvertex": mk_cvertex(None, vid="call-root")
    }),
    ("cmove $c1, $c1", {
        "c1": fn_a,
        "pvertex": mk_pvertex(fn_a, vid="cap-fn_a"),
    }),
    ("cjalr $c1, $c17", {
        "c17": pct_cap(0x1000, 0x0c, 0xf000, perm),
        "pvertex": mk_pvertex(pct_cap(0x1000, 0x0c, 0xf000, perm), vid="link"),
        "cvertex": mk_cvertex(
            0x10000,
            parent="call-root",
            vid="call-f_a",
            visible=[
                mk_cvertex_visible("cap-fn_a", 0x0, 1),
                mk_cvertex_visible("link", 0x0c, 17),
            ]),
    }),
    ("nop", {}),
))
trace_cjr_to_unexpected_addr_0x10000 = (0x10000, (
    ("cmove $c2, $c2", {
        "c2": pct_cap(0xff000, 0x0, 0x1000, perm),
        "pvertex": mk_pvertex(pct_cap(0xff000, 0x0, 0x1000, perm)),
    }),
    ("cjr $c2", {}), # return not matching expected
    ("nop", {}),
))
trace_cjr_to_unexpected_addr_0xff000 = (0xff000, (
    ("cjr $c17", {
        "cret": mk_cvertex_ret("call-f_a")
    }),
    ("nop", {}),
))

# Trace with return above the start point
# extra -> old_call_root -> fn
trace_cap_call_extra_return = (0x1000, (
    ("", {
        "cvertex": mk_cvertex(None, vid="call-root")
    }),
    ("", {
        "cvertex": mk_cvertex(None, parent="call-root", vid="old-call-root")
    }),
    ("cmove $c1, $c1", {
        "c1": fn_a,
        "pvertex": mk_pvertex(fn_a, vid="cap-fn_a"),
    }),
    ("cjalr $c1, $c17", {
        "c17": pct_cap(0x1000, 0x0c, 0xf000, perm),
        "pvertex": mk_pvertex(pct_cap(0x1000, 0x0c, 0xf000, perm), vid="link"),
        "cvertex": mk_cvertex(
            0x10000,
            parent="old-call-root",
            vid="fn_a",
            visible=[
                mk_cvertex_visible("cap-fn_a", 0x0, 1),
                mk_cvertex_visible("link", 0x0c, 17),
            ])
    }),
    ("nop", {})
))
trace_cap_call_extra_return_0x10000 = (0x10000, (
    ("cjr $c17", {
        "cret": mk_cvertex_ret("fn_a"),
    }),
    ("nop", {}),
))
trace_cap_call_extra_return_0x100c = (0x100c, (
    ("cmove $c10, $c10", {
        "c10": pct_cap(0xf0000, 0x0c, 0x1000, perm),
        "pvertex": mk_pvertex(pct_cap(0xf0000, 0x0c, 0x1000, perm)),
    }),
    ("cjr $c10", {
        "cret": mk_cvertex_ret("old-call-root"),
    })
))

# trace with non-capability calls
# call-root -> fn_cap_a -> fn_a
#           -> fn_b -> fn_cap_b
trace_non_cap_call_0x1000 = (0x1000, (
    ("", {
        "cvertex": mk_cvertex(None, vid="call-root"),
    }),
    ("cmove $c1, $c1", {
        "c1": fn_a,
        "pvertex": mk_pvertex(fn_a, vid="cap-fn_a"),
    }),
    ("cjalr $c1, $c17", {
        "c17": pct_cap(0x1000, 0x0c, 0xf000, perm),
        "pvertex": mk_pvertex(pct_cap(0x1000, 0x0c, 0xf000, perm), vid="link"),
        "cvertex": mk_cvertex(
            0x10000,
            parent="call-root",
            vid="fn_cap_a",
            visible=[
                mk_cvertex_visible("cap-fn_a", 0x0, 1),
                mk_cvertex_visible("link", 0x0c, 17),
            ])
    }),
    ("nop", {}),
))
trace_non_cap_call_0x10000 = (0x10000, (
    ("lui $1, 0x0090", {"1": 0x0090}),
    ("dsll $1, $1, 16", {"1": 0x90000}),
    ("jalr $1", {
        "31": 0x1000c,
        "cvertex": mk_cvertex(
            0x90000,
            parent="fn_cap_a",
            vid="fn_a",
            visible=[
                mk_cvertex_visible("cap-fn_a", 0x0, 1),
                mk_cvertex_visible("link", 0x0c, 17),
            ]),
    }),
    ("nop", {}),
))
trace_non_cap_call_0x90000 = (0x90000, (
    ("jr $ra", {
        "cret": mk_cvertex_ret("fn_a")
    }),
    ("nop", {}),
))
trace_non_cap_call_0x1000c = (0x1000c, (
    ("cjr $c17", {
        "cret": mk_cvertex_ret("fn_cap_a")
    }),
    ("nop", {}),
))
trace_non_cap_call_0x100c = (0x100c, (
    ("lui $1, 0x00b0", {"1": 0x00b0}),
    ("dsll $1, $1, 16", {"1": 0xb0000}),
    ("jalr $1", {
        "31": 0x1018,
        "cvertex": mk_cvertex(
            0xb0000,
            parent="call-root",
            vid="fn_b",
            visible=[
                mk_cvertex_visible("cap-fn_a", 0x0, 1),
                mk_cvertex_visible("link", 0x0c, 17),
            ]),
    }),
    ("nop", {}),
))
trace_non_cap_call_0xb0000 = (0xb0000, (
    ("cmove $c1, $c2", {
        "c1": fn_b,
        "pvertex": mk_pvertex(fn_b, vid="cap-fn_b"),
    }),
    ("cjalr $c1, $c17", {
        "c17": pct_cap(0x0, 0xb000c, 0x100000, perm),
        "cvertex": mk_cvertex(
            0x20000,
            parent="fn_b",
            vid="fn_cap_b",
            visible=[
                mk_cvertex_visible("cap-fn_b", 0x0, 1),
                mk_cvertex_visible("link", 0xb000c, 17),
            ]),
    }),
    ("nop", {}),
))
trace_non_cap_call_0x20000 = (0x20000, (
    ("cjr $c17", {
        "cret": mk_cvertex_ret("fn_cap_b")
    }),
    ("nop", {}),
))
trace_non_cap_call_0xb000c = (0xb000c, (
    ("jr $ra", {
        "cret": mk_cvertex_ret("fn_b")
    }),
    ("nop", {}),
))

# trace syscall
# Test simple syscall with random code
# Do not care about the correctness of the syscall code,
# the only thing that matters are valid registers
# at syscall/eret.
trace_syscall = (0x1000, (
    ("", {
        "cvertex": mk_cvertex(None, vid="call-root")
    }),
    ("lui $v0, 447", {"2": 124}), # random syscall code
    ("syscall", {
        "exc": 8,
        "cvertex": mk_cvertex(124, op=EdgeOperation.SYSCALL,
                              parent="call-root", vid="syscall")
    }),
    # set epcc since it is required to successfuly parse the return.
    ("cmove $c31, $c31", {
        "c31": pct_cap(0x1000, 0x0c, 0x10000, perm),
        "pvertex": mk_pvertex(pct_cap(0x1000, 0x0c, 0x10000, perm)),
    }),
    ("eret", {
        "cret": mk_cvertex_ret("syscall")
    }),
))

# trace syscall
# variant of the simple syscall test but epcc is not set and this
# should be detected as an error.
trace_syscall_err_missing_epcc = (0x1000, (
    ("", {
        "cvertex": mk_cvertex(None, vid="call-root")
    }),
    ("lui $v0, 124", {"2": 124}), # random syscall code
    ("syscall", {
        "exc": 8,
        "cvertex": mk_cvertex(124, op=EdgeOperation.SYSCALL,
                              parent="call-root", vid="syscall")
    }),
    ("nop", {}),
    ("eret", {
        "cret": mk_cvertex_ret("syscall")
    }),
))

# trace syscall
# Test trace syscall with spurious erets, these are
# remnants of previous exceptions/syscall but we can not be sure
# so ignore them for now.
# epcc is required to parse erets, here we do not care about the
# correctness of the epcc value, just call-layer behaviour.
trace_syscall_extra_eret = (0x1000, (
    ("", {
        "cvertex": mk_cvertex(None, vid="call-root")
    }),
    ("cmove $c31, $c31", {
        "c31": pct_cap(0x1000, 0x0c, 0xf000, perm),
        "pvertex": mk_pvertex(pct_cap(0x1000, 0x0c, 0xf000, perm)),
    }),
    ("eret", {}),
    ("eret", {}),
))

# trace syscall
# Test trace syscall with exception,
# the exception should not be counted and the eret ignored
trace_syscall_except = (0x1000, (
    ("", {
        "cvertex": mk_cvertex(None, vid="call-root")
    }),
    ("lui $v0, 450", {"2": 450}),
    ("syscall", {
        "exc": 8,
        "cvertex": mk_cvertex(450, op=EdgeOperation.SYSCALL,
                              parent="call-root", vid="syscall")
    }),
    ("cmove $c2, $c2", {
        "c2": pct_cap(0x1000, 0x0, 0xf000, perm_rw),
        "pvertex": mk_pvertex(pct_cap(0x1000, 0x0, 0xf000, perm_rw),
                              vid="v1000"),
    }),
    ("cmove $c31, $c31", {
        "c31": pct_cap(0x1000, 0x0c, 0xf000, perm),
        "pvertex": mk_pvertex(pct_cap(0x1000, 0x0c, 0xf000, perm)),
    }),
    ("cld $at, $zero, 0x10($c2)", {
        "exc": 1,
    }),
    ("nop", {}),
    ("eret", {}),
    ("cld $at, $zero, 0x10($c2)", {
        "1": 0xdeadbeef,
        "load": True,
        "mem": 0x1010,
        "vertex_deref": mk_vertex_deref("v1000", 0x1010, False, "load"),
    }),
    ("eret", {
        "cret": mk_cvertex_ret("syscall")
    }),
))

# trace syscall
# Mixed syscall and functions, when the syscall eret is found
# we must roll-back any outstanding calls up to the syscall frame
# since we are exiting from kernel space.
trace_syscall_mixed_0x1000 = (0x1000, (
    ("", {
        "cvertex": mk_cvertex(None, vid="call-root")
    }),
    ("lui $v0, 450", {"2": 450}),
    ("syscall", {
        "exc": 8,
        "cvertex": mk_cvertex(450, op=EdgeOperation.SYSCALL,
                              parent="call-root", vid="syscall")
    }),
    ("cmove $c1, $c1", {
        "c1": fn_a,
        "pvertex": mk_pvertex(fn_a, vid="cap-fn_a")
    }),
    ("cjalr $c1, $c17", {
        "c17": pct_cap(0x1000, 0x18, 0xf000, perm),
        "pvertex": mk_pvertex(pct_cap(0x1000, 0x18, 0xf000, perm), vid="link"),
        "cvertex": mk_cvertex(
            0x10000,
            parent="syscall",
            vid="call-fn_a",
            visible=[
                mk_cvertex_visible("cap-fn_a", 0x0, 1),
                mk_cvertex_visible("link", 0x18, 17),
            ]),
    }),
    ("nop", {}),
))
trace_syscall_mixed_0x10000 = (0x10000, (
    ("lui $1, 0x0020", {"1": 0x0020}),
    ("dsll $1, $1, 16", {"1": 0x20000}),
    ("jalr $1", {
        "31": 0x10010,
        "cvertex": mk_cvertex(
            0x20000,
            parent="call-fn_a",
            vid="call-fn_b",
            visible=[
                mk_cvertex_visible("cap-fn_a", 0x0, 1),
                mk_cvertex_visible("link", 0x18, 17),
            ]),
    }),
    ("nop", {}),
))
trace_syscall_mixed_0x20000 = (0x20000, (
    # again c31 is required to have a value for the eret parser to succeed.
    ("cmove $c31, $c17", {
        "c31": pct_cap(0x1000, 0x18, 0xf000, perm),
    }),
    ("eret", {
        "cret": mk_cvertex_ret("syscall", "call-fn_a", "call-fn_b"),
    }),
))

# trace syscall
# Test syscall pcc/epcc manipulation mixed with call-layer vertices
trace_syscall_epcc_update = (0x1000, (
    ("", { # call graph root
        "cvertex": mk_cvertex(None, vid="call-root")
    }),
    ("cmove $c1, $c1", {
        "c1": start_cap,
        "pvertex": mk_pvertex(start_cap, vid="start")
    }),
    ("cmove $c30, $c30", {
        "c30": kdc_default,
        "pvertex": mk_pvertex(kdc_default, vid="kdc")
    }),
    ("cmove $c31, $c31", {
        "c31": pcc,
        "pvertex": mk_pvertex(pcc, vid="pcc")
    }),
    ("eret", {}), # set pcc to epcc internally
    ("lui $v0, 447", {"2": 447}), # mmap code
    # {0x1014}
    ("syscall", {
        "exc": 8,
        "cvertex": mk_cvertex(
            447,
            op=EdgeOperation.SYSCALL,
            parent="call-root",
            vid="mmap",
            visible=[
                mk_cvertex_visible("start", 0x0, 1),
                mk_cvertex_visible("kdc", 0x0, 30),
                mk_cvertex_visible("pcc", 0x0, 31),
            ]),
    }),
    ("cincoffset $c1, $kdc, $zero", {"c1": kdc_default}),
    # simulate return of mmap(0x1000, 0x1000, ...)
    ("lui $at, 0x1000", {"1": 0x1000}),
    ("csetoffset $c1, $c1, $at", {
        "c1": pct_cap(0x00, 0x1000, 0xffffffffffffffff, CheriCapPerm.all())
    }),
    ("csetbounds $c2, $c1, $at", { # vertex 3
        "c2": pct_cap(0x1000, 0x0, 0x1000, CheriCapPerm.all()),
        "pvertex": mk_pvertex(pct_cap(0x1000, 0x0, 0x1000, CheriCapPerm.all()),
                              parent="kdc", origin=CheriNodeOrigin.SETBOUNDS,
                              vid="v1000"),
    }),
    ("cmove $c3, $c2", {
        "c3": pct_cap(0x1000, 0xf00, 0x1000, CheriCapPerm.all())
    }),
    # epcc address should match the expected return
    ("lui $at, 0x14", {"1": 0x18}),
    ("csetoffset $c31, $c31, $at", {
        "c31": pct_cap(0x1000, 0x18, 0x1000, perm),
    }),
    ("eret", {
        "cret": mk_cvertex_ret("mmap", offset=0xf00, retid="v1000"),
        # expect the vertex to be used in a syscall ret (TODO)
        # "vertex_call": mk_vertex_call("v1000", 447, "syscall_ret"),
    }),
))

# test arguments/return to call
# Check that visible and return vertices are correctly linked
# in different situations.
# call-root -> fn_a
#           -> fn_b
trace_call_connect_prov_0x1000 = (0x1000, (
    ("", { # call graph root
        "cvertex": mk_cvertex(None, vid="call-root")
    }),
    ("cmove $c1, $c1", {
        "c1": fn_a,
        "pvertex": mk_pvertex(fn_a, vid="cap-fn_a"),
    }),
    ("cmove $c2, $c2", {
        "c2": fn_b,
        "pvertex": mk_pvertex(fn_b, vid="cap-fn_b"),
    }),
    ("cmove $c3, $c3", {
        "c2": start_cap,
        "pvertex": mk_pvertex(start_cap, vid="start"),
    }),
    ("cjalr $c1, $c17", {
        "c17": pct_cap(0x1000, 0x14, 0x1000, perm),
        "pvertex": mk_pvertex(pct_cap(0x1000, 0x14, 0x1000, perm), vid="link"),
        "cvertex": mk_cvertex(
            0x10000,
            parent="call-root",
            vid="call-fn_a",
            visible=[
                mk_cvertex_visible("cap-fn_a", 0x0, 1),
                mk_cvertex_visible("cap-fn_b", 0x0, 2),
                mk_cvertex_visible("start", 0x0, 3),
                mk_cvertex_visible("link", 0x14, 17),
            ])
    }),
    ("nop", {}),
))
trace_call_connect_prov_0x10000 = (0x10000, (
    ("lui $at, 0x100", {"1": 0x100}),
    ("cincoffset $c4, $c3, $at", {
        "c4": pct_cap(0x1000, 0x100, 0x1000, perm),
    }),
    ("lui $at, 0x1f0", {"1": 0x1f0}),
    ("cincoffset $c3, $c3, $at", {
        "c3": pct_cap(0x1000, 0x1f0, 0x1000, perm),
    }),
    ("cmove $c5, $c3", {
        "c5": pct_cap(0x1000, 0x1f0, 0x1000, perm),
    }),
    ("cjalr $c2, $c17", {
        "c17": pct_cap(0x10000, 0x14, 0xf000, perm),
        "cvertex": mk_cvertex(
            0x20000,
            parent="call-fn_a",
            vid="call-fn_b",
            visible=[
                mk_cvertex_visible("cap-fn_a", 0x0, 1),
                mk_cvertex_visible("cap-fn_b", 0x0, 2),
                mk_cvertex_visible("start", 0x1f0, 3, 5),
                mk_cvertex_visible("start", 0x100, 4),
                mk_cvertex_visible("cap-fn_a", 0x14, 17),
            ])
    }),
    ("nop", {}),
))
trace_call_connect_prov_0x20000 = (0x20000, (
    ("cjr $c17", {
        "cret": mk_cvertex_ret("call-fn_b", offset=0x1f0, retid="start")
    }),
    ("nop", {}),
))

@pytest.mark.timeout(10)
@pytest.mark.parametrize("threads", [1,])
@pytest.mark.parametrize("traces", [
    (trace_cap_call,),
    (trace_cap_return_0x1000, trace_cap_return_0x10000,
     trace_cap_return_0x20000, trace_cap_return_0x1000c,
     trace_cap_return_0x100c, trace_cap_return_0x30000,
     trace_cap_return_0x40000, trace_cap_return_0x3000c),
    (trace_cjr_to_unexpected_addr_0x1000, trace_cjr_to_unexpected_addr_0x10000,
     trace_cjr_to_unexpected_addr_0xff000,),
    (trace_cap_call_extra_return, trace_cap_call_extra_return_0x10000,
     trace_cap_call_extra_return_0x100c),
    (trace_non_cap_call_0x1000, trace_non_cap_call_0x10000,
     trace_non_cap_call_0x90000, trace_non_cap_call_0x1000c,
     trace_non_cap_call_0x100c, trace_non_cap_call_0xb0000,
     trace_non_cap_call_0x20000, trace_non_cap_call_0xb000c),
    (trace_syscall,),
    (trace_syscall_extra_eret,),
    (trace_syscall_except,),
    (trace_syscall_mixed_0x1000, trace_syscall_mixed_0x10000,
     trace_syscall_mixed_0x20000),
    (trace_syscall_epcc_update,),
    (trace_call_connect_prov_0x1000, trace_call_connect_prov_0x10000,
     trace_call_connect_prov_0x20000),
])
def test_callgen(traces, threads):
    """Test provenance parser with the simplest trace possible."""

    with tempfile.NamedTemporaryFile() as tmp:
        # setup the mock trace
        w = ProvenanceTraceWriter(tmp.name)
        for base, model in traces:
            w.write_trace(model, pc=base)

        # get parsed graph
        parser = CheriMipsModelParser(trace_path=tmp.name, threads=threads)
        parser.parse()
        # check the provenance graph model
        pgm = parser.get_model()
        assert_graph_equal(w.pgm.graph, pgm.graph)

@pytest.mark.timeout(10)
@pytest.mark.parametrize("threads", [1,])
@pytest.mark.parametrize("test_data", [
    ((trace_syscall_err_missing_epcc,), UnexpectedOperationError),
])
def test_callgen_errors(test_data, threads):
    """Test provenance parser with the simplest trace possible."""

    with tempfile.NamedTemporaryFile() as tmp:
        # setup the mock trace
        w = ProvenanceTraceWriter(tmp.name)
        traces, error = test_data
        for base, model in traces:
            w.write_trace(model, pc=base)

        # get parsed graph
        parser = CheriMipsModelParser(trace_path=tmp.name, threads=threads)
        with pytest.raises(error):
            parser.parse()
