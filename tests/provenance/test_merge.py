"""
Test the graph merge logic
"""

import pytest
import logging

from cheriplot.provenance.parser import (
    SubgraphMergeError, MissingParentError, DereferenceUnknownCapabilityError)
from cheriplot.provenance.parser.base import RegisterSet, VertexMemoryMap
from cheriplot.provenance.parser.sub_mips import MergePartialSubgraphContext
from cheriplot.provenance.model import (
    CheriNodeOrigin, CheriCapPerm, ProvenanceVertexData,
    ProvenanceGraphManager, EdgeOperation)

from tests.provenance.helper import (
    assert_graph_equal, MockGraphBuilder, model_cap)

logging.basicConfig(level=logging.DEBUG)

@pytest.fixture
def worker_result_base():
    """
    Mock a worker result that is sent to the merge context.
    """
    pgm = ProvenanceGraphManager("")
    result = {
        "cycles_start": 0,
        "cycles_end": 100,
        "pgm": pgm,
        "regset": RegisterSet(pgm),
        "mem_vertex_map": VertexMemoryMap(pgm),
        "sub_pcc_fixup": {
            "saved_addr": None,
            "saved_pcc": None,
            "epcc_out_neightbours": None,
            "epcc": None,
            "badvaddr": None,
        },
        "sub_syscall": {
            "code": None,
            "active": False,
            "pc_eret": None,
            "eret_time": None,
            "eret_cap": None,
            "eret_addr": None
        },
        "sub_callgraph": {
            # these must be set to a valid vertex
            "root": None,
            "last_frame": None,
        }
    }
    return result


rw_perm = CheriCapPerm.LOAD | CheriCapPerm.STORE
rwx_perm = CheriCapPerm.LOAD | CheriCapPerm.STORE | CheriCapPerm.EXEC

trace_step_empty = tuple()

# trace beginning merge
# base case with 2 partial -> root connections and some children
# partial1 -> rootA -> 0
# partial2 -> rootB -> 1
#                   -> 2
trace_begin_simple_model = (
    ("prov_node", {
        "id": "rootA",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x1000, 0x0, 0x1000, rw_perm, t=0),
        "pc": 0x1000,
    }),
    ("prov_edge", "partial-1", "rootA", {}),
    ("prov_node", {
        "id": 0,
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x1100, 0x0, 0x100, rw_perm, t=10),
        "pc": 0x1004,
    }),
    ("prov_edge", "rootA", 0, {}),
    ("prov_node", {
        "id": "rootB",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0xf000, 0x0, 0x1000, rw_perm, t=20),
        "pc": 0x2000,
    }),
    ("prov_edge", "partial-2", "rootB", {}),
    ("prov_node", {
        "id": 1,
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0xf100, 0x0, 0x100, rw_perm, t=10),
        "pc": 0x2004,
    }),
    ("prov_edge", "rootB", 1, {}),
    ("prov_node", {
        "id": 2,
        "origin": CheriNodeOrigin.ANDPERM,
        "cap": model_cap(0xf000, 0x0, 0x1000, rw_perm, t=10),
        "pc": 0x3004,
    }),
    ("prov_edge", "rootB", 2, {}),
)

# trace beginning merge
# partial with multiple roots, the roots should be merged in the output
# partial1 -> rootA -> 0
#          -> rootB -> 1
trace_begin_partial_multi_root = (
    ("prov_node", {
        "id": "rootA",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x1000, 0x0, 0x1000, rw_perm, t=0),
        "pc": 0x1000,
    }),
    ("prov_node", {
        "id": 0,
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x1100, 0x0, 0x100, rw_perm, t=10),
        "pc": 0x1008,
    }),
    ("prov_node", {
        "id": "rootB",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x1000, 0x0, 0x1000, rw_perm, t=100),
        "pc": 0x2000,
    }),
    ("prov_node", {
        "id": 1,
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x1200, 0x0, 0x100, rw_perm, t=110),
        "pc": 0x2008,
    }),
    ("prov_edge", "partial-1", "rootA", {}),
    ("prov_edge", "partial-1", "rootB", {}),
    ("prov_edge", "rootA", 0, {}),
    ("prov_edge", "rootB", 1, {}),
)

# trace beginning merge
# partial with a root and non-root vertices, the non-root vetices are promoted
# to roots.
# partial1 -> rootA -> 0
#          -> 1 -> 2
trace_begin_partial_non_root = (
    ("prov_node", {
        "id": "rootA",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x1000, 0x0, 0x1000, rw_perm, t=0),
        "pc": 0x1000,
    }),
    ("prov_node", {
        "id": 0,
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x1000, 0x0, 0x100, rw_perm, t=10),
        "pc": 0x1008,
    }),
    ("prov_node", {
        "only": "subgraph",
        "id": 1,
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x1000, 0x0, 0x1000, rw_perm, t=30),
        "pc": 0x2000,
    }),
    ("prov_node", {
        "id": 2,
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x1000, 0x0, 0x200, rw_perm, t=50),
        "pc": 0x2008,
    }),
    ("prov_node", {
        "only": "expect",
        "id": "rootOut",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x1000, 0x0, 0x1000, rw_perm, t=30),
        "pc": 0x2000,
    }),
    # subgraph connections
    ("prov_edge", "partial-1", "rootA", {}),
    ("prov_edge", "rootA", 0, {}),
    ("prov_edge", "partial-1", 1, {}),
    ("prov_edge", 1, 2, {}),
    # expect graph connections
    ("prov_edge", "rootOut", 2, {}),
)

# trace beginning merge
# partial with only non-root vertices, the non-root vertices are
# attached to a common initial root
# partial1 -> 0
#          -> 1 -> 2
trace_begin_partial_all_non_root = (
    ("prov_node", {
        "id": 0,
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x1000, 0x0, 0x100, rw_perm, t=10),
        "pc": 0x1008,
    }),
    ("prov_node", {
        "id": 1,
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0xf000, 0x0, 0x1000, rw_perm, t=30),
        "pc": 0x2000,
    }),
    ("prov_node", {
        "id": 2,
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0xf000, 0x0, 0x200, rw_perm, t=50),
        "pc": 0x2008,
    }),
    ("prov_node", {
        "only": "expect",
        "id": "initial_root",
        "origin": CheriNodeOrigin.INITIAL_ROOT,
        "cap": model_cap(0x1000, 0x0, 0xf000, rw_perm, t=0),
        "pc": 0,
    }),
    # subgraph connections
    ("prov_edge", "partial-1", 0, {}),
    ("prov_edge", "partial-1", 1, {}),
    ("prov_edge", 1, 2, {}),
    # expect graph connections
    ("prov_edge", "initial_root", 0, {}),
    ("prov_edge", "initial_root", 1, {}),
)

# merge initial vertex
# Test 2-step merge register set only.
# step 1:
# partial1 -> rootA -> 0 [$c1]
#          -> rootB -> 1 [$c2]
# partial2 -> rootC -> 2 [$c3]
# partial3 -> rootD [$pcc]
#
# step 2:
# [$c1] partial1 -> 3
# [$c2] partial2 -> rootE -> 4
# [$c3] partial3 -> 5
# [$pcc] partial33 -> 6
# partial5 -> rootI -> 7
trace_step_1_no_mem = (
    ("prov_node", {
        "id": "rootA",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x1000, 0x0, 0x1000, rw_perm, t=1),
        "pc": 0x1000,
    }),
    ("prov_edge", "partial-1", "rootA", {}),
    ("prov_node", {
        "id": "rootB",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x3000, 0x0, 0x1000, rw_perm, t=2),
        "pc": 0x1004,
    }),
    ("prov_edge", "partial-1", "rootB", {}),
    ("prov_node", {
        "id": "rootC",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x5000, 0x0, 0x1000, rw_perm, t=3),
        "pc": 0x1008,
    }),
    ("prov_edge", "partial-2", "rootC", {}),
    ("prov_node", {
        "id": "rootD",
        "reg": "pcc",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x7000, 0x0, 0x1000, rw_perm, t=4),
        "pc": 0x100c,
    }),
    ("prov_edge", "partial-3", "rootD", {}),
    ("prov_node", {
        "id": 0,
        "reg": 1,
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x1500, 0x0, 0x100, rw_perm, t=5),
        "pc": 0x100c,
    }),
    ("prov_edge", "rootA", 0, {}),
    ("prov_node", {
        "id": 1,
        "reg": 2,
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x3500, 0x0, 0x100, rw_perm, t=6),
        "pc": 0x100c,
    }),
    ("prov_edge", "rootB", 1, {}),
    ("prov_node", {
        "id": 2,
        "reg": 3,
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x5500, 0x0, 0x100, rw_perm, t=7),
        "pc": 0x100c,
    }),
    ("prov_edge", "rootC", 2, {}),
)

trace_step_2_no_mem = (
    ("prov_node", { # replaces c2
        "id": "rootE",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0xf000, 0x0, 0x1000, rw_perm, t=1),
        "pc": 0x1000,
    }),
    ("prov_edge", "partial-2", "rootE", {}),
    ("prov_node", { # from c1
        "id": 3,
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x1500, 0x0, 0x10, rw_perm, t=2),
        "pc": 0x1004,
    }),
    ("prov_edge", "partial-1", 3, {}),
    ("prov_edge", 0, 3, {"only": "expect"}),
    ("prov_node", {
        "id": 4,
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0xf500, 0x0, 0x10, rw_perm, t=3),
        "pc": 0x1008,
    }),
    ("prov_edge", "rootE", 4, {}),
    ("prov_node", { # from c3
        "id": 5,
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x5500, 0x0, 0x10, rw_perm, t=4),
        "pc": 0x100c,
    }),
    ("prov_edge", "partial-3", 5, {}),
    ("prov_edge", 2, 5, {"only": "expect"}),
    ("prov_node", { # from pcc
        "id": 6,
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x7000, 0x0, 0x1000, rw_perm, t=5),
        "pc": 0x100c,
    }),
    ("prov_edge", "partial-32", 6, {}),
    ("prov_edge", "rootD", 6, {"only": "expect"}),
    ("prov_node", { # extra vertex only in this subgraph
        "id": "rootF",
        "reg": 5,
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x1500, 0x0, 0x100, rw_perm, t=6),
        "pc": 0x100c,
    }),
    ("prov_edge", "partial-5", "rootF", {}),
)

# merge initial vertex
# Test 2-step merge error due to dereferences in a partial
# without previous matching vertex
trace_step_2_err_partial_deref = (
    ("partial", {
        "id": "partial-1",
        "evt": {
            "time": [10],
            "addr": [0xff00],
            "type": [ProvenanceVertexData.EventType.DEREF_LOAD]
        }
    }),
)

# merge initial vertex
# Test 2-step merge error due to missing parent.
trace_step_2_err_no_parent = (
    ("prov_node", {
        "id": 0,
        "origin": CheriNodeOrigin.ANDPERM,
        "cap": model_cap(0x1500, 0x0, 0x100, rw_perm, t=6),
        "pc": 0x100c,
    }),
    ("prov_edge", "partial-1", 0, {}),
)

# merge initial vertex
# Test 2-step merge error due to multiple parents
trace_step_1_err_many_parents = (
    ("prov_node", {
        "id": "parent1",
        "reg": 1,
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x1000, 0x0, 0x100, rw_perm, t=0),
        "pc": 0x1500
    }),
    ("prov_node", {
        "id": "parent2",
        "reg": 2,
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x1000, 0x0, 0x100, rw_perm, t=1),
        "pc": 0x1600
    })
)
trace_step_2_err_many_parents = (
    ("prov_node", {
        "id": 0,
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x1000, 0x0, 0x10, rw_perm, t=4),
        "pc": 0x1700
    }),
    ("prov_edge", "partial-1", 0, {}),
    ("prov_edge", "partial-2", 0, {}),
)

# merge initial vertex
# Test 2-step merge root suppression when a valid parent is found
trace_step_1_root_suppress = (
    ("prov_node", {
        "id": "parent",
        "reg": 1,
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x5000, 0x0, 0x100, rw_perm, t=100),
        "pc": 0x2000
    }),
)
trace_step_2_root_suppress = (
    ("prov_node", {
        "only": "subgraph",
        "id": "suppressed",
        "reg": 1,
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x5000, 0x0, 0x100, rw_perm, t=150),
        "pc": 0x4000
    }),
    ("prov_node", {
        "id": 0,
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x5000, 0x0, 0x10, rw_perm, t=200),
        "pc": 0x5000
    }),
    ("prov_edge", "partial-1", "suppressed", {}),
    ("prov_edge", "suppressed", 0, {}),
    ("prov_edge", "parent", 0, {"only": "expect"}),
)

# merge initial vertex-memory map
# Test vertex memory map merge
#
# step1:
# partial1 -> rootA -> 0 [0x10000]
# partial2 -> rootB -> 1 [0x10100]
#                   -> 2 [0x10200]
# step2:
# [0x10000] partial4 -> rootC -> 3
# [0x10200] partial5 -> rootD -> 4
trace_step_1_vmap = (
    ("prov_node", {
        "id": "rootA",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x2000, 0x0, 0x1000, rw_perm, t=100),
        "pc": 0x2000
    }),
    ("prov_node", {
        "id": "rootB",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x3000, 0x0, 0x1000, rw_perm, t=101),
        "pc": 0x2004
    }),
    ("prov_node", {
        "id": 0,
        "mem": 0x10000,
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x2000, 0x0, 0x100, rw_perm, t=102),
        "pc": 0x2008
    }),
    ("prov_node", {
        "id": 1,
        "mem": 0x10100,
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x3000, 0x0, 0x100, rw_perm, t=103),
        "pc": 0x200c
    }),
    ("prov_node", {
        "id": 2,
        "mem": 0x10200,
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x3500, 0x0, 0x100, rw_perm, t=104),
        "pc": 0x2010
    }),
    ("prov_edge", "partial-1", "rootA", {}),
    ("prov_edge", "partial-2", "rootB", {}),
    ("prov_edge", "rootA", 0, {}),
    ("prov_edge", "rootB", 1, {}),
    ("prov_edge", "rootB", 2, {}),
)
trace_step_2_vmap = (
    ("prov_node", {
        "only": "subgraph",
        "id": "rootC",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x2000, 0x0, 0x100, rw_perm, t=100),
        "pc": 0x2000
    }),
    ("prov_node", {
        "only": "subgraph",
        "id": "rootD",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x3500, 0x0, 0x100, rw_perm, t=101),
        "pc": 0x2004
    }),
    ("prov_node", {
        "id": 3,
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x2000, 0x0, 0x10, rw_perm, t=102),
        "pc": 0x2008
    }),
    ("prov_node", {
        "id": 4,
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x3000, 0x0, 0x10, rw_perm, t=103),
        "pc": 0x200c
    }),
    ("prov_edge", "mem:0x10000", "rootC", {}),
    ("prov_edge", "mem:0x10200", "rootD", {}),
    ("prov_edge", "rootC", 3, {"only": "subgraph"}),
    ("prov_edge", "rootD", 4, {"only": "subgraph"}),
    ("prov_edge", 0, 3, {"only": "expect"}),
    ("prov_edge", 2, 4, {"only": "expect"}),
)

# merge initial vertex-memory map
# Test vertex memory map merge error with incompatible
# previous vertex.
# There are 3 cases:
# - mismatch on base
# - mismatch on bounds
# - mismatch on permissions
trace_step_1_vmap_err_incompatible = (
    ("prov_node", {
        "id": "incompatible",
        "mem": 0x10000,
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x2000, 0x0, 0x100, rw_perm, t=100),
        "pc": 0x2000
    }),
)
trace_step_2_vmap_err_incompatible_base_up = (
    ("prov_node", {
        "id": "root",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x2200, 0x0, 0x100, rw_perm, t=100),
        "pc": 0x3000
    }),
    ("prov_edge", "mem:0x10000", "root", {}),
)
trace_step_2_vmap_err_incompatible_base_down = (
    ("prov_node", {
        "id": "root",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x1000, 0x0, 0x100, rw_perm, t=100),
        "pc": 0x3000
    }),
    ("prov_edge", "mem:0x10000", "root", {}),
)
trace_step_2_vmap_err_incompatible_bound_up = (
    ("prov_node", {
        "id": "root",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x2000, 0x0, 0x1000, rw_perm, t=100),
        "pc": 0x3000
    }),
    ("prov_edge", "mem:0x10000", "root", {}),
)
trace_step_2_vmap_err_incompatible_bound_down = (
    ("prov_node", {
        "id": "root",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x2000, 0x0, 0x10, rw_perm, t=100),
        "pc": 0x3000
    }),
    ("prov_edge", "mem:0x10000", "root", {}),
)
trace_step_2_vmap_err_incompatible_perms = (
    ("prov_node", {
        "id": "root",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x2000, 0x0, 0x100, rwx_perm, t=100),
        "pc": 0x3000
    }),
    ("prov_edge", "mem:0x10000", "root", {}),
)

# merge initial vertex-memory map
# Test vertex memory map merge with no previous vertex.
trace_step_2_vmap_no_previous_vertex = (
    ("prov_node", {
        "id": "root",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0xf000, 0x0, 0x100, rw_perm, t=100),
        "pc": 0x3000
    }),
    ("prov_edge", "mem:0x10000", "root", {}),
)

# merge begin call graph vertex
# Test merging of a simple call graph without connections to
# the provenance graph.
trace_begin_call_graph = (
    ("call_node", {
        "root": True,
        "id": 0,
        "addr": None,
    }),
)

# merge begin call graph vertices
# Test the merge logic when multiple roots are added to the original
# root because extra returns were found.
trace_begin_call_graph_extra_ret = (
    ("call_node", {
        "root": True,
        "id": 0,
        "addr": None,
    }),
    ("call_node", {
        "id": 1,
        "addr": None,
        "t_return": 1000,
        "addr_return": 0x100c,
    }),
    ("call_edge", 0, 1, {
        "operation": EdgeOperation.CALL,
        "time": 0,
        "addr": 0,
    }),
)

# merge begin call graph vertex
# Test merging of simple call subgraphs without connections to
# the provenance graph.
# <call-root> -> 1 -> 3
trace_step_1_call_graph = (
    ("call_node", {
        "root": True,
        "id": 0,
        "addr": None,
    }),
    ("call_node", {
        "last": True,
        "id": 1,
        "addr": 0x1000,
    }),
    ("call_edge", 0, 1, {
        "operation": EdgeOperation.CALL,
        "time": 1000,
        "addr": 0xf000,
    }),
)
trace_step_2_call_graph = (
    ("call_node", {
        "only": "subgraph",
        "root": True,
        "id": 2,
        "addr": None,
    }),
    ("call_node", {
        "last": True,
        "id": 3,
        "addr": 0x5000,
    }),
    ("call_edge", 2, 3, {
        "only": "subgraph",
        "operation": EdgeOperation.CALL,
        "time": 2000,
        "addr": 0xb000,
    }),
    ("call_edge", 1, 3, {
        "only": "expect",
        "operation": EdgeOperation.CALL,
        "time": 2000,
        "addr": 0xb000,
    }),
)

# merge begin call graph
# Test initial merge with visible provenance layer vertices
trace_begin_call_graph_with_visible = (
    ("call_node", {
        "root": True,
        "id": "call-root",
        "addr": None,
    }),
    ("call_node", {
        "id": "fn",
        "addr": 0xf0000,
    }),
    ("prov_node", {
        "id": "arg0",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x1000, 0x0, 0x100, rw_perm, t=100),
        "pc": 0x3000
    }),
    ("prov_node", {
        "id": "arg1",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x5000, 0x0, 0x100, rw_perm, t=100),
        "pc": 0x10000
    }),
    ("call_edge", "call-root", "fn", {
        "operation": EdgeOperation.CALL,
        "time": 10,
        "addr": 0x1000,
    }),
    ("call_edge", "arg0", "fn", {
        "operation": EdgeOperation.VISIBLE,
        "time": 10,
        # offset of arg0 at time of call != from offset in the prov vertex
        "addr": 0x50,
        # pretend we found arg0 in $c10
        "regs": [10],
    }),
    ("call_edge", "arg1", "fn", {
        "operation": EdgeOperation.VISIBLE,
        "time": 10,
        "addr": 0x10,
        "regs": [4],
    }),
    ("prov_edge", "partial-1", "arg0", {}),
    ("prov_edge", "partial-2", "arg1", {}),
)

# merge begin call graph
# Test initial merge with visible provenance layer vertices
# where a PARTIAL vertex is visible
trace_begin_call_graph_partial_visible = (
    ("call_node", {
        "root": True,
        "id": "call-root",
        "addr": None,
    }),
    ("call_node", {
        "id": "fn",
        "addr": 0xf0000,
    }),
    ("prov_node", {
        "id": "arg0",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x1000, 0x0, 0x100, rw_perm, t=100),
        "pc": 0x3000
    }),
    ("call_edge", "call-root", "fn", {
        "operation": EdgeOperation.CALL,
        "time": 10,
        "addr": 0x1000,
    }),
    ("call_edge", "arg0", "fn", {
        "operation": EdgeOperation.VISIBLE,
        "time": 10,
        # offset of arg0 at time of call != from offset in the prov vertex
        "addr": 0x50,
        # pretend we found arg0 in $c10
        "regs": [10],
    }),
    ("call_edge", "partial-2", "fn", {
        "operation": EdgeOperation.VISIBLE,
        "time": 10,
        "addr": 0x10,
        "regs": [4],
    }),
    ("prov_edge", "partial-1", "arg0", {}),
)

@pytest.mark.timeout(4)
@pytest.mark.parametrize("mock_model, error", [
    (trace_begin_simple_model, None),
    (trace_begin_partial_multi_root, None),
    (trace_begin_partial_non_root, None),
    (trace_begin_partial_all_non_root, None),
    (trace_begin_call_graph, None),
    (trace_begin_call_graph_extra_ret, None),
    (trace_begin_call_graph_with_visible, None),
    (trace_begin_call_graph_partial_visible, None),
])
def test_single_step_merge(worker_result_base, mock_model, error):
    """
    Generate a simple subgraph and the expected merged graph.
    and test them
    """
    result = ProvenanceGraphManager("")
    expect = ProvenanceGraphManager("")
    builder = MockGraphBuilder(expect)
    builder.build(worker_result_base, mock_model)

    ctx = MergePartialSubgraphContext(result)
    if error is None:
        ctx.step(worker_result_base)
        assert_graph_equal(expect.graph, result.graph)
    else:
        with pytest.raises(error):
            ctx.step(worker_result_base)

@pytest.mark.timeout(4)
@pytest.mark.parametrize("mock_model1, mock_model2, error", [
    (trace_step_1_no_mem, trace_step_2_no_mem, None),
    (trace_step_empty, trace_step_2_err_partial_deref, SubgraphMergeError),
    (trace_step_empty, trace_step_2_err_no_parent, MissingParentError),
    (trace_step_1_err_many_parents, trace_step_2_err_many_parents, SubgraphMergeError),
    (trace_step_1_root_suppress, trace_step_2_root_suppress, None),
    (trace_step_1_vmap, trace_step_2_vmap, None),
    (trace_step_1_vmap_err_incompatible,
     trace_step_2_vmap_err_incompatible_base_up, SubgraphMergeError),
    (trace_step_1_vmap_err_incompatible,
     trace_step_2_vmap_err_incompatible_base_down, SubgraphMergeError),
    (trace_step_1_vmap_err_incompatible,
     trace_step_2_vmap_err_incompatible_bound_up, SubgraphMergeError),
    (trace_step_1_vmap_err_incompatible,
     trace_step_2_vmap_err_incompatible_bound_down, SubgraphMergeError),
    (trace_step_1_vmap_err_incompatible,
     trace_step_2_vmap_err_incompatible_perms, SubgraphMergeError),
    (trace_step_1_vmap_err_incompatible,
     trace_step_2_vmap_err_incompatible_perms, SubgraphMergeError),
    (trace_step_empty, trace_step_2_vmap_no_previous_vertex, None),
    (trace_step_1_call_graph, trace_step_2_call_graph, None),
])
def test_two_step_merge(mock_model1, mock_model2, error):
    """
    Generate a simple subgraph and the expected merged graph.
    and test them
    """
    worker_result_1 = worker_result_base()
    worker_result_2 = worker_result_base()
    result = ProvenanceGraphManager("")
    expect = ProvenanceGraphManager("")
    builder = MockGraphBuilder(expect)
    builder.build(worker_result_1, mock_model1)
    builder.build(worker_result_2, mock_model2)

    ctx = MergePartialSubgraphContext(result)
    if error is None:
        ctx.step(worker_result_1)
        ctx.step(worker_result_2)
        assert_graph_equal(expect.graph, result.graph)
    else:
        with pytest.raises(error):
            ctx.step(worker_result_1)
            ctx.step(worker_result_2)
