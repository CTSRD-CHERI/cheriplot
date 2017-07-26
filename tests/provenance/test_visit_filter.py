"""
Test the graph visitor filters.
"""

import pytest
import logging
from unittest.mock import Mock, call

from cheriplot.provenance.model import (
    CheriNodeOrigin, CheriCapPerm, EdgeOperation, ProvenanceGraphManager)

from cheriplot.provenance.visit import (
    FilterNullAndKernelVertices, FilterCfromptr, MergeCfromptr, BFSGraphVisit)

from tests.provenance.helper import (
    assert_graph_equal, MockGraphBuilder, model_cap)

logging.basicConfig(level=logging.DEBUG)


def test_chain_visit():
    """
    Test that chained visitors are traversed in the correct order
    """
    
    class Chain0(BFSGraphVisit):
        def __call__(self, graph_view):
            graph_view.call_chain(0)
            return graph_view

    class Chain1(BFSGraphVisit):
        def __call__(self, graph_view):
            graph_view.call_chain(1)
            return graph_view

    class Chain2(BFSGraphVisit):
        def __call__(self, graph_view):
            graph_view.call_chain(2)
            return graph_view

    tmp = Chain1(None) + Chain2(None)
    chained = Chain0(None) + tmp
    result = chained(Mock())
    assert result.call_chain.call_args_list == [call(0), call(1), call(2)]


rw_perm = CheriCapPerm.LOAD | CheriCapPerm.STORE

# test the NULL and kernel vertex filter
# A(kern) -> B(kern) -> C
#         -> D -> E(null)
# F -> G
# call-root
graph_filter_null_kernel = (
    ("prov_node", {
        "only": "subgraph",
        "id": "A",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x0, 0x0, 0x10000, rw_perm, t=0),
        "is_kernel": True,
        "pc": 0x1000,
    }),
    ("prov_node", {
        "only": "subgraph",
        "id": "B",
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x5000, 0x0, 0x5000, rw_perm, t=5),
        "is_kernel": True,
        "pc": 0x2000
    }),
    ("prov_node", {
        "id": "C",
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x6000, 0x0, 0x100, rw_perm, t=10),
        "pc": 0xf0000
    }),
    ("prov_node", {
        "id": "D",
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x0, 0x0, 0x5000, rw_perm, t=20),
        "pc": 0xf5000
    }),
    ("prov_node", {
        "only": "subgraph",
        "id": "E",
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x0, 0x0, 0x0, rw_perm, t=25),
        "pc": 0xf7000
    }),
    ("prov_edge", "A", "B", {}),
    ("prov_edge", "B", "C", {}),
    ("prov_edge", "A", "D", {}),
    ("prov_edge", "D", "E", {}),
    ("prov_node", {
        "id": "F",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x20000, 0x0, 0x1000, rw_perm, t=60),
        "pc": 0xff000,
    }),
    ("prov_node", {
        "id": "G",
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x20000, 0x0, 0x100, rw_perm, t=65),
        "pc": 0xff100
    }),
    ("prov_edge", "F", "G", {}),
    ("call_node", {
        "id": "call-root",
        "addr": None,
    }),
)

# test the cfromptr filter
graph_filter_cfromptr = (
    ("call_node", {
        "id": "call-root",
        "addr": None,
    }),
    ("prov_node", {
        "id": "A",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x0, 0x0, 0x10000, rw_perm, t=0),
        "pc": 0x1000,
    }),
    ("prov_node", {
        "id": "B",
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x5000, 0x0, 0x5000, rw_perm, t=5),
        "pc": 0x2000
    }),
    ("prov_node", {
        "only": "subgraph",
        "id": "C",
        "origin": CheriNodeOrigin.FROMPTR,
        "cap": model_cap(0x6000, 0x0, 0x100, rw_perm, t=10),
        "pc": 0xf0000
    }),
    ("prov_node", {
        "id": "D",
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x6000, 0x0, 0x10, rw_perm, t=15),
        "pc": 0x2000
    }),
    ("prov_edge", "A", "B", {}),
    ("prov_edge", "A", "C", {}),
    ("prov_edge", "C", "D", {}),
)

# test merge cfromptr and csetbounds
# A -> B
#   -> C -> D -> E
# call-root
graph_merge_cfromptr = (
    ("call_node", {
        "id": "call-root",
        "addr": None,
    }),
    ("prov_node", {
        "id": "A",
        "origin": CheriNodeOrigin.ROOT,
        "cap": model_cap(0x0, 0x0, 0x10000, rw_perm, t=0),
        "pc": 0x1000,
    }),
    ("prov_node", {
        "id": "B",
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x5000, 0x0, 0x5000, rw_perm, t=5),
        "pc": 0x2000
    }),
    ("prov_node", {
        "only": "subgraph",
        "id": "C",
        "origin": CheriNodeOrigin.FROMPTR,
        "cap": model_cap(0x6000, 0x0, 0x100, rw_perm, t=10),
        "pc": 0xf0000
    }),
    ("prov_node", {
        "only": "subgraph",
        "id": "D",
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x6000, 0x0, 0x10, rw_perm, t=15),
        "pc": 0x2000
    }),
    ("prov_node", {
        "only": "expect",
        "id": "CD",
        "origin": CheriNodeOrigin.PTR_SETBOUNDS,
        "cap": model_cap(0x6000, 0x0, 0x10, rw_perm, t=15),
        "pc": 0x2000
    }),
    ("prov_node", {
        "id": "E",
        "origin": CheriNodeOrigin.SETBOUNDS,
        "cap": model_cap(0x6000, 0x0, 0x1, rw_perm, t=20),
        "pc": 0x3000
    }),
    ("prov_edge", "A", "B", {}),
    ("prov_edge", "A", "C", {"only": "subgraph"}),
    ("prov_edge", "C", "D", {"only": "subgraph"}),
    ("prov_edge", "D", "E", {"only": "subgraph"}),
    ("prov_edge", "A", "CD", {"only": "expect"}),
    ("prov_edge", "CD", "E", {"only": "expect"}),
)

@pytest.mark.timeout(4)
@pytest.mark.parametrize("mock_model, visitor_class, error", [
    (graph_filter_null_kernel, FilterNullAndKernelVertices, None),
    (graph_filter_cfromptr, FilterCfromptr, None),
    (graph_merge_cfromptr, MergeCfromptr, None),
])
def test_filter(mock_model, visitor_class, error):
    """
    Generate a simple subgraph and the expected merged graph.
    and test them
    """
    input_ = ProvenanceGraphManager("")
    expect = ProvenanceGraphManager("")
    builder = MockGraphBuilder(expect)
    builder.build_graph(input_, mock_model)

    visitor = visitor_class(input_)
    if error is None:
        result_view = visitor(input_.graph)
        result_view.purge_vertices()
        assert_graph_equal(expect.graph, result_view)
    else:
        with pytest.raises(error):
            visitor(input_.graph)
