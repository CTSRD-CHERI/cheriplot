
import pytest
import logging
import operator

from itertools import repeat
from functools import reduce
from io import StringIO

from graph_tool.all import subgraph_isomorphism

from cheriplot.provenance import (
    PointerProvenanceParser, ProvenanceGraphManager, CheriCap,
    NodeData, CheriNodeOrigin, CheriCapPerm)
from cheriplot.core.test import MockTraceWriter

logger = logging.getLogger(__name__)

def dump_vertices(graph):
    dump = StringIO()
    for v in graph.vertices():
        data = graph.vp.data[v]
        dump.write("%d: %s\n" % (v, data))
    return dump.getvalue()

def dump_edges(graph):
    dump = StringIO()
    for e in graph.edges():
        dump.write("%d -> %d\n" % (e.source(), e.target()))
    return dump.getvalue()

def assert_vertex_equal(u_data, v_data):
    """
    Test that two provenance graph vertices have the same data
    """
    assert u_data.origin == v_data.origin,\
        "origin differ %s %s" % (u_data, v_data)
    assert u_data.pc == v_data.pc,\
        "pc differ %s %s" % (u_data, v_data)
    assert u_data.is_kernel == v_data.is_kernel,\
        "is_kernel differ %s %s" % (u_data, v_data)
    assert u_data.cap == v_data.cap,\
        "cap differ %s %s" % (u_data, v_data)
    assert u_data.cap.offset == v_data.cap.offset,\
        "cap offset differ %s %s" % (u_data, v_data)
    # events should be unordered but for performance reasons
    # we ensure ordering at the use/deref/memop category level
    memop_mask = NodeData.EventType.memop_mask()
    deref_mask = NodeData.EventType.deref_mask()
    use_mask = NodeData.EventType.use_mask()
    masks = [memop_mask, deref_mask, use_mask]
    # compare the table type column with each mask
    # t = event-table type column (Series)
    # m = mask pattern
    fn = lambda t,m: (t & m) != 0
    u_cond = map(fn, repeat(u_data.event_tbl["type"]), masks)
    v_cond = map(fn, repeat(v_data.event_tbl["type"]), masks)
    # compare the event table values for each mask position
    # t = event-table
    # cond = condition-based table index
    fn = lambda t,cond: t[cond].reset_index(drop=True)
    match = map(operator.eq,
                map(fn, repeat(u_data.event_tbl), u_cond),
                map(fn, repeat(v_data.event_tbl), v_cond))
    # extract the bool final value for each match
    # df_match = dataframe with boolean values
    # 2 all() are required
    # 1) DataFrame -> Series
    # 2) Series -> bool
    fn = lambda df_match: df_match.all().all()
    bool_match = reduce(operator.and_, map(fn, match))

    assert bool_match, "events differ:\n%s\n%s" % (
        u_data.event_tbl, v_data.event_tbl)

def assert_graph_equal(expect, other):
    """
    Test if the graph is equal to the given one.
    This is intended mostly for testing purposes.
    """
    __tracebackhide__ = True
    assert expect.num_vertices() == other.num_vertices(),\
        "Number of vertices differ expected %d, found %d\n%s\n\n%s" % (
            expect.num_vertices(), other.num_vertices(),
            dump_vertices(expect), dump_vertices(other))
    n_vertices = expect.num_vertices()

    # check if the graphs are isomorphic
    # there must exist an isomorphism for which the vertex
    # data matches, so we check all of them.
    isomaps = subgraph_isomorphism(expect, other, subgraph=False)
    assert len(isomaps) > 0, "Graph topology differ: %s\n%s\n\n%s\n%s" % (
        dump_vertices(expect), dump_edges(expect),
        dump_vertices(other), dump_edges(other))
    errors = []
    for isomap in isomaps:
        try:            
            # check that vertices match
            for v in expect.vertices():
                v_data = expect.vp.data[v]
                u = isomap[v]
                u_data = other.vp.data[u]
                assert_vertex_equal(v_data, u_data)
        except AssertionError as ex:
            errors.append((v,ex))
            continue
        else:
            break
    else:
        # all isomaps raised AssertionErrors
        msg = "Graphs do not have an isomorphism for which vertices match.\n"
        msg += "Failures for each isomorphism:\n"
        for e,iso in zip(errors, isomaps):
            msg += "Isomap: %s\n" % [iso[i] for i in range(n_vertices)]
            msg += "vertex %d: %s\n\n" % e
        pytest.fail(msg)

def mk_vertex(cap, parent=-1, origin=CheriNodeOrigin.ROOT, pc=None,
              mem=None, t_alloc=-1, t_free=-1):
    """
    Create a vertex data description that can be used as
    a ProvenanceTraceWriter side-effect to produce a
    vertex in the graph.
    """
    def _data():
        data = NodeData()
        data.origin = origin
        data.pc = pc
        if pc != None:
            data.is_kernel = pc > 0x7fffffffffffffff
        data.cap = CheriCap(cap)
        data.cap.t_alloc = t_alloc
        data.cap.t_free = t_free
        return data
    return (parent, _data)

def mk_vertex_deref(vertex_idx, addr, is_cap, type_):
    """
    Generate the side-effect data for an expected vertex
    dereference, this should be used with the vertex_deref
    side-effect key in the trace writer.
    """
    if type_ == "load":
        type_ = NodeData.EventType.DEREF_LOAD
    elif type_ == "store":
        type_ = NodeData.EventType.DEREF_STORE
    elif type_ == "call":
        type_ = NodeData.EventType.DEREF_CALL
    return (vertex_idx, addr, is_cap, type_)

def mk_vertex_call(vertex_idx, symbol, type_):
    """
    Generate the side-effect data for an expected vertex
    used as call argument or return, this should be used with the vertex_call
    side-effect key in the trace writer.
    """
    if type_ == "syscall_arg":
        type_ = NodeData.EventType.USE_SYSCALL | NodeData.EventType.USE_IS_ARG
    elif type_ == "syscall_ret":
        type_ = NodeData.EventType.USE_SYSCALL
    elif type_ == "call":
        type_ = NodeData.EventType.USE_CALL
    elif type_ == "ccall":
        type_ = NodeData.EventType.USE_CCALL
    return (vertex_idx, symbol, type_)

def mk_vertex_mem(vertex_idx, addr, type_):
    """
    Generate the side-effect data for an expected vertex store,
    this should be used with the vertex_store side-effect 
    key in the trace writer.

    Note: type_ may assume the following values:
    load: the vertex is loaded from some place
    store: the vertex is stored somewhere
    """
    if type_ == "load":
        type_ = NodeData.EventType.LOAD
    elif type_ == "store":
        type_ = NodeData.EventType.STORE
    return (vertex_idx, addr, type_)

class ProvenanceTraceWriter(MockTraceWriter):
    """
    Mock writer that also generates the provenance graph
    description from the trace description.
    """

    def __init__(self, *args):
        super().__init__(*args)
        self.pgm = ProvenanceGraphManager()
        self._current_side_effects = None

    def _process_entry(self, instr, side_effects):
        self._current_side_effects = side_effects
        if instr:
            return super()._process_entry(instr, side_effects)
        else:
            super()._process_side_effects(None, side_effects)
            return None

    def _side_effect(self, entry, key, val):
        if key == "vertex":
            v = self.pgm.graph.add_vertex()
            # the side effect parameter is (parent, NodeData)
            parent, data_builder = val
            data = data_builder()
            if data.pc == None:
                # fixup the pc with the trace entry pc
                data.pc = entry.pc
                data.is_kernel = entry.pc > 0x7fffffffffffffff
            # fixup t_alloc if not already set
            if data.cap.t_alloc == -1:
                # if entry is None this must be a root node, so by convention it is 0
                data.cap.t_alloc = entry.cycles if entry else 0
            logger.debug("register mock vdata %d -> %s", parent, data)
            self.pgm.data[v] = data
            if val[0] >= 0:
                # valid parent
                self.pgm.graph.add_edge(self.pgm.graph.vertex(parent), v)
        elif key == "vertex_mem":
            # a vertex memory write or read is expected
            # see mk_vertex_mem
            idx, addr, type_ = val
            self.pgm.data[idx].add_event(entry.cycles, addr, type_)
        elif key == "vertex_deref":
            # a vertex dereference is expected
            idx, addr, is_cap, type_ = val
            self.pgm.data[idx].add_deref(entry.cycles, addr, is_cap, type_)
        elif key == "vertex_call":
            # a vertex is expected to be used as a call/return argument
            idx, sym, type_ = val
            self.pgm.data[idx].add_event(entry.cycles, sym, type_)
        else:
            super()._side_effect(entry, key, val)
        
