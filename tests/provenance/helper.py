import pytest
import logging
import operator

from itertools import repeat
from functools import reduce
from io import StringIO

from graph_tool.all import subgraph_isomorphism

from cheriplot.provenance.model import (
    ProvenanceGraphManager, CheriCap, ProvenanceVertexData, CheriNodeOrigin,
    CheriCapPerm, EdgeOperation, CallVertexData)
from cheriplot.core.test import MockTraceWriter

logger = logging.getLogger(__name__)

def dump_vertices(graph):
    dump = StringIO()
    for v in graph.vertices():
        data = graph.vp.data[v]
        if graph.vp.layer_prov[v]:
            layer = "provenance"
        elif graph.vp.layer_call[v]:
            layer = "call"
        else:
            layer = "no-layer"
        dump.write("%d (%s): %s\n" % (v, layer, data))
    return dump.getvalue()

def dump_edges(graph):
    dump = StringIO()
    for e in graph.edges():
        dump.write("%d -> %d\n" % (e.source(), e.target()))
    return dump.getvalue()

def assert_vertex_equal(exp_graph, exp_v, other_graph, other_v):
    """
    Test that two provenance graph vertices have the same
    properties and data.
    """
    # test layer association
    v_layer = exp_graph.vp.layer_prov[exp_v]
    u_layer = other_graph.vp.layer_prov[other_v]
    assert v_layer == u_layer,\
        "provenance layer mapping differ expect:%s found:%s" % (v_layer, u_layer)
    v_layer = exp_graph.vp.layer_call[exp_v]
    u_layer = other_graph.vp.layer_call[other_v]
    assert v_layer == u_layer,\
        "call layer mapping differ expect:%s found:%s" % (v_layer, u_layer)
    # test vertex data
    v_data = exp_graph.vp.data[exp_v]
    u_data = other_graph.vp.data[other_v]
    if other_graph.vp.layer_prov[other_v]:
        assert_prov_vertex_data_equal(v_data, u_data)
    elif other_graph.vp.layer_call[other_v]:
        assert_call_vertex_data_equal(v_data, u_data)
    else:
        pytest.fail("Invalid vertex layer %s (expected: %s)", u_data, v_data)

def assert_prov_vertex_data_equal(u_data, v_data):
    """
    Test that two provenance graph vertices have the same data
    """
    assert u_data.origin == v_data.origin,\
        "origin differ expect:%s found:%s" % (u_data, v_data)
    assert u_data.pc == v_data.pc,\
        "pc differ expect:%s found:%s" % (u_data, v_data)
    assert u_data.is_kernel == v_data.is_kernel,\
        "is_kernel differ expect:%s found:%s" % (u_data, v_data)
    assert u_data.cap == v_data.cap,\
        "cap differ expect:%s found:%s" % (u_data, v_data)
    assert u_data.cap.offset == v_data.cap.offset,\
        "cap offset differ expect:%s found:%s" % (u_data, v_data)
    # events should be unordered but for performance reasons
    # we ensure ordering at the use/deref/memop category level
    memop_mask = ProvenanceVertexData.EventType.memop_mask()
    deref_mask = ProvenanceVertexData.EventType.deref_mask()
    use_mask = ProvenanceVertexData.EventType.use_mask()
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

    assert bool_match, "events differ:\nexpect:%s\nfound:%s" % (
        u_data.event_tbl, v_data.event_tbl)

def assert_call_vertex_data_equal(u_data, v_data):
    """
    Test that two call graph vertices have the same data
    """
    assert u_data == v_data, "call differ:\nexpect:%s\nfound:%s" % (
        u_data, v_data)

def assert_graph_equal(expect, other):
    """
    Test if the graph is equal to the given one.
    This is intended mostly for testing purposes.
    """
    __tracebackhide__ = True
    assert expect.num_vertices() == other.num_vertices(),\
        "Number of vertices differ expected %d, found %d\n%s\n%s\n\n%s\n%s" % (
            expect.num_vertices(), other.num_vertices(),
            dump_vertices(expect), dump_edges(expect),
            dump_vertices(other), dump_edges(other))
    n_vertices = expect.num_vertices()

    # check if the graphs are isomorphic
    # there must exist an isomorphism for which the vertex
    # data matches, so we check all of them.
    isomaps = subgraph_isomorphism(expect, other, subgraph=False)
    assert len(isomaps) > 0, "Graph topology differ:\n%s\n%s\n\n%s\n%s" % (
        dump_vertices(expect), dump_edges(expect),
        dump_vertices(other), dump_edges(other))
    errors = []
    for isomap in isomaps:
        try:
            # check that vertices match
            for v in expect.vertices():
                assert_vertex_equal(expect, v, other, isomap[v])
                # v_data = expect.vp.data[v]
                # u = isomap[v]
                # u_data = other.vp.data[u]
                # assert_vertex_equal(v_data, u_data)
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

def mk_pvertex(cap, parent=None, origin=CheriNodeOrigin.ROOT, pc=None,
               mem=None, t_alloc=-1, t_free=-1, vid=None):
    """
    Create ProvenanceTraceWriter side-effect to produce a vertex in the
    provenance layer.
    """
    def _data():
        """Generate expected provenance vertex and edge data."""
        data = ProvenanceVertexData()
        data.origin = origin
        data.pc = pc
        if pc != None:
            data.is_kernel = pc > 0x7fffffffffffffff
        data.cap = CheriCap(cap)
        data.cap.t_alloc = t_alloc
        data.cap.t_free = t_free
        return data, None, vid
    return (parent, _data)

def mk_cvertex(addr, parent=None, pc=None, call_time=None, vid=None):
    """
    Create ProvenanceTraceWriter side-effect to produce a vertex in the
    call layer.
    """
    def _data():
        """Generate expected vertex and edge data."""
        data = CallVertexData(addr)
        edata = {"operation": EdgeOperation.CALL}
        if pc is not None:
            edata["addr"] = pc
        if call_time is not None:
            edata["time"] = call_time
        return data, edata, vid
    return (parent, _data)

def mk_cvertex_ret(parent):
    """
    Create ProvenanceTraceWriter side-effect to set a call-vertex
    return time and address to the current instruction.
    """
    return parent

def mk_vertex_deref(vertex_id, addr, is_cap, type_):
    """
    Generate the side-effect data for an expected vertex
    dereference, this should be used with the vertex_deref
    side-effect key in the trace writer.
    """
    if type_ == "load":
        type_ = ProvenanceVertexData.EventType.DEREF_LOAD
    elif type_ == "store":
        type_ = ProvenanceVertexData.EventType.DEREF_STORE
    elif type_ == "call":
        type_ = ProvenanceVertexData.EventType.DEREF_CALL
    return (vertex_id, addr, is_cap, type_)

def mk_vertex_call(vertex_id, symbol, type_):
    """
    Generate the side-effect data for an expected vertex
    used as call argument or return, this should be used with the vertex_call
    side-effect key in the trace writer.
    """
    if type_ == "syscall_arg":
        type_ = (ProvenanceVertexData.EventType.USE_SYSCALL |
                 ProvenanceVertexData.EventType.USE_IS_ARG)
    elif type_ == "syscall_ret":
        type_ = ProvenanceVertexData.EventType.USE_SYSCALL
    elif type_ == "call":
        type_ = ProvenanceVertexData.EventType.USE_CALL
    elif type_ == "ccall":
        type_ = ProvenanceVertexData.EventType.USE_CCALL
    return (vertex_id, symbol, type_)

def mk_vertex_mem(vertex_id, addr, type_):
    """
    Generate the side-effect data for an expected vertex store,
    this should be used with the vertex_store side-effect
    key in the trace writer.

    Note: type_ may assume the following values:
    load: the vertex is loaded from some place
    store: the vertex is stored somewhere
    """
    if type_ == "load":
        type_ = ProvenanceVertexData.EventType.LOAD
    elif type_ == "store":
        type_ = ProvenanceVertexData.EventType.STORE
    return (vertex_id, addr, type_)

class ProvenanceTraceWriter(MockTraceWriter):
    """
    Mock writer that also generates the provenance graph
    description from the trace description.
    """

    def __init__(self, *args):
        super().__init__(*args)
        self.pgm = ProvenanceGraphManager("mock-trace")
        """Mock graph manager."""

        self._expect_vertex_id_map = {}
        """Map a user-defined node name to the node in the expected graph."""

    def _process_entry(self, instr, side_effects):
        if instr:
            return super()._process_entry(instr, side_effects)
        else:
            super()._process_side_effects(None, side_effects)
            return None

    def _id_to_vertex(self, vid):
        if vid is None:
            return None
        return self._expect_vertex_id_map[vid]

    def _side_effect(self, entry, key, val):
        if key == "pvertex":
            # side effect that creates a provenance layer vertex
            v = self.pgm.graph.add_vertex()
            self.pgm.layer_prov[v] = True
            # the side effect parameter is (parent, ProvenanceVertexData)
            parent_id, data_builder = val
            parent = self._id_to_vertex(parent_id)
            edge = None
            if parent is not None:
                # valid parent
                edge = self.pgm.graph.add_edge(self.pgm.graph.vertex(parent), v)
            data, edata, vid = data_builder()
            self._expect_vertex_id_map[vid] = v
            if data.pc == None:
                # fixup the pc with the trace entry pc
                data.pc = entry.pc
                data.is_kernel = entry.pc > 0x7fffffffffffffff
            # fixup t_alloc if not already set
            if data.cap.t_alloc == -1:
                # if entry is None this must be a root node, so by convention it is 0
                data.cap.t_alloc = entry.cycles if entry else 0
            logger.debug("register mock prov vertex %s -> %s", parent, data)
            self.pgm.data[v] = data
        elif key == "cvertex":
            # side effect that creates a call layer vertex
            v = self.pgm.graph.add_vertex()
            self.pgm.layer_call[v] = True
            # the side effect parameter is (parent, ProvenanceVertexData)
            parent_id, data_builder = val
            parent = self._id_to_vertex(parent_id)
            data, edata, vid = data_builder()
            self._expect_vertex_id_map[vid] = v
            logger.debug("register mock call vertex %s -> %s", parent, data)
            if parent is not None:
                edge = self.pgm.graph.add_edge(self.pgm.graph.vertex(parent), v)
                for k,v in edata.items():
                    setattr(self.pgm.graph.ep[edge], k, v)
            self.pgm.data[v] = data
        elif key == "cret":
            v = self._id_to_vertex(val)
            assert self.pgm.layer_call[v] == True,\
                "cret side-effect for non-call layer vertex %d" % val
            data = self.pgm.data[v]
            # set the return time/addr of a call-layer vertex to the
            # current entry values
            data.t_return = entry.cycles
            data.addr_return = entry.pc
        elif key == "vertex_mem":
            # a vertex memory write or read is expected
            # see mk_vertex_mem
            vid, addr, type_ = val
            v = self._id_to_vertex(vid)
            self.pgm.data[v].add_event(entry.cycles, addr, type_)
        elif key == "vertex_deref":
            # a vertex dereference is expected
            vid, addr, is_cap, type_ = val
            v = self._id_to_vertex(vid)
            self.pgm.data[v].add_deref(entry.cycles, addr, is_cap, type_)
        elif key == "vertex_call":
            # a vertex is expected to be used as a call/return argument
            vid, sym, type_ = val
            v = self._id_to_vertex(vid)
            self.pgm.data[v].add_event(entry.cycles, sym, type_)
        else:
            super()._side_effect(entry, key, val)


class MockGraphBuilder:
    """
    Factory that generates the expected graph and result partial graph
    from the same model specification.
    This is similar to the MockTraceWriter.
    """

    def __init__(self, expect):
        self.expect = expect
        self.expect_node_id = {}

    def make_subgraph_node_id_map(self, gm):
        """
        Generate map of node-id to vertex for a subgraph
        mock result.
        This sets the partial vertices to the correct vertices.
        """
        node_id_map = {}
        idx = 0
        for v in gm.graph.vertices():
            vdata = gm.data[v]
            if vdata.origin == CheriNodeOrigin.PARTIAL:
                node_id_map["partial-%d" % idx] = v
                idx += 1
        return node_id_map

    def build_prov_node(self, gm, idmap, spec):
        """Create a mock node in the provenance layer."""
        v = gm.graph.add_vertex()
        gm.layer_prov[v] = True
        vdata = ProvenanceVertexData()
        for key, val in spec.items():
            if key == "id":
                idmap[val] = v
            elif hasattr(vdata, key):
                setattr(vdata, key, val)
        gm.data[v] = vdata
        return v

    def build_call_node(self, gm, idmap, spec):
        """
        Create a mock node in the call layer.
        XXX this may be combined with build_call_node
        """
        v = gm.graph.add_vertex()
        gm.layer_call[v] = True
        vdata = CallVertexData(None)
        for key, val in spec.items():
            if key == "id":
                idmap[val] = v
            elif hasattr(vdata, key):
                setattr(vdata, key, val)
        gm.data[v] = vdata
        return v

    def build_prov_edge(self, gm, idmap, src, dst, spec):
        try:
            src_idx = idmap[src]
            dst_idx = idmap[dst]
        except KeyError:
            # indexing an only-vertex or partial
            return
        e = gm.graph.add_edge(src_idx, dst_idx)

    def build_subgraph_prov_edge(self, mock_result, idmap, src, dst, spec):
        gm = mock_result["pgm"]
        try:
            dst_idx = idmap[dst]
        except KeyError:
            # indexing an only-vertex
            return

        if type(src) == str and "mem:" in src:
            # create a partial vertex in the memory map by simulating a load
            # from empty location
            _,addr = src.split(":")
            vmap = mock_result["mem_vertex_map"]
            vmap.mem_load(int(addr, 16), dst_idx)
        else:
            try:
                src_idx = idmap[src]
            except KeyError:
                return
            e = gm.graph.add_edge(src_idx, dst_idx)

    def set_final_regset(self, regset, v, spec):
        """put the vertex in the final register set"""
        reg = spec.get("reg", None)
        if reg is not None:
            if reg == "pcc":
                regset._pcc = v
            else:
                regset.reg_nodes[reg] = v

    def set_final_vmap(self, vmap, v, spec):
        """put the vertex in the final vertex memory map"""
        addr = spec.get("mem", None)
        if addr is not None:
            vmap.mem_store(addr, v)

    def build(self, mock_result, model):
        """
        Generate the expected and test input graphs
        from a gml-like graph specification
        """
        subgraph = mock_result["pgm"]
        mock_node_id_map = self.make_subgraph_node_id_map(subgraph)
        for item in model:
            item_type = item[0]
            if item_type == "prov_node":
                # provenance vertex
                spec = item[1]
                only = spec.pop("only", None)
                if only is None or only == "subgraph":
                    v = self.build_prov_node(subgraph, mock_node_id_map, spec)
                    self.set_final_regset(mock_result["regset"], v, spec)
                    self.set_final_vmap(mock_result["mem_vertex_map"], v, spec)
                if only is None or only == "expect":
                    self.build_prov_node(self.expect, self.expect_node_id, spec)
            elif item_type == "prov_edge":
                # provenance edge
                src, dst, spec = item[1:]
                only = spec.pop("only", None)
                if only is None or only == "subgraph":
                    self.build_subgraph_prov_edge(mock_result, mock_node_id_map,
                                                  src, dst, spec)
                if only is None or only == "expect":
                    self.build_prov_edge(self.expect, self.expect_node_id,
                                         src, dst, spec)
            elif item_type == "partial":
                # modify partial vertex
                spec = item[1]
                v = mock_node_id_map[spec["id"]]
                vdata = subgraph.data[v]
                # the only thing that can be changed of the partial is
                # the event table
                evt = spec.get("evt", None)
                if evt is not None:
                    vdata.events = evt
            elif item_type == "call_node":
                # call vertex
                spec = item[1]
                self.build_call_node(subgraph, mock_node_id_map, spec)
                self.build_call_node(self.expect, self.expect_node_id, spec)
