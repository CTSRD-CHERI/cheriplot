import pytest
import logging
import operator

from itertools import repeat, chain
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
        e_addr = graph.ep.addr[e] or 0
        e_op = EdgeOperation(graph.ep.operation[e]).name if graph.ep.operation[e] else ""
        dump.write("%d -> %d [time:%s addr:0x%x op:%s regs:%s]\n" % (
            e.source(), e.target(), graph.ep.time[e],
            e_addr, e_op, graph.ep.regs[e]))
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
        "origin differ expect:{} found:{}".format(u_data, v_data)
    assert u_data.pc == v_data.pc,\
        "pc differ expect:{} found:{}".format(u_data, v_data)
    assert u_data.is_kernel == v_data.is_kernel,\
        "is_kernel differ expect:{} found:{}".format(u_data, v_data)
    assert u_data.cap == v_data.cap,\
        "cap differ expect:{} found:{}".format(u_data, v_data)
    assert u_data.cap.offset == v_data.cap.offset,\
        "cap offset differ expect:{} found:{}".format(u_data, v_data)
    assert u_data.active_memory == v_data.active_memory,\
        "active memory differ expect:{} found:{}".format(
            u_data.active_memory, v_data.active_memory)
    # events should be unordered but for performance reasons
    # we ensure ordering at the use/deref/memop category level
    memop_mask = ProvenanceVertexData.EventType.memop_mask()
    deref_mask = ProvenanceVertexData.EventType.deref_mask()
    masks = [memop_mask, deref_mask]
    # compare the table type column with each mask
    # t = event-table type column (Series)
    # m = mask pattern
    assert len(u_data.event_tbl) == len(v_data.event_tbl),\
        "events differ:\nexpect:{}\nfound:{}".format(
            u_data.event_tbl, v_data.event_tbl)
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

    assert bool_match, "events differ:\nexpect:{}\nfound:{}".format(
        u_data.event_tbl, v_data.event_tbl)

def assert_call_vertex_data_equal(u_data, v_data):
    """
    Test that two call graph vertices have the same data
    """
    assert u_data == v_data, "call differ:\nexpect:{}\nfound:{}".format(
        u_data, v_data)

def assert_edge_equal(expect, e, other, f):
    """
    Test that two edges in the graph have equal data.
    """
    edge_dump = "expect:(%d -> %d) found:(%d -> %d)" % (
        e.source(), e.target(), f.source(), f.target())
    e_time = expect.ep.time[e]
    f_time = other.ep.time[f]
    assert e_time == f_time, "Edge %s time differ expect:%s found:%s" % (
        edge_dump, e_time, f_time)
    e_addr = expect.ep.addr[e]
    f_addr = other.ep.addr[f]
    assert e_addr == f_addr, "Edge %s addr differ expect:%s found:%s" % (
        edge_dump,
        "0x%x" % e_addr if e_addr is not None else e_addr,
        "0x%x" % f_addr if f_addr is not None else f_addr)
    e_op = expect.ep.operation[e]
    f_op = other.ep.operation[f]
    assert e_op == f_op, "Edge %s operation differ expect:%s found:%s" % (
        edge_dump,
        EdgeOperation(e_op).name if e_op is not None else e_op,
        EdgeOperation(f_op).name if f_op is not None else f_op)
    e_reg = set(expect.ep.regs[e])
    f_reg = set(other.ep.regs[f])
    assert e_reg == f_reg, "Edge %s associated register differ "\
        "expect:%s found:%s" % (edge_dump, e_reg, f_reg)

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
                for v_out in v.out_neighbours():
                    e = expect.edge(v, v_out)
                    f = other.edge(isomap[v], isomap[v_out])
                    assert_edge_equal(expect, e, other, f)
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
        msg += "Expected graph:\n%s\n%s\n\n" % (
            dump_vertices(expect), dump_edges(expect))
        msg += "Found graph:\n%s\n%s\n\n" % (
            dump_vertices(other), dump_edges(other))
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

def mk_cvertex_visible(vid, offset, *args):
    """
    Helper mostly useful for clarity.
    Create a tuple in the visible argument to :func:`mk_cvertex`

    :param vid: vertex id
    :param offset: expected offset of the vertex at call time
    :param *args: indices of registers to which the vertex is associated with.
    """
    return (vid, offset, args)

def mk_cvertex(addr, op=EdgeOperation.CALL, parent=None, pc=None,
               call_time=None, vid=None, visible=[]):
    """
    Create ProvenanceTraceWriter side-effect to produce a vertex in the
    call layer.

    :param addr: the target address of the expected call
    :param op: EdgeOperation (default CALL) of the edge connecting
    this node to the parent (set edge_operation)
    :param parent: vertex id of the parent vertex
    :param pc: address of the call instruction (set edge_addr)
    :param call_time: time of the call instruction (set edge_time)
    :param vid: id of the new vertex created, this is only a shorthand
    to reference vertices in the mock model.
    :param visible: iterable of elements of type
    (mock-vertex-id, offset, (reg,...)) where:
    *mock-vertex-id* is the id of the provenance vertex to be
    connected to the new vertex as EdgeOperation.VISIBLE;
    *offset* is the capability offset of the capability
    at the time of call;
    *reg* is the index of a register that holds the capability.
    :return: tuple containing (parent, vertex_and_edge_data_builder)
    """
    def _data():
        """Generate expected vertex and edge data."""
        data = CallVertexData(addr)
        edata = {
            "operation": op,
            "addr": pc,
            "time": call_time,
        }
        return data, edata, vid, visible
    return (parent, _data)

def mk_cvertex_ret(*args, retid=None, offset=None):
    """
    Create ProvenanceTraceWriter side-effect to set a call-vertex
    return time and address to the current instruction.

    :param *args: IDs of vertices that have the return point marked
    by this side-effect.
    :param retid: id of the provenance vertex marked as return value,
    if multiple vertices are given in *args, retid should be an iterable
    of the same length.
    :param offset: offset of the returned capability
    """
    if isinstance(retid, list) or isinstance(retid, tuple):
        assert len(args) == len(retid)
    else:
        retid = repeat(retid)
    return (args, retid, offset)

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
    elif type_ == "delete":
        type_ = ProvenanceVertexData.EventType.DELETE
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
        """
        Process an entry in the trace model.
        If an instruction is provided, then go through the normal
        entry processing for the tracewriter. If no instruction
        is give, there is not a real trace entry backing this entry,
        so process the side effects and return None (no trace entry).
        """
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
        """
        Process side effects for a mock model entry.

        :param entry: the trace entry for this model entry, may be None
        :param key: side effect key
        :param val: side effect params, depend on the side-effect
        """
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
                # if entry is None this must be a root node,
                # so by convention it is 0
                data.cap.t_alloc = entry.cycles if entry else 0
            logger.debug("register mock prov vertex %s -> %s", parent, data)
            self.pgm.data[v] = data
        elif key == "pfree":
            # set prov vertex t_free
            v = self._id_to_vertex(val)
            v_data = self.pgm.data[v]
            v_data.cap.t_free = entry.cycles if entry else -1
        elif key == "cvertex":
            # side effect that creates a call layer vertex
            v = self.pgm.graph.add_vertex()
            self.pgm.layer_call[v] = True
            # the side effect parameter is (parent, ProvenanceVertexData)
            parent_id, data_builder = val
            parent = self._id_to_vertex(parent_id)
            # see mk_cvertex for the data_builder
            data, edata, vid, visible_vertices = data_builder()
            self.pgm.data[v] = data
            self._expect_vertex_id_map[vid] = v
            logger.debug("register mock call vertex %s -> %s", parent, data)
            # set edge data defaults
            if edata["addr"] is None:
                edata["addr"] = entry.pc if entry else 0
            if edata["time"] is None:
                edata["time"] = entry.cycles if entry else 0
            if parent is not None:
                edge = self.pgm.graph.add_edge(self.pgm.graph.vertex(parent), v)
                for key,val in edata.items():
                    self.pgm.graph.ep[key][edge] = val
            for visible_vid, cap_offset, regs in visible_vertices:
                u = self._id_to_vertex(visible_vid)
                edge = self.pgm.graph.add_edge(u, v)
                self.pgm.edge_operation[edge] = EdgeOperation.VISIBLE
                self.pgm.edge_addr[edge] = cap_offset
                self.pgm.edge_time[edge] = entry.cycles if entry else 0
                self.pgm.edge_regs[edge] = regs
        elif key == "cret":
            calls, ret_vertices, ret_target = val
            for vid, ret_id in zip(calls, ret_vertices):
                v = self._id_to_vertex(vid)
                assert self.pgm.layer_call[v] == True,\
                    "cret side-effect for non-call layer vertex %d" % vid
                data = self.pgm.data[v]
                # set the return time/addr of a call-layer vertex to the
                # current entry values
                data.t_return = entry.cycles
                data.addr_return = entry.pc
                if ret_id is not None:
                    ret_v = self._id_to_vertex(ret_id)
                    edge = self.pgm.graph.add_edge(ret_v, v)
                    self.pgm.edge_operation[edge] = EdgeOperation.RETURN
                    self.pgm.edge_addr[edge] = ret_target
                    self.pgm.edge_time[edge] = entry.cycles
        elif key == "vertex_mem" or key == "vertex_mem_overwrite":
            # a vertex memory write or read is expected or
            # a vertex memory write overwrites a previous vertex
            # see mk_vertex_mem
            vid, addr, type_ = val
            v = self._id_to_vertex(vid)
            self.pgm.data[v].add_event(entry.cycles, addr, type_)
        elif key == "vertex_deref":
            # a vertex dereference is expected
            vid, addr, is_cap, type_ = val
            v = self._id_to_vertex(vid)
            self.pgm.data[v].add_deref(entry.cycles, addr, is_cap, type_)
        else:
            super()._side_effect(entry, key, val)


def model_cap(base, offset, length, perm, otype=0x0, t=0, valid=True):
    """
    Shorthand factory for CheriCap mock values to use in
    the MockGraphBuilder.
    """
    cap = CheriCap()
    cap.base = base
    cap.offset = offset
    cap.length = length
    cap.permissions = perm
    cap.objtype = otype
    cap.valid = valid
    cap.sealed = False
    cap.t_alloc = t
    cap.t_free = -1
    return cap


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
            elif key == "addr":
                vdata.address = val
            elif hasattr(vdata, key):
                setattr(vdata, key, val)
        gm.data[v] = vdata
        return v

    def build_expect_prov_edge(self, gm, idmap, src, dst, spec):
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

    def build_call_edge(self, gm, idmap, src, dst, spec):
        try:
            src_idx = idmap[src]
            dst_idx = idmap[dst]
        except KeyError:
            return
        edge = gm.graph.add_edge(src_idx, dst_idx)
        gm.edge_operation[edge] = spec.get("operation", EdgeOperation.UNKNOWN)
        gm.edge_time[edge] = spec.get("time", 0)
        gm.edge_addr[edge] = spec.get("addr", 0)
        gm.edge_regs[edge] = spec.get("regs", [])

    def set_final_regset(self, regset, v, spec):
        """put the vertex in the final register set"""
        reg = spec.get("reg", None)
        if reg is not None:
            if reg == "pcc":
                regset.reg_nodes[32] = v
            else:
                regset.reg_nodes[reg] = v

    def set_final_vmap(self, vmap, v, spec):
        """put the vertex in the final vertex memory map"""
        addr = spec.get("mem", None)
        if addr is not None:
            vmap.mem_store(addr, v)

    def _process_entry(self, subgraph, mock_result, mock_node_id_map, entry):
        """
        Process a mock graph entry.

        :param subgraph: target mock subgraph to use as input for a test
        :param mock_result: mock intermediate subgraph merge data or None
        :param mock_node_id_map: map of subgraph nodes to model IDs
        :param entry: the model entry
        """
        entry_type = entry[0]
        if entry_type == "prov_node":
            # provenance vertex
            spec = entry[1]
            only = spec.pop("only", None)
            if only is None or only == "subgraph":
                v = self.build_prov_node(subgraph, mock_node_id_map, spec)
                if mock_result:
                    self.set_final_regset(mock_result["regset"], v, spec)
                    self.set_final_vmap(mock_result["mem_vertex_map"], v, spec)
            if only is None or only == "expect":
                self.build_prov_node(self.expect, self.expect_node_id, spec)
        elif entry_type == "prov_edge":
            # provenance edge
            src, dst, spec = entry[1:]
            only = spec.pop("only", None)
            if only is None or only == "subgraph":
                if mock_result:
                    # if we are building a mock result use the appropriate method
                    self.build_subgraph_prov_edge(mock_result, mock_node_id_map,
                                                  src, dst, spec)
                else:
                    self.build_expect_prov_edge(subgraph, mock_node_id_map,
                                                src, dst, spec)
            if only is None or only == "expect":
                self.build_expect_prov_edge(self.expect, self.expect_node_id,
                                            src, dst, spec)
        elif entry_type == "partial":
            # modify partial vertex
            spec = entry[1]
            v = mock_node_id_map[spec["id"]]
            vdata = subgraph.data[v]
            # the only thing that can be changed of the partial is
            # the event table
            evt = spec.get("evt", None)
            if evt is not None:
                vdata.events = evt
        elif entry_type == "call_node":
            # call layer vertex
            spec = entry[1]
            only = spec.pop("only", None)
            if only is None or only == "subgraph":
                # call node is the root (there should only be one)
                call_root = spec.pop("root", False)
                # call node is the last (there should only be one)
                call_last = spec.pop("last", False)
                v = self.build_call_node(subgraph, mock_node_id_map, spec)
                if call_root and mock_result:
                    mock_result["sub_callgraph"]["root"] = v
                if call_last and mock_result:
                    mock_result["sub_callgraph"]["last_frame"] = v
            if only is None or only == "expect":
                self.build_call_node(self.expect, self.expect_node_id, spec)
        elif entry_type == "call_edge":
            # call layer edge
            src, dst, spec = entry[1:]
            only = spec.get("only", None)
            if only is None or only == "subgraph":
                self.build_call_edge(subgraph, mock_node_id_map,
                                     src, dst, spec)
            if only is None or only == "expect":
                self.build_call_edge(self.expect, self.expect_node_id,
                                     src, dst, spec)

    def build_graph(self, subgraph, model):
        """
        Generate an input and expected graphs from a gml-like
        graph specification.
        This is similar to the build method but it operates
        directly on a pgm instead of the merge step intermediary data.

        :param subgraph: graph manager for the input graph
        :param model: graph specification
        """
        mock_node_id_map = self.make_subgraph_node_id_map(subgraph)
        for entry in model:
            self._process_entry(subgraph, None, mock_node_id_map, entry)

    def build(self, mock_result, model):
        """
        Generate the expected and test input graphs
        from a gml-like graph specification.

        :param mock_result: the intermediate graph merge step data to fill
        :param model: the graph specification
        """
        subgraph = mock_result["pgm"]
        mock_node_id_map = self.make_subgraph_node_id_map(subgraph)
        for entry in model:
            self._process_entry(subgraph, mock_result, mock_node_id_map, entry)
