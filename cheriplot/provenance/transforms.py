#-
# Copyright (c) 2016-2017 Alfredo Mazzinghi
# All rights reserved.
#
# This software was developed by SRI International and the University of
# Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
# ("CTSRD"), as part of the DARPA CRASH research programme.
#
# @BERI_LICENSE_HEADER_START@
#
# Licensed to BERI Open Systems C.I.C. (BERI) under one or more contributor
# license agreements.  See the NOTICE file distributed with this work for
# additional information regarding copyright ownership.  BERI licenses this
# file to you under the BERI Hardware-Software License, Version 1.0 (the
# "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at:
#
#   http://www.beri-open-systems.org/legal/license-1-0.txt
#
# Unless required by applicable law or agreed to in writing, Work distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations under the License.
#
# @BERI_LICENSE_HEADER_END@
#

import logging
import numpy as np

from graph_tool.all import BFSVisitor, bfs_search, DFSVisitor, dfs_search

from cheriplot.provenance.model import CheriNodeOrigin

logger = logging.getLogger(__name__)

def bfs_transform(graph, transforms):
    """
    Run a set of transformations through the graph.
    This is O(n) in the number of vertices of the graph,
    however running multiple transforms at once saves time
    because the root vertices have to be searched only once.
    """
    roots = []
    # find roots (normally there should be only one)
    for v in graph.vertices():
        if v.in_degree() == 0:
            roots.append(v)
    for t in transforms:
        for v in roots:
            bfs_search(graph, v, t)
    # apply the transforms here so that they can not
    # invalidate the vertex handles even if one of them
    # deletes vertices (note that property maps are not
    # invalidated by deletion)
    for t in transforms:
        t.apply_transform()

class BFSTransform(BFSVisitor):
    """
    Base class for Breadth first transformations.
    Note:
    the guideline here is that the vertices are NOT removed from
    the graph, instead we mask the graph nodes that we do not want
    to keep. The rationale is that we do not need to pay the price
    for vertex removal for temporary transformations that are not
    saved and the vertices can be removed toghether using the
    mask when necessary.
    """

    def apply_transform(self):
        """
        This method is called at the end of the visit.
        It is used to apply the transformation to the
        graph when it is safe to do so.
        """
        pass

class SingleMaskBFSTransform(BFSVisitor):
    """
    Transform that masks the graph after scanning the vertices
    """

    def __init__(self, graph):
        super().__init__()
        self.graph = graph
        self.vertex_mask = graph.new_vertex_property("bool")

    def apply_transform(self):
        vf,inverted = self.graph.get_vertex_filter()
        if vf is None:
            self.graph.set_vertex_filter(self.vertex_mask, inverted=True)
        elif inverted:
            vf.a |= self.vertex_mask.a
        else:
            vf.a |= np.logical_not(self.vertex_mask.a)


class MaskNullAndKernelVertices(SingleMaskBFSTransform):
    """
    Transform that masks kernel vertices and null capabilities.
    """

    def examine_vertex(self, u):
        data = self.graph.vp.data[u]
        if ((data.pc != 0 and data.is_kernel) or
            (data.cap.length == 0 and data.cap.base == 0)):
            self.vertex_mask[u] = True


class MergeCFromPtr(SingleMaskBFSTransform):
    """
    Transform that adds merged vertices that represent
    a cfromtpr immediately followed by a csetbounds and masks the
    original cfromptr and csetbounds vertices.
    """

    def examine_vertex(self, u):
        if u.in_degree() == 0:
            # root node
            return
        parent = None
        for p in u.in_neighbours():
            if not self.vertex_mask[p]:
                # found a parent that is not masked
                assert parent is None, \
                    "Found node with more than a single parent"
                parent = p
        assert parent is not None, "No unmasked parent for a node"
        parent_data = self.graph.vp.data[parent]
        data = self.graph.vp.data[u]
        if (parent_data.origin == CheriNodeOrigin.FROMPTR and
            data.origin == CheriNodeOrigin.SETBOUNDS):
            data.origin = CheriNodeOrigin.PTR_SETBOUNDS
            if parent.in_degree() == 0:
                self.vertex_mask[parent] = True
            else:
                next_parent = next(parent.in_neighbours())
                self.vertex_mask[parent] = True
                for child in parent.out_neighbours():
                    self.graph.add_edge(next_parent, child)

class MaskCFromPtr(SingleMaskBFSTransform):
    """
    Transform that removes cfromptr vertices that are never stored
    in memory nor used for dereferencing.
    """

    def examine_vertex(self, u):
        data = self.graph.vp.data[u]
        if data.origin == CheriNodeOrigin.FROMPTR:
            self.vertex_mask[u] = True
            # if (data.origin == CheriNodeOrigin.FROMPTR and
            #     len(data.address) == 0 and
            #     len(data.deref["load"]) == 0 and
            #     len(data.deref["load"]) == 0):
            #     # remove cfromptr that are never stored or used in
            #     # a dereference
            #     self.vertex_mask[u] = True
