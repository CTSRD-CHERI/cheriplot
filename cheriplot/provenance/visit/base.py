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
"""
Base classes and functions for cheriplot graph visit.
"""

import logging

from graph_tool.all import BFSVisitor, bfs_search, DFSVisitor, dfs_search

from cheriplot.core import ProgressTimer

logger = logging.getLogger(__name__)

class GraphVisitBase:
    """
    Base class for graph visiting classes.
    
    This enforces the basic structure and metadata to display progress
    and combine transformations.
    Note:
    the guideline here is that the vertices are NOT removed from
    the graph, instead we mask the graph nodes that we do not want
    to keep. The rationale is that we do not need to pay the price
    for vertex removal for temporary transformations that are not
    saved and the vertices can be removed toghether using the
    mask when necessary.
    """

    order = None
    description = ""

    def __init__(self, pgm):
        """
        Base constructor for a graph visit.

        :param pgm: graph model manager
        """
        super().__init__()

        self.pgm = pgm
        """The graph manager model."""

    def __call__(self, graph_view):
        """
        Visit the graph with the given view.

        :param graph_view: a :class:`graph_tool.GraphView`
        :return: a :class:`graph_tool.GraphView` after the scan.
        """
        with ProgressTimer("%s" % self, logger):
            if self.order == "bfs":
                bfs_search(graph_view, visitor=self)
            elif self.order == "dfs":
                dfs_search(graph_view, visitor=self)
            else:
                raise ValueError("Invalid visit order %s" % self.order)
            return self.finalize(graph_view)

    def finalize(self, graph_view):
        """
        Generate the final graph view and other data from the visit.

        :param graph_view: a :class:`graph_tool.GraphView`
        :return: a :class:`graph_tool.GraphView` after the scan.
        """
        return graph_view

    def __add__(self, other):
        try:
            if self.order != other.order:
                raise ValueError("Can not chain %s visitor with %s visitor" % (
                    other.order, self.order))
            return ChainGraphVisit(self.pgm, self, other)
        except AttributeError:
            raise TypeError("Can not add graph visit to %s" % type(other))

    def __str__(self):
        return "Graph visit %s: order:%s %s" % (
            self.__class__.__name__, self.order, self.description)


class ChainGraphVisit(GraphVisitBase):
    """
    Chain multiple visits when executed.
    """

    def __init__(self, pgm, *args):
        """
        Build a chain visit with the given visitors.

        :param *args: variable number of visitors to chain
        """
        super().__init__(pgm)

        self._visitors = list(args)

        self.order = args[-1].order if len(args) else None

    def __add__(self, other):
        """
        Append a visitor to the visitors chain.

        :param other: a :class:`GraphVisitBase`
        """
        if not isinstance(other, GraphVisitBase):
            raise TypeError("Can not add graph visit to %s" % type(other))
        if len(self._visitors) and other.order != self._visitors[0].order:
            raise ValueError("Can not chain %s visitor with %s visitor" % (
                other.order, self._visitors[0].order))
        self._visitors.append(other)
        return self

    def __call__(self, graph_view):
        for visitor in self._visitors:
            graph_view = visitor(graph_view)
        return graph_view


class BFSGraphVisit(BFSVisitor, GraphVisitBase):
    """Breadth-first-search ordering graph visitor."""

    order = "bfs"


class DFSGraphVisit(DFSVisitor, GraphVisitBase):
    """Depth-first-search ordering graph visitor."""

    order = "dfs"
