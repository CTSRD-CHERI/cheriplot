"""
Copyright 2016 Alfredo Mazzinghi

Copyright and related rights are licensed under the BERI Hardware-Software
License, Version 1.0 (the "License"); you may not use this file except
in compliance with the License.  You may obtain a copy of the License at:

http://www.beri-open-systems.org/legal/license-1-0.txt

Unless required by applicable law or agreed to in writing, software,
hardware and materials distributed under this License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
express or implied.  See the License for the specific language governing
permissions and limitations under the License.


Test data structure build functions for plots using the provenance tree
"""

import pytest
import logging
from unittest import mock
from operator import attrgetter

from cheriplot.plot import PointedAddressFrequencyPlot
from cheriplot.provenance_tree import CheriCapNodeNX

def mknode(start, end):
    node = CheriCapNodeNX()
    node.base = start
    node.length = end - start
    return node

def mkrange(start, end, count):
    r_node = PointedAddressFrequencyPlot.DataRange(start, end)
    r_node.num_references = count
    return r_node

# test node sets
graph_nodes = [
    [mknode(0x00, 0x2000), mknode(0x4000, 0x6000), mknode(0x1000, 0x5000)],
    [mknode(0x1000, 0x2000), mknode(0x3000, 0x4000), mknode(0x00, 0x5000)],
    [mknode(0x1000, 0x2000), mknode(0x3000, 0x4000), mknode(0x1500, 0x3500),
     mknode(0x3000, 0x3500)],
]

# expected range set for each node set
expected_ranges = [
    [mkrange(0x00, 0x1000, 1), mkrange(0x1000, 0x2000, 2),
     mkrange(0x2000, 0x4000, 1), mkrange(0x4000, 0x5000, 2),
     mkrange(0x5000, 0x6000, 1)],
    [mkrange(0x00, 0x1000, 1), mkrange(0x1000, 0x2000, 2),
     mkrange(0x2000, 0x3000, 1), mkrange(0x3000, 0x4000, 2),
     mkrange(0x4000, 0x5000, 1)],
    [mkrange(0x1000, 0x1500, 1), mkrange(0x1500, 0x2000, 2),
     mkrange(0x2000, 0x3000, 1), mkrange(0x3000, 0x3500, 3),
     mkrange(0x3500, 0x4000, 1)],
]

@pytest.fixture()
@mock.patch("cheriplot.plot.provenance_plot.PointerProvenanceParser")
def plot(patch):
    logging.basicConfig(level=logging.DEBUG)
    plot = PointedAddressFrequencyPlot("no_file")
    dataset = mock.MagicMock()
    plot.dataset = dataset
    return plot

@pytest.mark.parametrize("node_list,expected", zip(graph_nodes, expected_ranges))
def test_extract_ranges(plot, node_list, expected):
    plot.dataset.nodes.return_value = node_list
    
    plot._extract_ranges()

    range_set = sorted(plot.range_set, key=attrgetter("start"))
    expect = sorted(expected, key=attrgetter("start"))
    print(range_set, expect)

    assert len(range_set) == len(expect)
    for r_out, r_expect in zip(range_set, expect):        
        assert r_out.start == r_expect.start
        assert r_out.end == r_expect.end
        assert r_out.num_references == r_expect.num_references
