"""
Test the core plotting components
"""
import pytest
import numpy as np

from itertools import chain
from sortedcontainers import SortedList
from unittest import mock
from cheriplot.core.plot import *

benchmark = pytest.mark.skipif(not pytest.config.getoption("--run-benchmark"),
                               reason="Requires --run-benchmark option")

range_set_10 = [(0,10), (20,30), (40,50), (60,70)]
# assume that the omit_scale is 0.01
range_values = [
    # test some simple ranges
    (range_set_10, 0, 0),
    (range_set_10, 5, 5),
    (range_set_10, 10, 10),
    (range_set_10, 15, 10.05),
    (range_set_10, 20, 10.1),
    (range_set_10, 25, 15.1),
]

range_values_inverse = [
    # test some simple ranges
    (range_set_10, 0, 0),
    (range_set_10, 5, 5),
    (range_set_10, 10, 10),
    (range_set_10, 10.05, 15),
    (range_set_10, 10.1, 20),
    (range_set_10, 15.1, 25),
]

merge_test_ranges = [
    # simple add on empty set
    ([], (0,20), [(0,20)]),
    # simple add
    (range_set_10, (12,15), range_set_10 + [(12,15)]),
    # these should be identity
    (range_set_10, (0,5), range_set_10),
    (range_set_10, (0,10), range_set_10),
    (range_set_10, (20,30), range_set_10),
    (range_set_10, (25,30), range_set_10),
    (range_set_10, (65,70), range_set_10),
    (range_set_10, (60,70), range_set_10),
    # extend left
    (range_set_10, (15, 20), [(0,10), (15,30), (40,50), (60,70)]),
    (range_set_10, (15, 25), [(0,10), (15,30), (40,50), (60,70)]),
    (range_set_10, (15, 30), [(0,10), (15,30), (40,50), (60,70)]),
    (range_set_10, (15, 25), [(0,10), (15,30), (40,50), (60,70)]),
    (range_set_10, (55, 65), [(0,10), (20,30), (40,50), (55,70)]),
    # extend right
    (range_set_10, (10, 15), [(0,15), (20,30), (40,50), (60,70)]),
    (range_set_10, (5, 15), [(0,15), (20,30), (40,50), (60,70)]),
    (range_set_10, (25, 35), [(0,10), (20,35), (40,50), (60,70)]),
    (range_set_10, (30, 35), [(0,10), (20,35), (40,50), (60,70)]),
    (range_set_10, (65, 75), [(0,10), (20,30), (40,50), (60,75)]),
    (range_set_10, (70, 75), [(0,10), (20,30), (40,50), (60,75)]),
    # complete overlap
    (range_set_10, (15, 35), [(0,10), (15,35), (40,50), (60,70)]),    
    # join 2 ranges
    (range_set_10, (25, 45), [(0,10), (20,50), (60,70)]),
    (range_set_10, (15, 45), [(0,10), (15,50), (60,70)]),
    # join multiple ranges
    (range_set_10, (15, 65), [(0,10), (15,70)]),
    (range_set_10, (15, 60), [(0,10), (15,70)]),
    (range_set_10, (15, 80), [(0,10), (15,80)]),
]

@pytest.fixture
def trans():
    return AddressSpaceCollapseTransform()

def intervals_ids(value):
    return "10^%d intervals" % value

@pytest.fixture(params=np.logspace(2,5,4), ids=intervals_ids)
def intervals(request):
    """
    Generate disjoint intervals for benchmark tests to check
    how things scale in the number of intervals
    """
    n = request.param
    step = 20
    start = np.arange(0, step*n, step)
    end = start + step / 2
    return np.column_stack((start, end))

@pytest.fixture
def intervals_1000():
    """
    Generate 1000 intervals for benchmarks to check how things
    scale in the number of lookups
    """
    n = 1000
    step = 20
    start = np.arange(0, step*n, step)
    end = start + step / 2
    return np.column_stack((start, end))

@pytest.mark.parametrize("r_in,r_add,r_out", merge_test_ranges)
def test_interval_merge(trans, r_in, r_add, r_out):
    r_in = trans._merge(r_in + [r_add])
    assert len(r_in) == len(r_out)
    assert set(r_in) == set(r_out)

@benchmark
def test_interval_merge_benchmark(benchmark, trans):
    ints = np.random.randint(0,100,10000)
    data = np.column_stack((ints, ints + 30))
    def run():
        trans._merge(data)
    benchmark.pedantic(run, iterations=5, rounds=100)

@mock.patch("cheriplot.core.plot.addrspace_axes.AddressSpaceCollapseTransform._gen_omit_scale")
@pytest.mark.parametrize("ranges,val,expect", range_values)
def test_collapse_transform(mock_scale, trans, ranges, val, expect):
    trans.set_ranges(ranges)
    trans.omit_scale = 0.01
    t = trans.transform([float(val), 0])
    assert t[0] == expect

@mock.patch("cheriplot.core.plot.addrspace_axes.AddressSpaceCollapseTransform._gen_omit_scale")
@pytest.mark.parametrize("ranges,val,expect", range_values_inverse)
def test_collapse_inverse_transform(mock_scale, trans, ranges, val, expect):
    trans.set_ranges(ranges)
    trans.omit_scale = 0.01
    t = trans.inverted().transform([float(val), 0])
    assert pytest.approx(t[0], 0.000001) == expect

@benchmark
def test_collapse_benchmark_intervals(benchmark, trans, intervals):
    trans.set_ranges(intervals)
    # trigger gen_intervals outside benchmark loop
    trans.transform((0,0))
    max_interval = np.max(intervals[:,1])
    def run():
        trans.get_x(np.random.randint(0, max_interval))
    benchmark.pedantic(run, iterations=5, rounds=100)

@benchmark
@pytest.mark.parametrize("rounds", np.logspace(2,4,3))
def test_collapse_benchmark_lookup(benchmark, trans, intervals_1000, rounds):
    intervals = intervals_1000
    trans.set_ranges(intervals)
    # trigger gen_intervals outside benchmark loop
    trans.transform((0,0))
    max_interval = np.max(intervals[:,1])
    def run():
        for i in range(int(rounds)):
            trans.get_x(np.random.randint(0, max_interval))
    benchmark.pedantic(run, iterations=1, rounds=10)
