"""
Test the core parser callback handling
"""

import pytest
import logging
import pycheritrace as pct

from unittest import mock
from tempfile import NamedTemporaryFile
from itertools import chain

from cheriplot.core import (
    CallbackTraceParser, MultiprocessCallbackParser, CheriMipsCallbacksManager)
from cheriplot.core.test import MockTraceWriter

from tests.utils import skipbenchmark

logging.basicConfig(level=logging.DEBUG)

logger = logging.getLogger(__name__)

# globally referenced mocks used to mock parser methods
mock_scan_all = mock.Mock(name="scan_all_callback")
mock_scan_all.__qualname__ = "mock_callback"
mock_scan_cap = mock.Mock(name="scan_cap_callback")
mock_scan_cap.__qualname__ = "mock_callback"
mock_scan_cap_store = mock.Mock(name="scan_cap_store_callback")
mock_scan_cap_store.__qualname__ = "mock_callback"
mock_scan_cap_load = mock.Mock(name="scan_cap_load_callback")
mock_scan_cap_load.__qualname__ = "mock_callback"
mock_scan_cap_flow = mock.Mock(name="scan_cap_bound_callback")
mock_scan_cap_flow.__qualname__ = "mock_callback"
mock_scan_cap_bound = mock.Mock(name="scan_cap_flow_callback")
mock_scan_cap_bound.__qualname__ = "mock_callback"
mock_scan_daddiu = mock.Mock(name="scan_daddiu_callback")
mock_scan_daddiu.__qualname__ = "mock_callback"
mock_scan_csc = mock.Mock(name="scan_csc_callback")
mock_scan_csc.__qualname__ = "mock_callback"
mock_scan_clc = mock.Mock(name="scan_clc_callback")
mock_scan_clc.__qualname__ = "mock_callback"

# list of opcodes used in tests
opcode_list = ["daddiu", "li", "csetbounds", "csc", "csd",
               "clc", "clb", "ccall"]

# list all expected combinations of parser callback setup and
# expected callback list returned by CallbackTraceParser._get_callbacks
expect_sets = {
    # instruction class callbacks
    (("all", mock_scan_all),): {
        "daddiu": [mock_scan_all],
        "li": [mock_scan_all],
        "csetbounds": [mock_scan_all],
        "csc": [mock_scan_all],
        "csd": [mock_scan_all],
        "clc": [mock_scan_all],
        "clb": [mock_scan_all],
        "ccall": [mock_scan_all]
    },
    (("cap", mock_scan_cap),): {
        "daddiu": [],
        "li": [],
        "csetbounds": [mock_scan_cap],
        "csc": [mock_scan_cap],
        "csd": [mock_scan_cap],
        "clc": [mock_scan_cap],
        "clb": [mock_scan_cap],
        "ccall": [mock_scan_cap]
    },
    (("cap_store", mock_scan_cap_store),): {
        "daddiu": [],
        "li": [],
        "csetbounds": [],
        "csc": [mock_scan_cap_store],
        "csd": [mock_scan_cap_store],
        "clc": [],
        "clb": [],
        "ccall": []
    },
    (("cap_load", mock_scan_cap_load),): {
        "daddiu": [],
        "li": [],
        "csetbounds": [],
        "csc": [],
        "csd": [],
        "clc": [mock_scan_cap_load],
        "clb": [mock_scan_cap_load],
        "ccall": []
    },
    (("cap_flow", mock_scan_cap_flow),): {
        "daddiu": [],
        "li": [],
        "csetbounds": [],
        "csc": [],
        "csd": [],
        "clc": [],
        "clb": [],
        "ccall": [mock_scan_cap_flow]
    },
    (("cap_bound", mock_scan_cap_bound),): {
        "daddiu": [],
        "li": [],
        "csetbounds": [mock_scan_cap_bound],
        "csc": [],
        "csd": [],
        "clc": [],
        "clb": [],
        "ccall": []
    },
    # single instruction callbacks
    (("daddiu", mock_scan_daddiu),): {
        "daddiu": [mock_scan_daddiu],
        "li": [],
        "csetbounds": [],
        "csc": [],
        "csd": [],
        "clc": [],
        "clb": [],
        "ccall": []
    },
    (("csc", mock_scan_csc),): {
        "daddiu": [],
        "li": [],
        "csetbounds": [],
        "csc": [mock_scan_csc],
        "csd": [],
        "clc": [],
        "clb": [],
        "ccall": []
    },
    # mixed multiple callbacks
    (("csc", mock_scan_csc),
     ("cap_store", mock_scan_cap_store),
     ("cap", mock_scan_cap),
     ("all", mock_scan_all)): {
        "daddiu": [mock_scan_all],
        "li": [mock_scan_all],
        "csetbounds": [mock_scan_cap, mock_scan_all],
        "csc": [mock_scan_csc, mock_scan_cap_store,
                mock_scan_cap, mock_scan_all],
        "csd": [mock_scan_cap_store, mock_scan_cap, mock_scan_all],
        "clc": [mock_scan_cap, mock_scan_all],
        "clb": [mock_scan_cap, mock_scan_all],
        "ccall": [mock_scan_cap, mock_scan_all]
    },
    (("csc", mock_scan_csc),
     ("clc", mock_scan_clc),
     ("cap_store", mock_scan_cap_store),
     ("cap", mock_scan_cap),
     ("all", mock_scan_all)): {
        "daddiu": [mock_scan_all],
        "li": [mock_scan_all],
        "csetbounds": [mock_scan_cap, mock_scan_all],
        "csc": [mock_scan_csc, mock_scan_cap_store,
                mock_scan_cap, mock_scan_all],
        "csd": [mock_scan_cap_store, mock_scan_cap, mock_scan_all],
        "clc": [mock_scan_clc, mock_scan_cap, mock_scan_all],
        "clb": [mock_scan_cap, mock_scan_all],
        "ccall": [mock_scan_cap, mock_scan_all]
    },
    (("csc", mock_scan_csc),
     ("clc", mock_scan_clc),
     ("cap_store", mock_scan_cap_store),
     ("cap", mock_scan_cap)): {
        "daddiu": [],
        "li": [],
        "csetbounds": [mock_scan_cap],
        "csc": [mock_scan_csc, mock_scan_cap_store, mock_scan_cap],
        "csd": [mock_scan_cap_store, mock_scan_cap],
        "clc": [mock_scan_clc, mock_scan_cap],
        "clb": [mock_scan_cap],
        "ccall": [mock_scan_cap]
    },
}


@pytest.fixture(params=expect_sets.keys())
@mock.patch("os.path.exists")
@mock.patch("pycheritrace.trace")
def parser_setup(mock_trace, mock_exists, request):
    
    class _Parser(CallbackTraceParser):
        callback_manager_class = CheriMipsCallbacksManager
        pass

    for cbk_name, cbk_meth in request.param:
        cbk_name = "scan_%s" % cbk_name
        setattr(_Parser, cbk_name, cbk_meth)
    expect = expect_sets[request.param]

    return (expect, _Parser(trace_path="no_file"), request.param)

@pytest.mark.parametrize("opcode", opcode_list)
def test_callbacks(parser_setup, opcode):
    # expect holds the expected mapping opcode -> expected callback list
    # parser is the parser object to test
    # setup_key is the parser_setup parameter used, it is only used
    # to show the key when an assertion fails
    expect, parser, setup_key = parser_setup

    inst = mock.Mock()
    inst.opcode = opcode

    # multiple calls should be idempotent
    # this makes sure that the internal state is not altered by mistake
    parser._cbk_manager.get_callbacks(inst)
    callbacks = list(parser._cbk_manager.get_callbacks(inst))

    assert len(callbacks) == len(expect[opcode]), \
        "Number of callbacks differ for %s with setup %s" % (
            opcode, setup_key)
    for cbk in callbacks:
        assert cbk in expect[opcode], "Callback method not expected %s" % cbk


class ThreadedParserTest(MultiprocessCallbackParser):
    """
    test the threaded parser to check that the entries it
    reads are sensible
    """

    expected_trace = (
        ("lui $at, 0x00", {"1": 0x00}),
        ("lui $at, 0x22", {"1": 0x22}),
        ("lui $at, 0x44", {"1": 0x44}),
        ("lui $at, 0x88", {"1": 0x88}),
        ("lui $at, 0xcc", {"1": 0xcc}),
    )

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # keep track of entry values found
        self.entries = []

    def scan_all(self, instr, entry, regs, last, idx):
        self.entries.append(instr.op0.value)
        assert entry.cycles == idx
        assert entry.pc == 0x2000 + idx * 4
        expected_entry = ThreadedParserTest.expected_trace[idx][1]
        assert expected_entry["1"] == instr.op0.value
        return False

    def mp_result(self):
        return self.entries

    def mp_merge(self, mp_results):
        # check that all the entries  have been inspected
        entries_seen = list(chain(*mp_results))
        self.entries = entries_seen
        values = [e[1]["1"] for e in ThreadedParserTest.expected_trace]
        assert len(entries_seen) == 5
        assert set(entries_seen) == set(values)


def test_threaded_parser():

    with NamedTemporaryFile() as tmp:
        # write mock trace
        w = MockTraceWriter(tmp.name)
        w.write_trace(ThreadedParserTest.expected_trace, pc=0x2000)

        # parse the trace and check that it did run
        p = ThreadedParserTest(trace_path=tmp.name)
        p.mp.threads = 2
        p.parse()
        assert len(p.entries) == 5


@skipbenchmark
@pytest.mark.benchmark(group="cheritrace-scan")
@pytest.mark.parametrize("start, end", [(0, 0.2), (0.5, 0.7), (0.8, 1)])
def test_raw_cheritrace_benchmark(benchmark, start, end):
    trace_path = "traces/helloworld/helloworld.cvtrace.xz"
    def run():
        trace = pct.trace.open(trace_path)
        assert trace
        def scan(entry, regs, index):
            return False
        idx_start = int(start * trace.size())
        idx_end = int(end * trace.size())
        trace.scan(scan, idx_start, idx_end, 0)
    benchmark.pedantic(run, iterations=1, rounds=5)


class NopBenchmarkTraceParser(CallbackTraceParser):

    def scan_all(self, instr, entry, regs, last, idx):
        return False

@skipbenchmark
@pytest.mark.benchmark(group="cheritrace-scan")
@pytest.mark.parametrize("start, end", [(0, 0.2), (0.5, 0.7), (0.8, 1)])
def test_cbk_parser_benchmark(benchmark, start, end):
    trace_path = "traces/helloworld/helloworld.cvtrace.xz"
    def run():
        parser = NopBenchmarkTraceParser(trace_path=trace_path)
        idx_start = int(start * trace.size())
        idx_end = int(end * trace.size())
        parser.parse(idx_start, idx_end)
    benchmark.pedantic(run, iterations=1, rounds=5)

class InstrBenchmarkTraceParser(CallbackTraceParser):

    def scan_all(self, instr, entry, regs, last, idx):
        return False

@skipbenchmark
@pytest.mark.benchmark(group="cheritrace-scan")
@pytest.mark.parametrize("start, end", [(0, 0.2), (0.5, 0.7), (0.8, 1)])
def test_cbk_parser_benchmark(benchmark, start, end):
    trace_path = "traces/helloworld/helloworld.cvtrace.xz"
    def run():
        parser = NopBenchmarkTraceParser(trace_path=trace_path)
        idx_start = int(start * trace.size())
        idx_end = int(end * trace.size())
        parser.parse(idx_start, idx_end)
    benchmark.pedantic(run, iterations=1, rounds=5)
