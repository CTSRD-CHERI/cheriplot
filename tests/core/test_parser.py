"""
Test the core parser callback handling
"""

import pytest
import logging
from unittest import mock

from cheriplot.core import CallbackTraceParser

logging.basicConfig(level=logging.DEBUG)

# globally referenced mocks used to mock parser methods
mock_scan_all = mock.Mock(name="scan_all_callback")
mock_scan_cap = mock.Mock(name="scan_cap_callback")
mock_scan_cap_store = mock.Mock(name="scan_cap_store_callback")
mock_scan_cap_load = mock.Mock(name="scan_cap_load_callback")
mock_scan_cap_flow = mock.Mock(name="scan_cap_bound_callback")
mock_scan_cap_bound = mock.Mock(name="scan_cap_flow_callback")
mock_scan_daddiu = mock.Mock(name="scan_daddiu_callback")
mock_scan_csc = mock.Mock(name="scan_csc_callback")
mock_scan_clc = mock.Mock(name="scan_clc_callback")

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
        pass

    for cbk_name, cbk_meth in request.param:
        cbk_name = "scan_%s" % cbk_name
        setattr(_Parser, cbk_name, cbk_meth)
    expect = expect_sets[request.param]

    return (expect, _Parser(trace_path="no_file"), request.param)

@pytest.fixture
@mock.patch("os.path.exists")
@mock.patch("pycheritrace.trace")
def provenance_parser(mock_trace, mock_exists):

    return PointerProvenanceParser(trace_path="no_file")


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
    parser._get_callbacks(inst)
    callbacks = parser._get_callbacks(inst)

    assert len(callbacks) == len(expect[opcode]), \
        "Number of callbacks differ for %s with setup %s" % (
            opcode, setup_key)
    for cbk in callbacks:
        assert cbk in expect[opcode], "Callback method not expected %s" % cbk

