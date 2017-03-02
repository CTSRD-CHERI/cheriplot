"""
Test the taskdriver configuration generator
"""
import pytest
import logging
import argparse

from unittest import mock
from cheriplot.core import TaskDriver, Argument, Option

# attempt to define some task drivers

@pytest.fixture
def empty_driver():
    class EmptyDriver(TaskDriver):
        pass
    return EmptyDriver

@pytest.fixture
def arg_driver():
    class ArgDriver(TaskDriver):
        my_arg = Argument(help="ArgDriver my_arg", type=int)
    return ArgDriver

@pytest.fixture
def opt_driver():
    class OptDriver(TaskDriver):
        my_opt = Option(help="OptDriver my_opt", type=int)
    return OptDriver

@pytest.fixture
def parser():
    ap = argparse.ArgumentParser(help="Test parser")
    return ap

def test_empty_config(empty_driver):

    parser = mock.Mock()

    dict_conf = empty_driver.make_config()
    assert len(dict_conf) == 0

    empty_driver.make_config(parser)
    # check that the parser have not arguments
    assert not parser.add_argument.called
    assert not parser.add_subparsers.called
