"""
Test the taskdriver configuration generator
"""
import pytest
import logging
import argparse

from unittest import mock
from cheriplot.core import TaskDriver, Argument, Option, SubCommand, NestedConfig

# attempt to define some task drivers

@pytest.fixture
def empty_driver():
    class EmptyDriver(TaskDriver):
        pass
    return EmptyDriver

@pytest.fixture
def arg_driver():
    class ArgDriver(TaskDriver):
        my_arg = Argument(help="myArgDriver", type=int)
    return ArgDriver

@pytest.fixture
def opt_driver():
    class OptDriver(TaskDriver):
        my_opt = Option(help="myOptDriver", type=int)
    return OptDriver

@pytest.fixture
def sub_driver():
    class SubArg(TaskDriver):
        my_opt = Option(help="mySubOpt")

    class SubDriver(TaskDriver):
        my_sub = SubCommand(SubArg, help="mySub")
    return SubDriver

@pytest.fixture
def nested_driver():
    class NestedArg(TaskDriver):
        my_opt = Option(help="myNestedOpt")

    class NestedDriver(TaskDriver):
        my_sub = NestedConfig(NestedArg)
    return NestedDriver

@pytest.fixture
def full_driver():
    class NestedArg(TaskDriver):
        my_nested = Option(help="myNested")

    class SubArg(TaskDriver):
        my_sub = Option(help="mySubOpt")

    class FullDriver(TaskDriver):
        my_opt1 = Option(help="myOption1")
        my_arg1 = Argument(help="myArgument1")
        my_arg2 = Argument(help="myArgument2",
                           default="my_arg2_default")
        my_opt2 = Option(help="myOption2",
                         default="my_opt2_default")
        whatever = NestedConfig(NestedArg)
        subcmd = SubCommand(SubArg)
    return FullDriver

@pytest.fixture
def parser():
    ap = argparse.ArgumentParser(description="Test parser")
    return ap

def test_empty_config(empty_driver):
    parser = mock.Mock()

    dict_conf = empty_driver.make_config()
    assert len(dict_conf) == 0

    empty_driver.make_config(parser)
    # check that the parser have not arguments
    parser.add_argument.assert_not_called()
    parser.add_subparsers.assert_not_called()

def test_arg_config(arg_driver):
    parser = mock.Mock()

    dict_conf = arg_driver.make_config()
    assert len(dict_conf) == 1
    assert dict_conf["my_arg"] == None

    arg_driver.make_config(parser)
    # check the argument
    parser.add_argument.assert_called_once_with(
        "my_arg", help="myArgDriver", type=int)

def test_opt_config(opt_driver):
    parser = mock.Mock()

    dict_conf = opt_driver.make_config()
    assert len(dict_conf) == 1
    assert dict_conf["my_opt"] == None

    opt_driver.make_config(parser)
    # check the argument
    parser.add_argument.assert_called_once_with(
        "--my_opt", help="myOptDriver", type=int)

def test_subcommand(sub_driver):
    parser = mock.Mock()
    subparser = mock.Mock()

    dict_conf = sub_driver.make_config()
    assert len(dict_conf) == 1
    assert dict_conf["my_opt"] == None

    sub_driver.make_config(parser, subparser)
    parser.add_argument.assert_not_called()
    subparser.add_parser.assert_called_once_with("my_sub", help="mySub")
    new_parser = subparser.add_parser.return_value
    new_parser.add_argument.assert_called_once_with("--my_opt", help="mySubOpt")

def test_nestedconf(nested_driver):
    parser = mock.Mock()
    subparser = mock.Mock()

    dict_conf = nested_driver.make_config()
    assert len(dict_conf) == 1
    assert dict_conf["my_opt"] == None

    nested_driver.make_config(parser, subparser)
    parser.add_argument.assert_called_once_with("--my_opt", help="myNestedOpt")
    subparser.add_parser.assert_not_called()

def test_full_config(full_driver):
    parser = mock.Mock()
    subparser = mock.Mock()

    dict_conf = full_driver.make_config()
    assert len(dict_conf) == 6
    assert dict_conf["my_opt1"] == None
    assert dict_conf["my_opt2"] == "my_opt2_default"
    assert dict_conf["my_arg1"] == None
    assert dict_conf["my_arg2"] == "my_arg2_default"
    assert dict_conf["my_nested"] == None

    parser.reset_mock()
    subparser.reset_mock()
    full_driver.make_config(parser, subparser)
    # check the argument
    parser.add_argument.assert_any_call("--my_opt1", help="myOption1")
    parser.add_argument.assert_any_call("my_arg2", help="myArgument2",
                                        default="my_arg2_default")
    parser.add_argument.assert_any_call("my_arg1", help="myArgument1")
    parser.add_argument.assert_any_call("--my_opt2", help="myOption2",
                                        default="my_opt2_default")
    parser.add_argument.assert_any_call("--my_nested", help="myNested")
    subparser.add_parser.assert_called_once_with("subcmd")
    new_parser = subparser.add_parser.return_value
    new_parser.add_argument.assert_any_call("--my_sub", help="mySubOpt")

def test_interop(full_driver, parser):
    full_driver.make_config(parser, parser.add_subparsers())

    # check that we can call the argparse parser
    args = parser.parse_args(["--my_opt1", "foo", "--my_opt2", "bar",
                              "--my_nested", "baz", "subcmd",
                              "--my_sub", "sub_opt", "arg1", "arg2"])
    assert args.my_opt1 == "foo"
    assert args.my_opt2 == "bar"
    assert args.my_arg1 == "arg1"
    assert args.my_arg2 == "arg2"
    assert args.my_nested == "baz"
    assert args.my_sub == "sub_opt"
