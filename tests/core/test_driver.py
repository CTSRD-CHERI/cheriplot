"""
Test the taskdriver configuration generator
"""
import pytest
import argparse

from unittest import mock
from cheriplot.core import *

# attempt to define some task drivers

@pytest.fixture
def empty_driver():
    class EmptyDriver(TaskDriver):
        pass
    return EmptyDriver

@pytest.fixture
def full_driver():
    class NestedArg(TaskDriver):
        my_nested = Option(help="myNested")
        my_nested_with_dest = Option(dest="override_nested")
        my_nested_arg = Argument()

    class SubArg(TaskDriver):
        my_sub = Option(help="mySubOpt")

    class FullDriver(TaskDriver):
        my_int_opt = Option(help="myIntOpt", type=int)
        my_arg = Argument(help="myArg")
        my_default_arg = Argument(default="arg_default")
        my_default_opt = Option(default="opt_default")
        nested = NestedConfig(NestedArg)
        subcmd = SubCommand(SubArg)
        proxy = ProxyConfig(proxy_opt=Option(default="proxy_default"))
    return FullDriver

@pytest.fixture
def subclass_driver():
    class Base(TaskDriver):
        my_base = Argument(help="myBaseArg")

    class Derived(Base):
        my_derived = Argument(help="myDerivedArg")
    return Derived

@pytest.fixture
def simple_driver():
    class Simple(TaskDriver):
        my_arg = Argument()
        my_opt = Option()
    return Simple

@pytest.fixture
def parser():
    ap = TaskDriverArgumentParser(description="Test parser")
    return ap

def test_empty_config(empty_driver):
    parser = mock.Mock()

    default = empty_driver.make_config(parser)
    # check that the parser have not arguments
    parser.add_argument.assert_not_called()
    parser.add_subparsers.assert_not_called()
    # check that there are no default args
    assert len(default.__dict__) == 0

def test_reuse_config(simple_driver):
    """
    Check that the config can be used to configure multiple
    parsers
    """
    parser = mock.Mock()

    # multiple calls should yield the same result
    default = simple_driver.make_config(parser)
    parser.add_argument.assert_any_call("my_arg")
    parser.add_argument.assert_any_call("--my_opt")
    assert len(default.__dict__) == 2
    assert default.my_arg == None
    assert default.my_opt == None
    parser.reset_mock()
    default = simple_driver.make_config(parser)
    parser.add_argument.assert_any_call("my_arg")
    parser.add_argument.assert_any_call("--my_opt")
    assert len(default.__dict__) == 2
    assert default.my_arg == None
    assert default.my_opt == None


def test_parser(parser):

    parser.add_argument("x.foo", metavar="foo")
    parser.add_argument("--bar", action="store_true", dest="x.y.bar")
    parser.add_argument("--baz", type=int)
    parser.add_argument("--buzz", action="store_true", dest="w.z.buzz")

    args = parser.parse_args(["--baz", "10", "--bar", "foovalue"])
    assert args.baz == 10
    assert args.x.foo == "foovalue"
    assert args.x.y.bar == True
    assert args.w.z.buzz == False

def test_full_config(full_driver):
    parser = mock.Mock()

    default = full_driver.make_config(parser)
    # check the argument parser
    parser.add_argument.assert_any_call("--my_int_opt", help="myIntOpt", type=int)
    parser.add_argument.assert_any_call("my_arg", help="myArg")
    parser.add_argument.assert_any_call("my_default_arg", default="arg_default")
    parser.add_argument.assert_any_call("--my_default_opt", default="opt_default")
    parser.add_argument.assert_any_call("--my_nested", help="myNested",
                                        dest="nested.my_nested")
    parser.add_argument.assert_any_call("--my_nested_with_dest",
                                        dest="nested.override_nested")
    parser.add_argument.assert_any_call("nested.my_nested_arg")
    subparser = parser.add_subparsers.return_value
    subparser.add_parser.assert_called_once_with("subcmd")
    new_parser = subparser.add_parser.return_value
    new_parser.add_argument.assert_any_call("--my_sub", help="mySubOpt",
                                            dest="subcmd.my_sub")
    # check defaults
    assert len(default.__dict__) == 7
    assert default.my_int_opt == None
    assert default.my_default_opt == "opt_default"
    assert default.my_arg == None
    assert default.my_default_arg == "arg_default"
    assert len(default.nested.__dict__) == 3
    assert default.nested.my_nested == None
    assert default.nested.override_nested == None
    assert default.nested.my_nested_arg == None
    assert len(default.subcmd.__dict__) == 1
    assert default.subcmd.my_sub == None
    assert default.proxy_opt == "proxy_default"

def test_interop(full_driver, parser):
    full_driver.make_config(parser)

    # check that we can call the argparse parser
    # ordering of the arguments should be respected
    args = parser.parse_args(["--my_int_opt", "10",
                              "--my_nested", "nested_opt_value",
                              "--my_nested_with_dest", "nested_with_dest_value",
                              "--proxy_opt", "proxy_opt_value",
                              "arg_value", "default_arg", "nested_arg_value",
                              "subcmd", "--my_sub", "sub_opt_value"])
    assert args.my_int_opt == 10
    assert args.my_default_opt == "opt_default"
    assert args.nested.my_nested == "nested_opt_value"
    assert args.nested.override_nested == "nested_with_dest_value"
    assert args.proxy_opt == "proxy_opt_value"
    assert args.my_arg == "arg_value"
    assert args.my_default_arg == "default_arg"
    assert args.nested.my_nested_arg == "nested_arg_value"
    assert args.subcmd.my_sub == "sub_opt_value"

def test_subclass(subclass_driver):
    parser = mock.Mock()

    default = subclass_driver.make_config(parser)
    parser.add_argument.assert_any_call("my_base", help="myBaseArg")
    parser.add_argument.assert_any_call("my_derived", help="myDerivedArg")
    assert default.my_base == None
    assert default.my_derived == None

def test_multiple_inheritance():
    class Base:
        pass

    class ConfBase(ConfigurableComponent):
        base_opt = Option(default="a")

    class Child(Base, ConfBase):
        child_opt = Option(default=100)

    default = Child.make_config(mock.Mock())
    assert len(default.__dict__) == 2
    assert default.base_opt == "a"
    assert default.child_opt == 100
