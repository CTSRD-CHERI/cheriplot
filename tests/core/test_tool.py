"""
Test the DriverTool automated parser generation and configuration dispatch
"""
import pytest

from unittest import mock
from cheriplot.core import *

def test_driver_tool():

    result = {
        "init_called": False,
        "run_called": False
    }
    class TaskA(TaskDriver):
        a_foo = Option(help="A foo", type=int)
        a_bar = Argument(help="A bar")

        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            assert self.config.a_foo == 10
            assert self.config.a_bar == "arg_bar_A"

        def run(self):
            pass

    run_driver_tool(TaskA, ["--a_foo", "10", "arg_bar_A"])
