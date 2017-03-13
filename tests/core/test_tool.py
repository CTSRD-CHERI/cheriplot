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

@pytest.mark.timeout(2)
@mock.patch("cheriplot.core.tool.input")
def test_interactive_tool_wrap_simple_task(mock_input):
    """
    Test the interactive-tool wrapper
    """

    called = {
        "interactive_init": False,
        "interactive_run": False
    }
    class TaskA(TaskDriver):
        a_foo = Option(help="A foo", type=int)
        a_bar = Argument(help="A bar")

    @interactive_tool(key="inner_task")
    class Interactive(TaskDriver):
        non_interactive_opt = Option(help="non-interactive")
        inner_task = NestedConfig(TaskA)

        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            called["interactive_init"] = True
            assert len(self.config.__dict__) == 2
            assert self.config.inner_task.a_foo == 10
            assert self.config.inner_task.a_bar == "arg_bar_A"

        def run(self):
            called["interactive_run"] = True
            assert len(self.config.__dict__) == 2
            assert self.config.inner_task.a_foo == 100
            assert self.config.inner_task.a_bar == "arg_bar_changed"
            # change mock return value to exit the interactive loop
            mock_input.return_value = "quit"

    mock_input.return_value = "--a_foo 100 arg_bar_changed"

    run_driver_tool(Interactive, ["-i", "--a_foo", "10", "arg_bar_A"])

    assert called["interactive_init"]
    assert called["interactive_run"]

@pytest.mark.timeout(2)
@mock.patch("cheriplot.core.tool.input")
def test_interactive_tool_wrap_multiple_opts(mock_input):
    """
    Test the interactive-tool wrapper with interactive arguments
    from multiple sources
    """

    called = {
        "interactive_init": False,
        "interactive_run": False
    }
    class TaskA(TaskDriver):
        a_foo = Option(help="A foo", type=int)
        a_bar = Argument(help="A bar")

    @interactive_tool(key=["inner_task", "other_opt"])
    class Interactive(TaskDriver):
        non_interactive_opt = Option(help="non-interactive")
        inner_task = NestedConfig(TaskA)
        other_opt = Option()

        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            called["interactive_init"] = True
            assert len(self.config.__dict__) == 3
            assert self.config.inner_task.a_foo == 10
            assert self.config.inner_task.a_bar == "bar_start"
            assert self.config.other_opt == None

        def run(self):
            called["interactive_run"] = True
            assert len(self.config.__dict__) == 3
            assert self.config.inner_task.a_foo == 100
            assert self.config.inner_task.a_bar == "bar_changed"
            assert self.config.other_opt == "other"
            mock_input.return_value = "quit"

    mock_input.return_value = "--a_foo 100 --other_opt other bar_changed"

    run_driver_tool(Interactive, ["-i", "--a_foo", "10", "bar_start"])

    assert called["interactive_init"]
    assert called["interactive_run"]

@pytest.mark.timeout(2)
@mock.patch("cheriplot.core.tool.input")
def test_interactive_tool_wrap_subcommand(mock_input):
    """
    Test the interactive-tool wrapper with interactive arguments
    from multiple sources
    """

    called = {
        "interactive_init": False,
        "interactive_run": False
    }
    class TaskA(TaskDriver):
        a_foo = Option(help="A foo", type=int)
        a_bar = Argument(help="A bar")

    @interactive_tool(key=["subcmd", "empty_subcmd", "other_opt"])
    class Interactive(TaskDriver):
        non_interactive_opt = Option(help="non-interactive")
        subcmd = SubCommand(TaskA)
        empty_subcmd = SubCommand()
        other_opt = Option()

        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            called["interactive_init"] = True
            assert len(self.config.__dict__) == 3
            assert self.config.subcmd.a_foo == 10
            assert self.config.subcmd.a_bar == "bar_start"
            with pytest.raises(AttributeError):
                self.config.empty_subcmd
            assert self.config.other_opt == None

        def run(self):
            called["interactive_run"] = True
            assert len(self.config.__dict__) == 3
            assert self.config.subcmd.a_foo == 100
            assert self.config.subcmd.a_bar == "bar_changed"
            with pytest.raises(AttributeError):
                self.config.empty_subcmd
            assert self.config.other_opt == "other"
            mock_input.return_value = "quit"

    mock_input.return_value = "--other_opt other subcmd --a_foo 100 bar_changed"

    run_driver_tool(Interactive, ["-i", "subcmd", "--a_foo", "10", "bar_start"])

    assert called["interactive_init"]
    assert called["interactive_run"]
