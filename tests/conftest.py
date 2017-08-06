import pytest

def pytest_addoption(parser):
    parser.addoption("--run-benchmark", action="store_true",
                     help="Run benchmark tests")
    parser.addoption("--parser-threads", nargs="+",
                     default=[1, 2],
                     help="Test parsing with the given numbers of threads")
