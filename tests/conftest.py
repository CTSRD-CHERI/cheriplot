import pytest

def pytest_addoption(parser):
    parser.addoption("--run-benchmark", action="store_true",
                     help="Run benchmark tests")
