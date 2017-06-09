
import pytest

# pytest marker that is used to mark benchmarks, these must be run explicitly
skipbenchmark = pytest.mark.skipif(not pytest.config.getoption("--run-benchmark"),
                                   reason="Requires --run-benchmark option")
