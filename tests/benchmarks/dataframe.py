"""
These tests aim to justify the use cases and performance
characteristics of pandas dataframes.

Since no reliable information is found about the real performance,
here we present the evaluation of some critical aspects of data frames
when it comes to use cases relevant to cheriplot.
"""

import pytest
import numpy as np
import pandas as pd

from tests.utils import skipbenchmark


@pytest.fixture
def long_table_data():
    t = np.random.randint(10**9, size=10**7)
    a = np.random.randint(2**32, size=10**7)
    k = np.random.randint(10, size=10**7)
    return (t, a, k)

@pytest.fixture
def short_table_data():
    t = np.random.randint(10**9, size=10**4)
    a = np.random.randint(2**32, size=10**4)
    k = np.random.randint(10, size=10**4)
    return (t, a, k)

@pytest.fixture
def dataframe():
    """
    Generate a predictable dataframe with lots of data.
    This is used to test indexing operations on dataframes
    vs dictionary-based data.

    The table has 3 columns, two are linspaces with unique values,
    the third has 1/3 of the data randomly duplicated so that
    matching on that column will return multiple rows of data.
    """
    t = np.linspace(0, 10**7, dtype=int, num=10**7)
    a = np.linspace(0, 10**7, dtype=int, num=10**7)
    k = np.linspace(0, 10**7, dtype=int, num=10**7)
    src = 10**6
    dst = np.arange(0, 10**7, 10**4)
    k[dst] = k[src]
    df = pd.DataFrame({"t": t, "a": a, "k": k})
    return (k[src], df)

@skipbenchmark
@pytest.mark.parametrize("table_data", [
    short_table_data
])
@pytest.mark.benchmark(group="dataframe-gen")
def test_benchmark_dataframe_gen_dict(benchmark, table_data):
    def gen():
        table = {"t": [], "a": [], "k": []}
        for tt, aa, kk in zip(*table_data()):
            table["t"].append(tt)
            table["a"].append(aa)
            table["k"].append(kk)
        df = pd.DataFrame(table, dtype=np.uint64)

    benchmark.pedantic(gen, rounds=2, iterations=1)

@skipbenchmark
@pytest.mark.parametrize("table_data", [
    short_table_data
])
@pytest.mark.benchmark(group="dataframe-gen")
def test_benchmark_dataframe_gen_append(benchmark, table_data):
    # forced to clip the size of the dataset otherwise it takes > 30min
    def gen():
        df = pd.DataFrame(columns=["t", "a", "k"], dtype=np.uint64)
        for tt, aa, kk in zip(*table_data()):
            df.loc[len(df)] = [tt, aa, kk]

    benchmark.pedantic(gen, rounds=2, iterations=1)

@skipbenchmark
@pytest.mark.parametrize("table_data, prealloc_size", [
    (short_table_data, 10),
    (short_table_data, 10**2),
    (short_table_data, 10**3),
    (short_table_data, 5*10**3)
])
@pytest.mark.benchmark(group="dataframe-gen")
def test_benchmark_dataframe_gen_append_prealloc(benchmark, table_data, prealloc_size):
    """
    This still extends the dataframe online but preallocates chunks
    of 1K blocks.
    """
    def gen():
        df = pd.DataFrame(columns=["t", "a", "k"], dtype=np.uint64)
        idx = 0
        for tt, aa, kk in zip(*table_data()):
            if idx == len(df):
                df = df.reindex(range(0, len(df.index) + prealloc_size), copy=False)
            df.loc[idx] = [tt, aa, kk]
            idx += 1

    benchmark.pedantic(gen, rounds=2, iterations=1)

@skipbenchmark
@pytest.mark.benchmark(group="dataframe-read")
def test_benchmark_read_dict(benchmark, dataframe):
    dup_value, df = dataframe
    table = df.to_dict(orient="list")

    def gen():
        n = sum(aa for aa, kk in zip(table["a"], table["k"]) if kk == dup_value)
        assert n == 4995000000

    benchmark.pedantic(gen, rounds=2, iterations=1)

@skipbenchmark
@pytest.mark.benchmark(group="dataframe-read")
def test_benchmark_read_dataframe(benchmark, dataframe):
    dup_value, df = dataframe
    
    def gen():
        n = df[df["k"] == dup_value]["a"].sum()
        assert n == 4995000000

    benchmark.pedantic(gen, rounds=2, iterations=1)

@skipbenchmark
@pytest.mark.parametrize("entries", np.logspace(4, 8, num=5, dtype=int))
@pytest.mark.benchmark(group="dataframe-create")
def test_benchmark_build_dataframe(benchmark, entries):
    """
    The goal of this test is to check dataframe creation time when
    dictionaries are large.
    """
    tbl = {
        "t": np.random.randint(0, 10**4, size=entries),
        "a": np.random.randint(0, 10**4, size=entries),
        "k": np.random.randint(0, 10**4, size=entries)
    }

    def gen():
        df = pd.DataFrame(tbl, dtype=np.uint64)

    benchmark.pedantic(gen, rounds=2, iterations=1)
