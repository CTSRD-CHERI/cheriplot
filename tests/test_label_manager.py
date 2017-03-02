"""
Test the LabelManager ordering of matplotlib text artists.
Use real matplotlib objects, this needs to be also an interop test
and mocking the matplotlib interface is hard in this case.

"""
import pytest
import logging

from unittest import mock
from matplotlib import text as mtext
from matplotlib import transforms as mtransform
from matplotlib import pyplot
from cheriplot.core import LabelManager

logging.basicConfig(level=logging.DEBUG)

@pytest.fixture
def hlabel_manager():
    # horizontal label manager
    mgr = LabelManager(direction="h")
    return mgr

@pytest.fixture
def vlabel_manager():
    # vertical label manager
    mgr = LabelManager(direction="v")
    return mgr

@pytest.fixture
def fig_and_ax():
    # pyplot axes
    fig = pyplot.figure(figsize=[10, 10])
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)    
    return (fig, ax)

def mklabel(x, y):
    lb = mtext.Text(x, y, text="(%f, %f)" % (x,y))
    return lb

@pytest.fixture
def label_set_no_overlap():
    # set of non-overlapping labels
    label_set = [
        mklabel(0.1, 0),
        mklabel(0.2, 0)
    ]
    return label_set

def test_non_overlapping(fig_and_ax, hlabel_manager, label_set_no_overlap):
    pass
