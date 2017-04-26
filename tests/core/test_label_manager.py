"""
Test the LabelManager ordering of matplotlib text artists.
Use real matplotlib objects, this needs to be also an interop test
and mocking the matplotlib interface is hard in this case.

"""
import pytest
import logging
import numpy as np

from unittest import mock
from matplotlib.text import Text
from matplotlib import transforms as mtransform
from cheriplot.core import LabelManager

logging.basicConfig(level=logging.DEBUG)

def assert_no_hoverlap(labels, xmin=-np.inf, xmax=np.inf):
    """
    Check that a list of labels do not overlap
    and that the label ordering is preserved.
    """
    for idx, lb in enumerate(labels):
        lb_box = lb.get_window_extent()
        # check the constraints
        assert lb_box.xmin >= xmin and lb_box.xmax <= xmax
        for other_idx, other_lb in enumerate(labels):
            if idx == other_idx:
                continue
            other_lb_box = other_lb.get_window_extent()
            # check label ordering
            if other_idx < idx:
                assert other_lb_box.xmin < lb_box.xmin
            # check label overlap
            assert not lb_box.overlaps(other_lb_box)

def assert_no_voverlap(labels):
    """
    Check that a list of labels do not overlap
    and that the label ordering is preserved.
    """
    for idx, lb in enumerate(labels):
        lb_box = lb.get_window_extent()
        for other_idx, other_lb in enumerate(labels):
            if idx == other_idx:
                continue
            other_lb_box = other_lb.get_window_extent()
            if other_idx < idx:
                assert other_lb_box.ymin < lb_box.ymin
            assert not lb_box.overlaps(other_lb_box)

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
def renderer():
    renderer = mock.Mock()
    renderer.configure_mock(name="renderer")

# label width is set to 0.1 fixed
label_width = 0.1
label_height = 0.1
labels = [
    # no overlap
    [0.1, 0.25],
    # one overlapping group
    [0.2, 0.25],
    [0.2, 0.25, 0.30],
    [0, 0.1, 0.15],
    # one overlapping group that when moved overlaps
    # something else
    [0.2, 0.25, 0.30, 0.41],
    [0.2, 0.25, 0.30, 0.41, 0.52],
    # two overlapping groups
    [0.2, 0.25, 0.50, 0.55],
    # check that we do not cause order inversion
    [0.2, 0.21, 0.22],
]

@pytest.fixture(params=labels)
def h_label_set(request):
    lb = list(map(lambda t: Text(t, 0, text="(%f, %f)" % (t, 0)), request.param))
    return lb

@pytest.fixture(params=labels)
def v_label_set(request):
    lb = list(map(lambda t: Text(0, t, text="(%f, %f)" % (0, t)), request.param))
    return lb

# mock everything in matplotlib so that we have direct control over
# what the label manager sees, all matplotlib transformations are
# identities and the bbox coordinates coincide with the data coordinates
@mock.patch.object(Text, "get_window_extent", autospec=True)
def test_resolve_horizontal_overlap(mock_method, renderer, hlabel_manager, h_label_set):
    mock_method.side_effect = lambda self, renderer=None: (
        mtransform.Bbox.from_bounds(self._x, self._y, label_width, label_height))
    hlabel_manager.add_labels(h_label_set)
    hlabel_manager.update_label_position(renderer)
    assert_no_hoverlap(h_label_set)

@mock.patch.object(Text, "get_window_extent", autospec=True)
def test_resolve_vertical_overlap(mock_method, renderer, vlabel_manager, v_label_set):
    mock_method.side_effect = lambda self, renderer=None: (
        mtransform.Bbox.from_bounds(self._x, self._y, label_width, label_height))
    vlabel_manager.add_labels(v_label_set)
    vlabel_manager.update_label_position(renderer)
    assert_no_voverlap(v_label_set)

@pytest.mark.skip(reason="Label manager constraints not supported yet")
@mock.patch.object(Text, "get_window_extent", autospec=True)
def test_resolve_h_overlap_constrain(mock_method, renderer, hlabel_manager, h_label_set):
    mock_method.side_effect = lambda self, renderer=None: (
        mtransform.Bbox.from_bounds(self._x, self._y, label_width, label_height))
    hlabel_manager.add_labels(h_label_set)
    hlabel_manager.constraint = (0.3, np.inf)
    hlabel_manager.update_label_position(renderer)
    assert_no_hoverlap(h_label_set, xmin=0.3, xmax=np.inf)
