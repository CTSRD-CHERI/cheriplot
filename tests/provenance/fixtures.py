"""
Common module fixtures.
"""

import pytest

from cheriplot.provenance.model import ProvenanceGraphManager

@pytest.fixture
def pgm():
    return ProvenanceGraphManager(None)
