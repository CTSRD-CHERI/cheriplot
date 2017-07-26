"""
This module implements the various algorithms that walk the graph to filter, update or aggregate data.
"""
from .base import *
from .vertex_merge import (
    MaskBFSVisit, FilterNullAndKernelVertices, FilterCfromptr, MergeCfromptr)
from .symbols import ResolveSymbolsGraphVisit
