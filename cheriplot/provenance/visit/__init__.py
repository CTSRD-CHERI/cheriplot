"""
This module implements the various algorithms that walk the graph to filter, update or aggregate data.
"""
from .base import (
    GraphVisitBase, ChainGraphVisit, BFSGraphVisit, DFSGraphVisit,
    MaskBFSVisit, MaskDFSVisit)
from .vertex_merge import MergeCfromptr
from .filters import (
    FilterNullVertices, FilterKernelVertices, FilterCfromptr,
    FilterStackVertices)
from .symbols import ResolveSymbolsGraphVisit
from .slice import ProvGraphTimeSlice
from .driver import GraphFilterDriver
