cheriplot.core
**************

The core module contains the implementation of the base parser and matplotlib projections used by the plots.

AddressSpaceAxes
----------------

.. automodule:: cheriplot.core.plot
   :members:
   :undoc-members:
   :show-inheritance:


Parser
------

The parser module provides two classes that use pycheritrace to scan CHERI binary instruction traces.
:class:`cheriplot.core.parser.TraceParser` is the base class that only handles the opening of the trace file,
the "scan()" method of the trace object must be called manually.

The class :class:`cheriplot.core.parser.CallbackTraceParser` handles instruction filtering and parsing based on
callback methods defined by subclasses. Callback methods must have the form "scan_<opcode>" or "scan_<instr_class>", these will be called every time an instruction with the given opcode or in one of the valid instruction classes is found.

.. automodule:: cheriplot.core.parser
   :members:
   :undoc-members:
   :show-inheritance:

Tool
----

.. automodule:: cheriplot.core.driver
   :members:
   :undoc-members:
   :show-inheritance:

.. automodule:: cheriplot.core.tool
   :members:
   :undoc-members:
   :show-inheritance:
