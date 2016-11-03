
CheriPlot
=========

Helper library for parsing and plotting CHERI instruction traces.

Build
-----

Install the dependencies listed in requirements.txt
```
pip install -r requirements.txt
```

Cheritrace must also be installed, it can be found at [this repository](https://github.com/CTSRD-CHERI/cheritrace.git). If a virtualenv is used, pycheritrace has to be installed manually in the virtualenv by using the cheritrace_build/Python/setup.py script from the virtualenv.

Documentation
-------------
Sphinx documentation for the library can be built using the makefile in the docs directory.

License
-------
This software is released under the BERI HARDWARE-SOFTWARE License. A copy is available at [beri-open-systems]( http://www.beri-open-systems.org/legal/license-1-0.txt)