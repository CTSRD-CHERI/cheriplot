
# CheriPlot


Helper library for parsing and plotting CHERI instruction traces.

## Documentation

Sphinx documentation for the library can be built using the makefile in the docs directory.

## Quick start

### Build

Install the dependencies listed in requirements.txt
```
pip install -r requirements.txt
```

### Additional Requirements

Cheritrace must also be installed, it can be found at [this repository](https://github.com/CTSRD-CHERI/cheritrace.git).
If a virtualenv is used, pycheritrace has to be installed manually in the virtualenv by using the cheritrace_build/Python/setup.py script from the virtualenv.

Python [graph-tool](https://graph-tool.skewed.de) is needed for the provenance graph,
it is not available in pip but it can be installed from most package managers as python-graph-tool.

The [cheribuild](https://github.com/CTSRD-CHERI/cheribuild) tool, used to build most CHERI-related artifacts.

### Building Graph Tool for FreeBSD
The [graph-tool](https://git.skewed.de/count0/graph-tool/-/wikis/installation-instructions#manual-compilation) lists the dependencies and
steps requred in general.
Building of FreeBSD 12 is known to work with the following packages (where XX is the python version, e.g. 37 for python3.7):
- boost-all
- cgal
- sparsehash
- cairomm
- pyXX-cairo
- pyXX-numpy

The configuration step requires extra options to find the libraries:
```shell
export CC=clang
export CXX=clang++
export LDFLAGS=-L/usr/local/lib
./configure --prefix=cheri/sdk --with-boost-libdir=/usr/local/lib --with-boost-iostreams=boost_iostreams --with-boost-python=boost_python37
```

Note: building with LLVM is not strictly required, but there have been issues in configuring CGAL when using g++.

### Manually tracing programs

1. Build qemu
```shell
% cheribuild.py qemu
```

2. Build cheribsd
```shell
% cheribuild.py cheribsd-purecap
% cheribuild.py disk-image-purecap
```

3. Boot cheribsd on qemu, configure qemu to generate a binary trace in $WORKDIR/trace.cvtrace
```shell
% cheribuild.py run-purecap --run-purecap/extra-options "\-D $WORKDIR/trace.cvtrace -cheri-trace-format cvtrace"
```

4. (optional) Enable per-thread tracing, this will pause tracing when the traced thread is preempted, avoiding to capture instructions from other threads.
```shell
% sysctl hw.qemu_trace_perthread=1
```

5. Run program to trace. `qtrace` can also be used to start and stop tracing manually from the command line.
```shell
% qtrace exec my-test-program
```

6. Process trace and build the provenance/call graphs.
```shell
% cheriplot-provenance --outfile trace_graph.gt --display-name "My Test Trace" --cheri-cap-size 128 trace_file.cvtrace
```

6. Example processing: dump all the capabilities with length less than 8 bytes and show the capabilities they are children of.
```shell
% cheriplot-treedump --layer prov --size 0-8 --predecessors trace_graph.gt
```

**Extracting the memory map of a process**
This is useful to detect the mapped memory regions and resolve symbol addresses in shared libraries.

a. Use `procstat` on a running process.
```shell
% procstat -v $PID
```

b. Use vmmap_dump tool. Currently not in mainline cheribsd, see [fork](https://github.com/qwattash/cheribsd.git#user/qwattash) in `usr.bin/vmmap\_dump`.
This will run the program under test and stop at the exit system call to extract the VM map to a csv file.
```shell
% vmmap\_dump my-test-program
```

### Automatically tracing programs
XXX TODO

### Tools description

The following tools are provided in cheriplot:

- **cheriplot-tracedump**
  Inspection tool for binary traces. It can dump and filter trace entries based on various parameters (e.g. $pc or memory ranges, register used...).
- **cheriplot-provenance**
  Main tool for plots that use the pointer provenance graph. Produce address-map, cdf, capability-size and dereference plots.
- **cheriplot-treedump**
  Inspection tool for the provenance graph. It is similar to cheriplot-tracedump but reads data from the provenance graph instead of the raw trace.

## License

This software is released under the BERI HARDWARE-SOFTWARE License. A copy is available at [beri-open-systems]( http://www.beri-open-systems.org/legal/license-1-0.txt)
