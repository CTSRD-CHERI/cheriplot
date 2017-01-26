
# CheriPlot


Helper library for parsing and plotting CHERI instruction traces.

## Build


Install the dependencies listed in requirements.txt
```
pip install -r requirements.txt
```

### Additional Requirements

Cheritrace must also be installed, it can be found at [this repository](https://github.com/CTSRD-CHERI/cheritrace.git). If a virtualenv is used, pycheritrace has to be installed manually in the virtualenv by using the cheritrace_build/Python/setup.py script from the virtualenv.

Python graph-tool is needed for the provenance graph, it is not available in pip but it can be installed from most package managers as python-graph-tool

## Documentation

Sphinx documentation for the library can be built using the makefile in the docs directory.

## Quick start

This sections is a walkthrough to start working with the cheriplot tools. The next two sections cover taking qemu traces and using the traces to produce various types of plots.

### Tracing programs

To start producing traces with qemu the following are required:

- qemu-cheri must be compiled with the option -DCHERI_DEFAULT_CVTRACE
- patch the CheriBSD kernel to solve a bug in trace termination when using the sysctl hw.qemu_trace_perthread, the patched kernel is at https://github.com/qwattash/cheribsd.git (branch user/qwattash).
  The patch will be merged upstream asap.
- use the vmmap_dump utility to dump the memory map of a process (found in the same branch). At some point this will be superseded by dynamically extracting mapping events from the trace.

Once the qemu instance is booted the selected process VM map can be dumped to a CSV file with vmmap_dump as:
`vmmap_dump <executable>`
This will create a vm_map_<pid>.csv file with the input for cheriplot tools.

In order to avoid including output from other processes in the trace the sysctl `hw.qemu_trace_perthread` should be set. When this is enabled tracing is paused whenever there is a context switch
to another thread that is not being traced.

To capture a trace the qtrace tool is used. The trace will be saved to the qemu log-file that must be specified, I use the qemu console command `logfile /path/to/cvtrace/file`.

Note that currently only a single trace can be taken for each qemu boot as qemu does not correctly rewrite the cvtrace header if the logfile is changed, this should be fixed.

Below there is a complete example for helloworld.

```
(qemu-console) logfile /my/home/traces/helloworld.cvtrace
root@qemu # sysctl hw.qemu_trace_perthread=1
root@qemu # vmmap_dump helloworld
Hello World!
Pid 596 - extracting vm map to vm_map_000596.csv
root@qemu # qtrace exec helloworld
Hello World!

qwattash@host $ xz helloworld.cvtrace # (optionally compress trace to save space)
```

### Inspecting traces

All tools provided by cheriplot are in the `tools/` subdirectory in the tree.

- pytracedump
  Provides generic inspection of binary traces, can dump registers and apply various filters
- pointer_provenance
  Main tool for pointer provenance plots, currently only the `--asmap` and `--pfreq` plots are supported, others are WIP.
- pointer_oob
  Looks for capability manipulations that generate an out-of-bound offset that would trigger an error if dereferenced.
- pointer_density
  Plots the number of capabilites stored (number of accesses by csc, there may be overcounting if there are a lot of store to the same location) vs the virtual address with page granularity.
- pointer_size_cdf
  CDF plot of the capability size.

Note that most plots support the `-c` switch that enables caching of intermediate data structures such as the provenance graph, so that subsequent calls will not scan again the trace
which is time-consuming task.

## License

This software is released under the BERI HARDWARE-SOFTWARE License. A copy is available at [beri-open-systems]( http://www.beri-open-systems.org/legal/license-1-0.txt)