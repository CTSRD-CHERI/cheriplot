
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

- patch the CheriBSD kernel to solve a bug in trace termination when using the sysctl hw.qemu_trace_perthread, the patched kernel is at https://github.com/qwattash/cheribsd.git (branch user/qwattash).
  The patch will be merged upstream asap.
- use the vmmap_dump utility to dump the memory map of a process (found in the same branch). At some point this will be superseded by dynamically extracting mapping events from the trace.

Run qemu-system-cheri selecting the type of output trace as "cvtrace" using the _-trace_ command line option. The trace file can be selected with the _-D_ option or the
_logfile_ command from the qemu console.

Once the qemu instance is booted the selected process VM map can be dumped to a CSV file with vmmap_dump as:
`vmmap_dump <executable>`
This will create a vm_map_<pid>.csv file with the input for cheriplot tools.

In order to avoid including output from other processes in the trace the sysctl `hw.qemu_trace_perthread` should be set. When this is enabled tracing is paused whenever there is a context switch
to another thread that is not being traced.

To capture a trace the qtrace tool is used. The trace will be saved to the qemu log-file.

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

### Tools description

The following tools are provided in cheriplot:

- **cheriplot-tracedump**
  Inspection tool for binary traces. It can dump and filter trace entries based on various parameters (e.g. $pc or memory ranges, register used...).
- **cheriplot-provenance**
  Main tool for plots that use the pointer provenance graph. Produce address-map, cdf, capability-size and dereference plots.
- **cheriplot-tracecmp**
  Tool that compares binary and text traces to find differences.
- **cheriplot-treedump**
  Inspection tool for the provenance graph. It is similar to cheriplot-tracedump but reads data from the provenance graph instead of the raw trace.
- **cheriplot-backtrace**
  Produces backtraces and call-graphs from cheri binary traces.

## License

This software is released under the BERI HARDWARE-SOFTWARE License. A copy is available at [beri-open-systems]( http://www.beri-open-systems.org/legal/license-1-0.txt)