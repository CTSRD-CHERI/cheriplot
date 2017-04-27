
Tracing Howto Notes
*******************

Tracing in qemu
---
The CTSRD fork of qemu implements two trace formats (link formats specs when they are ready).
Tracing can be controlled in various ways: from qemu-system-cheri CLI options, from the qemu console and programmatically from
within the traced program.

Notable qemu-system-cheri options:

* *-d* starts tracing as qemu begins execution (use *-d instr* to start instruction tracing).
* *-D* specify the output file.
* *-cheri-trace-format* sets the output trace format (text or cvtrace).

Notable qemu console commands:

* *logfile* speficy the output file.
* *trace* start tracing (use *trace instr* to start instruction tracing).

The CHERI qemu also provides a way to start and stop tracing with special noop instructions, these can be inlined in the program
to have more control over when tracing starts or stops. The following noops are currently defined:

* ``li $zero, 0xbeef`` turns on instruction trace logging.
* ``li $zero, 0xdead`` turns off instruction trace logging.
* ``li $zero, 0xdeaf`` turns on userspace-only instruction trace logging.
* ``li $zero, 0xfaed`` turns off userspace-only instruction trace logging.
* ``li $zero, 0xface`` logs a debug message to the trace (multiple noops are used to hold longer messages)

CheriBSD also provides a few facilities to help generating useful instruction traces. It is possible to instruct the kernel
to turn off tracing when a context switch occurs, so that the trace will only contain userspace and kernel instructions executed in
the traced thread.

Notable sysctl:

* hw.qemu_trace_perthread (bool) The kernel will pause instruction tracing when a thread that is not traced is scheduled.

(TODO) add knobs to change allocators behaviour.

Notable tracing utilitis in CheriBSD:

* *qtrace* trace a program from fork/execve to exit.
* *procstat* can be used to dump the virtual memory mappings of a process (``-v``)
* *vmmap_dump* utility that runs a program and dumps the memory mappings when ``exit()`` is called. (In qwattash/cheribsd fork.)

Example:

.. code-block:: bash

		# in the qemu-console
		(qemu-console) logfile /my/home/traces/helloworld.cvtrace
		# in the qemu cheri guest
		$ sysctl hw.qemu_trace_perthread=1
		$ vmmap_dump helloworld
		Hello World!
		Pid 596 - extracting vm map to vm_map_000596.csv
		$  qtrace exec helloworld
		Hello World!
		# (optionally compress trace to save space)
		$ xz helloworld.cvtraceconsole
