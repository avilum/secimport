<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Tracing processes for syscalls](#tracing-processes-for-syscalls)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Tracing processes for syscalls
There are several methods to create a secimport profile for your modules.
  - Using a YAML build
    - See <a href="YAML_PROFILES.md">YAML Profiles Usage</a>
  - Using `secure_import` from python:
    - `secimport.secure_import(..., log_syscalls=True, destructive=False)`
    - The log output will contain all the syscalls made by your process.
    - Create a secure import based on that log
  - Using our dscript to generate a profile:
    -  `sudo dtrace -s secimport/templates/default.allowlist.template.d -c "python -m http.server"`
    - CTRL+C
    - Create a secure import based on that log.
  - Using `bpftrace`
    - See https://github.com/iovisor/bpftrace/tree/master/tools
  - Using `dtrace`
    - Tracing the syscalls of a process with pid `12345`
      - `dtrace -n 'syscall::: /pid == ($1)/ {@[pid,execname,probefunc]=count()}' 12345`
    - Tracing the syscalls of a docker container with pid `12345`
      - `dtrace -n 'syscall::: /progenyof($1)/ {@[pid,execname,probefunc]=count()}' 12345`
  - Using an `strace` script I contributed to FireJail
    -  A script to list all your application's syscalls using `strace`.<br> I contributed it to `firejail` a few years ago:
      - https://github.com/netblue30/firejail/blob/master/contrib/syscalls.sh
      - ```
        wget "https://raw.githubusercontent.com/netblue30/firejail/c5d426b245b24d5bd432893f74baec04cb8b59ed/contrib/syscalls.sh" -O syscalls.sh

        chmod +x syscalls.sh

        ./syscalls.sh examples/http_request.py
        ```
