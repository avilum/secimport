<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Try secimport with bpftrace](#try-secimport-with-bpftrace)
  - [How to Use](#how-to-use)
  - [FAQ](#faq)
    - [How it runs on macOS?](#how-it-runs-on-macos)
    - [Can we trace a macOS host with this docker?](#can-we-trace-a-macos-host-with-this-docker)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Try secimport with bpftrace

## How to Use

1. Install Docker: https://docs.docker.com/get-docker
2. `./build.sh`
    - will build a docker image with
        - python with dtrace static USDT instrumentations
        - bpftrace
        - secimport code
    - ~1GB in size
3. `./run.sh` will start a new docker container with secimport.
    - `secimport interactive`
        -  `secimport shell` or `secimport trace` will run a new process (python interpreter or specific entrypoint). It it will <b>record all functions and syscalls inside the newly created process</b>.
        - All syscalls and modules will be logged to ./trace.log once you hit CTRL+D or CTRL+C.
    - You can use `-v` in docker run to mount your code into the container and trace it.

```python
root@d57458518cbf:/workspace$ ./run_sandbox.sh
🚀 Starting secimport sandbox with bpftrace backend, the sandbox should kill the python process...
WARNING: Addrspace is not set
  PID TTY          TIME CMD
    1 pts/0    00:00:00 sh
   10 pts/0    00:00:00 bash
   18 pts/0    00:00:00 bash
   19 pts/0    00:00:00 bpftrace
   23 pts/0    00:00:00 python
   24 pts/0    00:00:00 sh
   25 pts/0    00:00:00 sh
   26 pts/0    00:00:00 pkill
   27 pts/0    00:00:00 ps


🛑 The process was killed, as expected.
🚀 The sandbox bpftrace code is at sandbox.bt
🚀 The sandbox log is at sandbox.log.
```

## FAQ

### How it runs on macOS?
- The Docker for mac runs Linux on a hypervisor called hyperkit, and docker runs inside it, so you can use Linux features.

### Can we trace a macOS host with this docker?
- Not at the moment. The bpftrace runs inside a Linux VM.
- For macOS, there is dtrace.

=====================

Based on the great example repo: https://github.com/mmisono/try-bpftrace-in-mac
