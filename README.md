<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [secimport](#secimport)
  - [Why It's Awesome](#why-its-awesome)
  - [Examples](#examples)
  - [Quick Start - Using the CLI](#quick-start---using-the-cli)
  - [Alternative Usage: Python Imports](#alternative-usage-python-imports)
  - [Docker](#docker)
  - [Installation](#installation)
  - [Documentation](#documentation)
  - [References](#references)
- [Contributing](#contributing)
    - [Roadmap](#roadmap)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# secimport
`secimport` is a sandbox toolkit that traces your application and enforces privileges per module in your code in runtime.<br>
It uses backends like bpftrace (eBPF) and dtrace under the hood, making it cross-platform.

[Medium Article](https://infosecwriteups.com/sandboxing-python-modules-in-your-code-1e590d71fc26?source=friends_link&sk=5e9a2fa4d4921af0ec94f175f7ee49f9)

## Why It's Awesome
- Trace which syscalls are called by each module in your code.
  - Like seccomp, apparmor, firejail, etc.
  - Audit the flow of your python application at user-space/os/kernel level.
- Reduce supply chain attack and RCE vectors.
  - Restrict modules/packages inside your production environment
  - It is hard to keep 3rd party and open source up-to-date.
  - Vulnerabilities are inevitable.
- No performance impact (see  <a href="https://github.com/avilum/secimport/wiki/Performance-Benchmarks">Performance</a>)
- Don't change the way you code!

## Examples
<a href="https://github.com/avilum/secimport/wiki/Sandbox-Examples">Sandbox Examples</a> contains basic and advanced usage with many interactive examples.

## Quick Start - Using the <a href="https://github.com/avilum/secimport/wiki/Command-Line-Usage">CLI</a><br>
  - `secimport` or `python -m secimport.cli --help`
Let's trace some logic we would like to trace.
```shell
root@e28bf0ec63d4:/workspace# secimport trace
 >>> secimport trace

TRACING: ['/workspace/secimport/profiles/trace.bt', '-c', '/workspace/Python-3.10.0/python', '-o', 'trace.log']

                        Press CTRL+D to stop the trace;

Python 3.10.0 (default, Mar 19 2023, 08:34:46) [GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> os.cpu_count()

CTRL+D
 TRACING DONE;
```
Create a sandbox from the trace, it should allow only running os.num_cpus() and no syscalls;
```shell
root@e28bf0ec63d4:/workspace# secimport build
 >>> secimport build

SECIMPORT COMPILING...

CREATED JSON TEMPLATE:  sandbox.json
CREATED YAML TEMPLATE:  sandbox.yaml


compiling template sandbox.yaml
...
[debug] adding syscall openat to allowlist for module /workspace/Python-3.10.0/Lib/ast.py
[debug] adding syscall close to allowlist for module /workspace/Python-3.10.0/Lib/codecs.py
...

 SANDBOX READY: sandbox.bt
```
Try to violate the behavior by running os.system, we expect it to be logged / kill the process:
```shell
root@e28bf0ec63d4:/workspace# secimport run
 >>> secimport run
 RUNNING SANDBOX... ['./sandbox.bt', '--unsafe', ' -c ', '/workspace/Python-3.10.0/python']
Attaching 5 probes...
REGISTERING SYSCALLS...
STARTED
Python 3.10.0 (default, Mar 19 2023, 08:34:46) [GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> os.cpu_count()
6
>>> os.system('echo pwned')
[SECIMPORT VIOLATION]: <stdin> called syscall clone at depth 1
[SECIMPORT VIOLATION]: <stdin> called syscall execve at depth 1
[SECIMPORT VIOLATION]: <stdin> called syscall wait4 at depth 1
pwned
0
```

## Alternative Usage: <a href="examples/python_imports/">Python Imports</a>
  - Works by replacing `import` with `secimort.secure_import` for selected modules.

## Docker
The quickest method to evaluate secimport is using our [Docker for MacOS and Linux](docker/README.md). The container includes `bpftrace`, python and secimport.<br> `dtrace` can be used in Mac OS, Windows, Solaris, Unix, some Linux distributions.<br>

```python
root@d57458518cbf:/workspace$ ./run_sandbox.sh
🚀 Starting secimport sandbox with bpftrace backend, the sandbox should kill the python process...

  PID TTY          TIME CMD
    1 pts/0    00:00:00 sh
   18 pts/0    00:00:00 bash
   19 pts/0    00:00:00 bpftrace
   23 pts/0    00:00:00 python


🛑 The process was killed, as expected.
🚀 The sandbox bpftrace code is at sandbox.bt
🚀 The sandbox log is at sandbox.log.
```
## Installation
For evaluation, we highly recommend the QuickStart with <a href="#Docker">Docker</a> instead of self-installing.

```shell
# To install secimport from git clone:
python3 -m pip install -e .

# To install secimport from pypi (latest stable release):
python3 -m pip install secimport
```

This does not install the backends that secimport needs in order to run, but only the python package.
To install one of the backends yourself (eBPF or DTrace), please see <a href="https://github.com/avilum/secimport/wiki/Installation">Installation</a>.

## Documentation
[Our documentation center is Wiki on GitHub](https://github.com/avilum/secimport/wiki)

## References
- Read more about the primitives of secimport:
  - `bpftrace` - https://github.com/iovisor/bpftrace
  - `dtrace` - [DTrace Cheatsheet](https://www.brendangregg.com/DTrace/DTrace-cheatsheet.pdf)
    - [DTrace for Linux (2018)](https://www.brendangregg.com/blog/2018-10-08/dtrace-for-linux-2018.html)
- <a href="https://github.com/avilum/secimport/wiki/Sandbox-Examples">Sandbox Examples</a>
- Guides
  - <a href="https://github.com/avilum/secimport/wiki/Tracing-Processes">Tracing Processes Guide</a>
  - <a href="https://github.com/avilum/secimport/wiki/Installation">Installation</a>
  - <a href="https://github.com/avilum/secimport/wiki/YAML-Profiles">Create a Sandbox from YAML file</a>
  - <a href="https://github.com/avilum/secimport/wiki/MacOS-Users">Mac OS Users</a>
  - <a href="https://github.com/avilum/secimport/wiki/F.A.Q">F.A.Q</a>

# Contributing
1. Fork this repo ^
2. Install `poetry`, `pre-commit`, `doctoc` (Run `python3 -m pip install poetry pre-commit doctoc`)
3. Run `poetry install`
4. Add your feature/bugfixes/changes (see [Roadmap](#roadmap) if your are looking for Ideas)
5. Run ./scripts/lint to correct the code styling and lint using pre-commit hooks
6. Create a pull request with a desriptive title :)

### Roadmap
- <b>Extandible Language Template</b>
  - Create a miminal template that will support instrumenting different artifacts for different languages easily.
    - <b>JS support</b> (bpftrace/dtrace hooks)
      - Implement a template for JS event loop (V8 or alt.)
    - <b>Go support</b>
      - Implement a template for golang's call stack
    - <b>Node support</b>
      - Implement a template for Node's call stack and event loop

Changelog:
- ✔️ Added Allow/Block list configuration
- ✔️ Created a .yaml configuration per module in the code
  - ✔️ Use secimport to compile that yml
  - ✔️ Create a single dcript policy
  - ✔️ Run an application with that policy using dtrace, without using `secure_import`
- ✔️ Added eBPF basic support using bpftrace
  - ✔️ bpftrace backend tests
- ✔️ Implemented python USDT probes template
- ✔️ Added CLI for bpftrace backend usage
- ✔️ Updated documentation and improved CLI
- ✔️ Added GIFs
