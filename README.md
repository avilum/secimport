# secimport
[![Upload Python Package](https://github.com/avilum/secimport/actions/workflows/python-publish.yml/badge.svg)](https://github.com/avilum/secimport/actions/workflows/python-publish.yml)


## The Tailor-Made Sandbox for Your Application
`secimport` is production-oriented sandbox toolkit.<br>
It traces your code, and runs an executable that allows only the same syscalls per module.

- 🚀 Trace which syscalls are called by each module in your code.
  - `secimport` uses USDT (Userland Statically Defined Tracing) probes in the runtime using eBPF or dtrace instrumentation scripts.
- 🚀 Control the execution or third-party and open-source packages you can't fully control.
  - Avoid incidents like <a href="https://en.wikipedia.org/wiki/Log4Shell">log4shell</a>.
- 🚀 Prevent code execution, reduce the risk of supply chain attacks.
  - Trace the syscalls flow of your application at user-space/os/kernel and per module.
  - Run your application while enforcing syscalls per module.
  - Upon violation of the policy, it can log, stop or kill the process.
- 🚀 Has negligible performance impact thanks to eBPF [Performance](https://github.com/avilum/secimport/wiki/Performance-Benchmarks).


## Quick Start
Follow these steps to run an interactive example:
1. Build and run the Docker container with a custom kernel that matches your existing OS kernel version:
```
cd docker/ && ./build.sh && ./run.sh
```
A temporary container will be created, and you will be logged in as the root user.
1. Use the CLI to create your first tailor-made sandbox:
```
secimport interactive

Let's create our first tailor-made sandbox with secimport!
- A python shell will be opened
- The behavior will be recorded.

...
```

To sandbox your program using the CLI, start a bpftrace program that logs all the syscalls for all the modules in your application into a file with the secimport trace command. Once you have covered the logic you would like to sandbox, hit CTRL+C or CTRL+D, or wait for the program to finish. Then, build a sandbox from the trace using the secimport build command, and run the sandbox with the secimport run command.

For more detailed usage instructions, see the [Command-Line Usage](https://github.com/avilum/secimport/wiki/Command-Line-Usage) page.

## Python API

You can also use `secimport` by replacing `import` with `secimport.secure_import` for selected modules. See the [Python Imports](examples/python_imports/) example for more details.


## Installation
Tested on Mac and Linux x86.<b>
For evaluation, we highly recommend using our <a href="#Docker">Docker</a> image instead of self-installing.<br>
If you are not using Docker, follow <a href="https://github.com/avilum/secimport/wiki/Installation">Installation</a> to install eBPF or DTrace.
- To install secimport from git clone, install `poetry` and run `poetry install`
- To install secimport from pypi (latest stable release): `python3 -m pip install secimport`


## Docker
The quickest way to evaluate `secimport` is to use our [Docker container](docker/README.md), which includes `bpftrace` (`ebpf`) and other plug-and-play examples.


## Examples

The [Sandbox Examples](https://github.com/avilum/secimport/wiki/Sandbox-Examples) page contains basic and advanced real-world examples.

## Contributing

For information on how to contribute to `secimport`, see the [Contributing](https://github.com/avilum/secimport/blob/master/docs/CONTRIBUTING.md) guide.

## Roadmap

See the [Roadmap](https://github.com/avilum/secimport/blob/master/docs/ROADMAP.md) for the planned features and development milestones.

## Changelog

See the [Changelog](https://github.com/avilum/secimport/blob/master/docs/CHANGELOG.md) for development progress and existing features.
