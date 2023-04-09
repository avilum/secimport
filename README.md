# secimport

`secimport` is a cross-platform sandbox toolkit that traces your Python application and enforces privileges per module in your code in runtime. It uses backends like bpftrace (eBPF) and dtrace under the hood.

## Why It's Awesome

- Trace which syscalls are called by each module in your code.
  - `secimport` uses USDT (Userland Statically Defined Tracing) probes in the runtime (Python interpreter for example) using eBPF and dtrace instrumentation scripts.
  - Audit the flow of your application at user-space/os/kernel level
- Reduce supply chain attack and RCE vectors by restricting modules/packages inside your production environment.
- No performance impact (see [Performance](https://github.com/avilum/secimport/wiki/Performance-Benchmarks)).
- Don't change the way you code!
- Supports `Python` at the moment
  -  `Go` is under development


## Installation
For evaluation, we highly recommend the QuickStart with <a href="#Docker">Docker</a> instead of self-installing.<br>
If you are not using Docker, follow <a href="https://github.com/avilum/secimport/wiki/Installation">Installation</a> to install eBPF or DTrace.
- To install secimport from git clone: `python3 -m pip install -e .`
- To install secimport from pypi (latest stable release): `python3 -m pip install secimport`


## Docker
The quickest way to evaluate `secimport` is to use our [Docker container](docker/README.md), which includes `bpftrace` (`ebpf`) and other plug-and-play examples.

## Quick Start - Using the CLI
To run an end-to-end interactive example:
1. Build a docker with custom kernel that matches your existing OS kernel version
    ```
    ➜  secimport ✗ cd docker/
    ➜  docker ✗ ./build.sh
    ```
2. Run the container
    ```
    ➜  docker ✗ ./run.sh
    Running temporary container...

    root@f05d2c33b0b3:/workspace#
    ```
3. Use the CLI
    ```
    root@f05d2c33b0b3:/workspace# secimport interactive

    Let's create our first tailor-made sandbox with secimport!
    - A python shell will be opened
    - The behavior will be recorded.

    OK? (y): y
    >>> secimport trace

    TRACING: ['/workspace/secimport/profiles/trace.bt', '-c', '/workspace/Python-3.10.0/python', '-o', 'trace.log']

                            Press CTRL+D/CTRL+C to stop the trace;

    Python 3.10.0 (default, Apr  9 2023, 17:19:17) [GCC 9.4.0] on linux
    Type "help", "copyright", "credits" or "license" for more information.
    >>> import ...


    ```
## Sandbox Your Program (Using the CLI)
`secimport trace` will start a bpftrace program that will log all the syscalls for all the modules in your application into a file.<br>
Once you covered the logic you would like to or sandbox and you're satisfied, hit `CTRL+C` or `CTRL+D` or wait for the program to finish.
```
$ secimport trace
$ secimport trace -h
$ secimport trace_pid 123
$ secimport trace_pid -h
```

Then, build a sandbox from the trace using the `build` command:
```
# secimport build
$ secimport build -h
```

Finally, run the sandbox with the `run` command:
```
$ secimport run
$ secimport run --entrypoint my_custom_main.py
$ secimport run --entrypoint my_custom_main.py --stop_on_violation=true
$ secimport run --entrypoint my_custom_main.py --kill_on_violation=true
$ secimport run --sandbox_executable /path/to/my_sandbox.bt --pid 2884
$ secimport run --sandbox_executable /path/to/my_sandbox.bt --sandbox_logfile my_log.log
$ secimport run -h
```

For more detailed usage instructions, see the [Command-Line Usage](https://github.com/avilum/secimport/wiki/Command-Line-Usage) page.

## Python API

You can also use `secimport` by replacing `import` with `secimport.secure_import` for selected modules. See the [Python Imports](examples/python_imports/) example for more details.

## Examples

The [Sandbox Examples](https://github.com/avilum/secimport/wiki/Sandbox-Examples) page contains basic and advanced real-world examples.

## Contributing

For information on how to contribute to `secimport`, see the [Contributing](https://github.com/avilum/secimport/blob/master/docs/CONTRIBUTING.md) guide.

## Roadmap

See the [Roadmap](https://github.com/avilum/secimport/blob/master/docs/ROADMAP.md) for the planned features and development milestones.

## Changelog

See the [Changelog](https://github.com/avilum/secimport/blob/master/docs/CHANGELOG.md) for development progress and existing features.
