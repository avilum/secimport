# secimport
[![Upload Python Package](https://github.com/avilum/secimport/actions/workflows/python-publish.yml/badge.svg)](https://github.com/avilum/secimport/actions/workflows/python-publish.yml)


## The Tailor-Made Sandbox for Your Application
`secimport` is production-oriented sandbox toolkit.<br>
It traces your code, and runs an executable that allows only the same syscalls per module.

- 🚀 Trace which syscalls are called by each module in your code.
  - secimport uses USDT (Userland Statically Defined Tracing) probes in the runtime using eBPF or dtrace instrumentation scripts.
- 🚀 Control the execution or third-party and open-source packages you can't fully control.
  - Avoid incidents like <a href="https://en.wikipedia.org/wiki/Log4Shell">log4shell</a>.
- 🚀 Prevent code execution, reduce the risk of supply chain attacks.
  - Trace the syscalls flow of your application at the user-space/os/kernel level and per module.
  - Run your application while enforcing syscalls per module.
  - Upon violation of the policy, it can log, stop, or kill the process.
- 🚀 Has negligible performance impact and is production-ready thanks to eBPF. Check out the [Performance](https://github.com/avilum/secimport/wiki/Performance-Benchmarks) benchmarks.

secimport is a production-oriented sandbox toolkit that traces your code and runs an executable that allows only the same syscalls per module.

🚀 Trace which syscalls are called by each module in your code.
secimport uses USDT (Userland Statically Defined Tracing) probes in the runtime using eBPF or dtrace instrumentation scripts.
🚀 Control the execution of third-party and open-source packages you can't fully control.
Avoid incidents like log4shell.
🚀 Prevent code execution, reduce the risk of supply chain attacks.
Trace the syscalls flow of your application at the user-space/os/kernel level and per module.
Run your application while enforcing syscalls per module.
Upon violation of the policy, it can log, stop, or kill the process.
🚀 Has negligible performance impact and is production-ready thanks to eBPF. Check out the Performance Benchmarks.

## Installation
Tested on Ubuntu, Debian, Rocky (Linux x86/AMD/ARM) and MacOS in (x86/M1).<br>

### With Docker
For quicker evaluation, we recommend using the <a href="#Docker">Docker</a> image instead of self-installing.<br>
- Build and run the Docker container with a custom kernel that matches your existing OS kernel version:
  ```
  cd docker/ && ./build.sh && ./run.sh
  ```
  A temporary container will be created, and you will be logged in as the root user.

### Without Docker
1. Install python with USDT probes by <a href="https://github.com/avilum/secimport/wiki/Installation#python-interpreter-requirements">configuring it with '--dtrace'</a>
2. Install one of the backends: <a href="https://github.com/avilum/secimport/wiki/Installation">eBPF or DTrace</a>.
3. Install secimport
  - Install from pypi
    - ```
      python3 -m pip install secimport
      ```
  - Install from source
    - ```
      git clone https://github.com/avilum/secimport.git && cd secimport
      python3 -m pip install poetry && python3 -m poetry install
      ```


## Usage
To sandbox your program using the CLI, start a bpftrace program that logs all the syscalls for all the modules in your application into a file with the secimport trace command. Once you have covered the logic you would like to sandbox, hit CTRL+C or CTRL+D, or wait for the program to finish. Then, build a sandbox from the trace using the secimport build command, and run the sandbox with the secimport run command.

```shell
NAME
    SecImport - A toolkit for Tracing and Securing Python Runtime using USDT probes and eBPF/DTrace

SYNOPSIS
    cli.py COMMAND

DESCRIPTION
    QUICK START:
            >>> secimport interactive

    EXAMPLES:
        1. trace:
            $  secimport trace
            $  secimport trace -h
            $  secimport trace_pid 123
            $  secimport trace_pid -h
        2. build:
            $ secimport build
            $ secimport build -h
        3. run:
            $  secimport run
            $  secimport run --entrypoint my_custom_main.py
            $  secimport run --entrypoint my_custom_main.py --stop_on_violation=true
            $  secimport run --entrypoint my_custom_main.py --kill_on_violation=true
            $  secimport run --sandbox_executable /path/to/my_sandbox.bt --pid 2884
            $  secimport run --sandbox_executable /path/to/my_sandbox.bt --sandbox_logfile my_log.log
            $  secimport run -h

COMMANDS
    COMMAND is one of the following:

     build

     interactive

     run
       Run a python process inside the sandbox.

     trace
       Traces

     trace_pid
       Traces a running process by pid. It might require sudo privilleges on some hosts.

```

## Stop on violation 
```
root@1bc0531d91d0:/workspace# secimport run  --stop_on_violation=true
 >>> secimport run
[WARNING]: This sandbox will send SIGSTOP to the program upon violation.
 RUNNING SANDBOX... ['./sandbox.bt', '--unsafe', ' -c ', '/workspace/Python-3.10.0/python', 'STOP']
Attaching 4 probes...
Python 3.10.0 (default, Apr 28 2023, 11:32:40) [GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> os.system('ps')
[SECURITY PROFILE VIOLATED]: <stdin> called syscall 56 at depth 8022

^^^ STOPPING PROCESS 85918 DUE TO SYSCALL VIOLATION ^^^
		PROCESS 85918 STOPPED.
```

## Kill on violation
```
root@ee4bc99bb011:/workspace# secimport run --kill_on_violation
 >>> secimport run
[WARNING]: This sandbox will send SIGKILL to the program upon violation.
 RUNNING SANDBOX... ['./sandbox.bt', '--unsafe', ' -c ', '/workspace/Python-3.10.0/python', 'KILL']
import os
oAttaching 4 probes...
sPython 3.10.0 (default, Apr 28 2023, 11:32:40) [GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> os.system('ps')
[SECURITY PROFILE VIOLATED]: <stdin> called syscall 56 at depth 8022

^^^ KILLING PROCESS 86466 DUE TO SYSCALL VIOLATION ^^^
		KILLED.
 SANDBOX EXITED;
```

## Dynamic profiling - trace, build sandbox, run.
```shell
root@1fa3d6f09989:/workspace# secimport interactive

Let's create our first tailor-made sandbox with secimport!
- A python shell will be opened
- The behavior will be recorded.

OK? (y): y
 >>> secimport trace

TRACING: ['/workspace/secimport/profiles/trace.bt', '-c', '/workspace/Python-3.10.0/python', '-o', 'trace.log']

                        Press CTRL+D to stop the trace;

Python 3.10.0 (default, Mar 19 2023, 08:34:46) [GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import this
>>>
 TRACING DONE;
 >>> secimport build

SECIMPORT COMPILING...

CREATED JSON TEMPLATE:  traced_modules.json
CREATED YAML TEMPLATE:  traced_modules.yaml


compiling template traced_modules.yaml

DTRACE SANDBOX:  traced_modules.d
BPFTRCE SANDBOX:  sandbox.bt
```

Now, let's run the sandbox.
```python
- Run the same commands as before, they should run without any problem;.
- Do something new in the shell; e.g:   >>> __import__("os").system("ps")

        OK? (y): y
 >>> secimport run
 RUNNING SANDBOX... ['./sandbox.bt', '--unsafe', ' -c ', '/workspace/Python-3.10.0/python']
Attaching 5 probes...
REGISTERING SYSCALLS...
STARTED
Python 3.10.0 (default, Mar 19 2023, 08:34:46) [GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import this
>>> import os
[SECIMPORT VIOLATION]: <stdin> called syscall ioctl at depth 0
[SECIMPORT VIOLATION]: <stdin> called syscall ioctl at depth 0
```

For more detailed usage instructions, see the [Command-Line Usage](https://github.com/avilum/secimport/wiki/Command-Line-Usage) page.

## Python API

You can also use `secimport` by replacing `import` with `secimport.secure_import` for selected modules. See the [Python Imports](examples/python_imports/) example for more details.

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
