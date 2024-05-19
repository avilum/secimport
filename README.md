# secimport
[![Upload Python Package](https://github.com/avilum/secimport/actions/workflows/python-publish.yml/badge.svg)](https://github.com/avilum/secimport/actions/workflows/python-publish.yml)
![](https://img.shields.io/badge/Test_Coverage-90%-blue)

A Tailor-Made Sandbox for Your Python Applications.<br>
secimport is eBPF-based sandbox toolkit for Python, that enforces specific syscalls per module in yoyr code.<br>
1. It traces your python code
2. It creates a security profile for your application<br>
3. Use the profile by applying it to running processes, or to run a new python process with supervision.

<b>secimport for python is like seccomp-bpf for linux but per module in your code.</b>

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Background](#background)
  - [Technical Blogs](#technical-blogs)
  - [The problem](#the-problem)
  - [How it works](#how-it-works)
  - [Who is it for?](#who-is-it-for)
- [Getting Started](#getting-started)
  - [Example Sandboxes](#example-sandboxes)
  - [Using Docker](#using-docker)
  - [Without Docker](#without-docker)
- [Command Line Usage](#command-line-usage)
    - [Stop on violation](#stop-on-violation)
    - [Kill on violation](#kill-on-violation)
- [Quickstart: trace, build, run.](#quickstart-trace-build-run)
- [Advanced](#advanced)
  - [Python API](#python-api)
  - [seccomp-bpf support using nsjail](#seccomp-bpf-support-using-nsjail)
  - [Changelog](#changelog)
  - [Contributing](#contributing)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Background
## Technical Blogs
- <a href="https://infosecwriteups.com/sandboxing-python-modules-in-your-code-1e590d71fc26?source=friends_link&sk=5e9a2fa4d4921af0ec94f175f7ee49f9">secimport + Dtrace</a>
- <a href="https://infosecwriteups.com/securing-pytorch-models-with-ebpf-7f75732b842d?source=friends_link&sk=14d8db403aaf66724a8a69b4dea24e12">secimprt + eBPF + PyTorch</a>
- <a href="https://avi-lumelsky.medium.com/secure-fastapi-with-ebpf-724d4aef8d9e?source=friends_link&sk=b01a6b97ef09003b53cd52c479017b03">secimport + eBPF + FastAPI </a>

## The problem 
Traditional tools like seccomp or AppArmor enforce syscalls for the entire process.<br>Something like `allowed_syscalls=["read","openat","bind","write"]`, which is great, but not enough for python's attack surface.<br>

## How it works
1. `secimport` is able to trace which syscalls each module in your code uses (by package name).<br>
2. After tracing, secimport creates a JSON/YAML policy for your code. It compiles it into a high-performance eBPF instrumentation script (smaller then 512 bytes overall), that looks like <a>this</a>.
    ```
    modules:
      requests:
        destructive: true     # when true, secimport will kill on vilation instead of logging.
        syscall_allowlist:
          - fchmod
          - getentropy
          - getpgrp
          - getrlimit
    ...
    ```
    You can also use JSON instaead of YAML, and even confine builtin python modules.<br>
3. Finally, you convert this policy into an sandbox (eBPF instrumentation script) to run the python process in production. Running the sandbox will enfore python to obey any given policy.

## Who is it for?
`secimport` is great for...
- Preventing Code Execution: reduce the risk of supply chain attacks.
  - Trace the syscalls flow of your application at the user-space/os/kernel level and per module.
  - Run your application while enforcing syscalls per module.
    - Upon violation of the policy, it can log, stop, or kill the process.
- Protect yourself from RCE:
  - secimport makes 1day attacks less of an issue, because it prevents the code form running. If you are using a vulnerable package and someone exploited it, your policy will not allow this exploit's syscalls and it will be handled as you wish.
  - Avoid incidents like <a href="https://en.wikipedia.org/wiki/Log4Shell">log4shell</a>. A logging library requires very few syscalls, and it should never run command using fork, execve or spawn.
    - The syscalls that "fastapi", "numpy" or "requests" use are very different.
- Load AI Models from Insecure Sources
  - Models from unsafe source (huggingface, torch hub, and pytorch pickled models) can be limited to run only a set of syscalls. RCE like 'import os;os.system(...)' somewhere deep in the code will be catched by secimport.
- Minimal Performance Impact
  -  Has negligible performance impact and is production-ready thanks to eBPF. Check out the [Performance](https://github.com/avilum/secimport/wiki/Performance-Benchmarks) benchmarks.
- Trace which syscalls are called by each module in your code.
  - secimport uses USDT (Userland Statically Defined Tracing) together with kernel probes in the runtime using eBPF or dtrace instrumentation scripts.


# Getting Started
## Example Sandboxes

The [Sandbox Examples](https://github.com/avilum/secimport/wiki/Sandbox-Examples) page contains basic and advanced real-world examples.
## Using Docker
The quickest way to evaluate `secimport` is to use our [Docker container](docker/README.md), which includes `bpftrace` (`ebpf`) and other plug-and-play examples.
For quicker evaluation, we recommend using the <a href="https://github.com/avilum/secimport/tree/master/docker">Secimport Docker Image</a> instead of self-installing.<br>
- Build and run the Docker container with a custom kernel that matches your existing OS kernel version:
  ```
  cd docker/ && ./build.sh && ./run.sh
  ```
  A temporary container will be created, and you will be logged in as the root user.

## Without Docker
Tested on Ubuntu, Debian, Rocky (Linux x86/AMD/ARM) and MacOS in (x86/M1). If you run on MacOS you will need to <a href="https://github.com/avilum/secimport/blob/master/docs/MAC_OS_USERS.md">disable SIP for dtrace. </a>

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


# Command Line Usage
To sandbox your program using the CLI, start a bpftrace program that logs all the syscalls for all the modules in your application into a file with the secimport trace command. Once you have covered the logic you would like to sandbox, hit CTRL+C or CTRL+D, or wait for the program to finish. Then, build a sandbox from the trace using the secimport build command, and run the sandbox with the secimport run command.

```shell
NAME
    secimport - is a comprehensive toolkit designed to enable the tracing, construction, and execution of secure Python runtimes. It leverages USDT probes and eBPF/DTrace technologies to enhance the overall security measures.

SYNOPSIS
    secimport COMMAND

DESCRIPTION
    https://github.com/avilum/secimport/wiki/Command-Line-Usage

    WORKFLOW:
            1. secimport trace / secimport shell
            2. secimport build
            3. secimport run

    QUICKSTART:
            $ secimport interactive

    EXAMPLES:
        1. trace:
            $  secimport trace
            $  secimport trace -h
            $  secimport trace_pid 123
            $  secimport trace_pid -h
        2. build:
            # secimport build
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
       Compiles a trace log (trace.log). Creates the sandbox executable (instrumentation script) for each supported backend It uses `create_profile_from_trace ...` and `sandbox_from_profile`.

     compile_sandbox_from_profile
       Generates a tailor-made sandbox that will enforce a given yaml profile/policy in runtime.

     interactive

     run
       Run a python process inside the sandbox.

     shell
       Alternative syntax for secimport "trace".

     trace
       Traces a python process using an entrypoint or interactive interpreter. It might require sudo privilleges on some hosts.

     trace_pid
       Traces a running process by pid. It might require sudo privilleges on some hosts.
```

### Stop on violation
```
root@1bc0531d91d0:/workspace# secimport run  --stop_on_violation=true
 >>> secimport run
[WARNING]: This sandbox will send SIGSTOP to the program upon violation.
 RUNNING SANDBOX... ['./sandbox.bt', '--unsafe', ' -c ', '/workspace/Python-3.11.8/python', 'STOP']
Attaching 4 probes...
Python 3.11.8 (default, Apr 28 2023, 11:32:40) [GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> os.system('ps')
[SECURITY PROFILE VIOLATED]: <stdin> called syscall 56 at depth 8022

^^^ STOPPING PROCESS 85918 DUE TO SYSCALL VIOLATION ^^^
		PROCESS 85918 STOPPED.
```

### Kill on violation
```
root@ee4bc99bb011:/workspace# secimport run --kill_on_violation
 >>> secimport run
[WARNING]: This sandbox will send SIGKILL to the program upon violation.
 RUNNING SANDBOX... ['./sandbox.bt', '--unsafe', ' -c ', '/workspace/Python-3.11.8/python', 'KILL']
import os
oAttaching 4 probes...
sPython 3.11.8 (default, Apr 28 2023, 11:32:40) [GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> os.system('ps')
[SECURITY PROFILE VIOLATED]: <stdin> called syscall 56 at depth 8022

^^^ KILLING PROCESS 86466 DUE TO SYSCALL VIOLATION ^^^
		KILLED.
 SANDBOX EXITED;
```

# Quickstart: trace, build, run.
```shell
root@1fa3d6f09989:/workspace# secimport interactive

Let's create our first tailor-made sandbox with secimport!
- A python shell will be opened
- The behavior will be recorded.

OK? (y): y
 >>> secimport trace

TRACING: ['/workspace/secimport/profiles/trace.bt', '-c', '/workspace/Python-3.11.8/python', '-o', 'trace.log']

                        Press CTRL+D to stop the trace;

Python 3.11.8 (default, Mar 19 2023, 08:34:46) [GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import this
>>>
 TRACING DONE;
 >>> secimport build

SECIMPORT COMPILING...

CREATED JSON TEMPLATE:  policy.json
CREATED YAML TEMPLATE:  policy.yaml
compiling template policy.yaml
DTRACE SANDBOX:  sandbox.d
BPFTRCE SANDBOX:  sandbox.bt
```

Now, let's run the sandbox!
```python
- Run the same commands as before, they should run without any problem;.
- Do something new in the shell; e.g:   >>> __import__("os").system("ps")

        OK? (y): y
 >>> secimport run
 RUNNING SANDBOX... ['./sandbox.bt', '--unsafe', ' -c ', '/workspace/Python-3.11.8/python']
Attaching 5 probes...
REGISTERING SYSCALLS...
STARTED
Python 3.11.8 (default, Mar 19 2023, 08:34:46) [GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import this
>>> import os
[SECIMPORT VIOLATION]: <stdin> called syscall ioctl at depth 0
[SECIMPORT VIOLATION]: <stdin> called syscall ioctl at depth 0
```

For more detailed usage instructions, see the [Command-Line Usage](https://github.com/avilum/secimport/wiki/Command-Line-Usage) page.

# Advanced

## Python API
See the [Python Imports](examples/python_imports/) example for more details.<br>
You can use secimport directly from python, instead of the CLI.<br> you can replace `import` with `secimport.secure_import` for selected modules, and have them supervised in real time.<br>

## seccomp-bpf support using nsjail
Beside the sandbox that secimport builds, <br>
The `secimport build` command creates an <a href="https://github.com/google/nsjail">nsjail</a> sandbox with seccomp profile for your traced code.<br> `nsjail` enables namespace sandboxing with seccomp on linux<br>
`secimport` automatically generates seccomp profiles to use with `nsjail` as executable bash script.
It can be used to limit the syscalls of the entire python process, as another layer of defence.

## Changelog
See the [Changelog](https://github.com/avilum/secimport/blob/master/docs/CHANGELOG.md) for development progress and existing features.

## Contributing
For information on how to contribute to `secimport`, see the [Contributing](https://github.com/avilum/secimport/blob/master/docs/CONTRIBUTING.md) guide.
