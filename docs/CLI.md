<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Usage](#usage)
- [Stop on violation](#stop-on-violation)
- [Kill on violation](#kill-on-violation)
- [Dynamic profiling - trace, build sandbox, run.](#dynamic-profiling---trace-build-sandbox-run)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Usage
To sandbox your program using the CLI, start a bpftrace program that logs all the syscalls for all the modules in your application into a file with the secimport trace command. Once you have covered the logic you would like to sandbox, hit CTRL+C or CTRL+D, or wait for the program to finish. Then, build a sandbox from the trace using the secimport build command, and run the sandbox with the secimport run command.

```shell
NAME
    SecImport - A toolkit for Tracing and Securing Python Runtime using USDT probes and eBPF/DTrace

SYNOPSIS
    cli.py COMMAND

DESCRIPTION
    QUICK START:
            $ secimport interactive

    EXAMPLES:
        1. trace | shell:
            $  secimport shell
            $  secimport trace
            $  secimport trace -h
            $  secimport trace_pid 123
            $  secimport trace_pid -h
        2. build:
            # secimport build
            $ secimport build
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

## Kill on violation
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

## Dynamic profiling - trace, build sandbox, run.
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
[debug] adding syscall close to allowlist for module None
[debug] adding syscall dup to allowlist for module None
[debug] adding syscall fstat to allowlist for module None
[debug] adding syscall ioctl to allowlist for module None
[debug] adding syscall lseek to allowlist for module None
[debug] adding syscall read to allowlist for module None
...
[debug] adding syscall set_robust_list to allowlist for module general_requirements
[debug] adding syscall set_tid_address to allowlist for module general_requirements

DTRACE SANDBOX:  sandbox.d
BPFTRCE SANDBOX:  sandbox.bt

 SANDBOX READY: sandbox.bt

Now, let's run the sandbox!
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
