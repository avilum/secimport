# CLI scripts

Secimport uses Fire to create a powerful CLI.

```shell
$ pip install secimport
$ secimport --help
```
```shell
NAME
    cli.py - SecImport - A toolkit for Tracing and Securing Python Runtime using USDT probes and eBPF/DTrace: https://github.com/avilum/secimport/wiki/Command-Line-Usage

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
            # secimport build
            $ secimport build -h
        3. run:
            $  secimport run
            $  secimport run --entrypoint my_custom_main.py
            $  secimport run --sandbox_executable /path/to/my_sandbox.bt --pid 2884
            $  secimport run -h

COMMANDS
    COMMAND is one of the following:

     build

     interactive

     run
       Run a python process inside the sandbox.

     trace
       Generate snippets for trace command line usage.

     trace_pid
       Traces a running process by pid. It might require sudo privilleges on some hosts.
(END)
```



# Creating a new sandbox from scratch:

1. Run the secimport docker container
```shell
cd docker
./build.sh      # Build the bpftrace docker, to support your existing kernel
./run.sh        # Starts a new temporary container.
```

## QUICKSTART
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
The Zen of Python, by Tim Peters

Beautiful is better than ugly.
Explicit is better than implicit.
Simple is better than complex.
Complex is better than complicated.
Flat is better than nested.
Sparse is better than dense.
Readability counts.
Special cases aren't special enough to break the rules.
Although practicality beats purity.
Errors should never pass silently.
Unless explicitly silenced.
In the face of ambiguity, refuse the temptation to guess.
There should be one-- and preferably only one --obvious way to do it.
Although that way may not be obvious at first unless you're Dutch.
Now is better than never.
Although never is often better than *right* now.
If the implementation is hard to explain, it's a bad idea.
If the implementation is easy to explain, it may be a good idea.
Namespaces are one honking great idea -- let's do more of those!
>>> 


 TRACING DONE; 
 >>> secimport build 
 
SECIMPORT COMPILING... 

CREATED JSON TEMPLATE:  traced_modules.json
CREATED YAML TEMPLATE:  traced_modules.yaml
 

compiling template traced_modules.yaml
[debug] adding syscall close to allowlist for module None
[debug] adding syscall dup to allowlist for module None
[debug] adding syscall fstat to allowlist for module None
[debug] adding syscall ioctl to allowlist for module None
[debug] adding syscall lseek to allowlist for module None
[debug] adding syscall read to allowlist for module None
...
[debug] adding syscall set_robust_list to allowlist for module general_requirements
[debug] adding syscall set_tid_address to allowlist for module general_requirements

DTRACE SANDBOX:  traced_modules.d
BPFTRCE SANDBOX:  traced_modules.bt
 
 SANDBOX READY: traced_modules.bt 
 
Now, let's run the sandbox.
- Run the same commands as before, they should run without any problem;.
- Do something new in the shell; e.g:   >>> __import__("os").system("ps") 

        OK? (y): y
 >>> secimport run 
 RUNNING SANDBOX... ['./traced_modules.bt', '--unsafe', ' -c ', '/workspace/Python-3.10.0/python'] 
Attaching 5 probes...
REGISTERING SYSCALLS...
STARTED
Python 3.10.0 (default, Mar 19 2023, 08:34:46) [GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import this
The Zen of Python, by Tim Peters

Beautiful is better than ugly.
Explicit is better than implicit.
Simple is better than complex.
Complex is better than complicated.
Flat is better than nested.
Sparse is better than dense.
Readability counts.
Special cases aren't special enough to break the rules.
Although practicality beats purity.
Errors should never pass silently.
Unless explicitly silenced.
In the face of ambiguity, refuse the temptation to guess.
There should be one-- and preferably only one --obvious way to do it.
Although that way may not be obvious at first unless you're Dutch.
Now is better than never.
Although never is often better than *right* now.
If the implementation is hard to explain, it's a bad idea.
If the implementation is easy to explain, it may be a good idea.
Namespaces are one honking great idea -- let's do more of those!
>>> import os
[SECIMPORT VIOLATION]: <stdin> called syscall ioctl at depth 0
[SECIMPORT VIOLATION]: <stdin> called syscall ioctl at depth 0
[SECIMPORT VIOLATION]: <stdin> called syscall ioctl at depth 0
[SECIMPORT VIOLATION]: <stdin> called syscall ioctl at depth 0
[SECIMPORT VIOLATION]: <stdin> called syscall ioctl at depth 0
[SECIMPORT VIOLATION]: <stdin> called syscall ioctl at depth 0
[SECIMPORT VIOLATION]: <stdin> called syscall ioctl at depth 0
[SECIMPORT VIOLATION]: <stdin> called syscall ioctl at depth 0
```
