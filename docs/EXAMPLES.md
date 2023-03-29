# Sandbox Examples
To understand how to trace your process and create custom profiles for modules or applications, please see <a href="TRACING_PROCESSES.md">Tracing Processes</a>

# Docker examples
We have a Zero-To-One with Docker that goes through <a href="../docker/README.md">Tracing and Compiling an eBPF sandbox for an app.</a>

# Secure Import Examples
## Simple Usage
- <a href="CLI.md">`secimport` CLI usage</a>
    - The easiest option to start with inside docker.
    - `secimport --help` or `python3 -m secimport.cli`
- <a href="../examples/python_imports/">Running Sandbox Using Python Imports</a>
- See <a href="YAML_PROFILES.md">YAML Profiles Usage</a>
<br><br>

## Advanced Usage
- <a href="../examples/bpftrace_sandbox/">`eBPF` Example Sandbox</a>
- <a href="../examples/dtrace_sandbox/">`DTrace` Example Sandbox</a>
- <a href="../examples/yaml_template/">Generate Sandbox Code From YAML Configuration</a>
<br><br>

# Interactive Examples

### How pickle can be exploited in your 3rd party packages:
```python
import pickle
class Demo:
    def __reduce__(self):
        return (eval, ("__import__('os').system('echo Exploited!')",))
 
pickle.dumps(Demo())
b"\x80\x04\x95F\x00\x00\x00\x00\x00\x00\x00\x8c\x08builtins\x94\x8c\x04eval\x94\x93\x94\x8c*__import__('os').system('echo Exploited!')\x94\x85\x94R\x94."
pickle.loads(b"\x80\x04\x95F\x00\x00\x00\x00\x00\x00\x00\x8c\x08builtins\x94\x8c\x04eval\x94\x93\x94\x8c*__import__('os').system('echo Exploited!')\x94\x85\x94R\x94.")
Exploited!
0
```
With `secimport`, you can control such action to do whatever you want:
```python
import secimport
pickle = secimport.secure_import("pickle")
pickle.loads(b"\x80\x04\x95F\x00\x00\x00\x00\x00\x00\x00\x8c\x08builtins\x94\x8c\x04eval\x94\x93\x94\x8c*__import__('os').system('echo Exploited!')\x94\x85\x94R\x94.")

[1]    28027 killed     ipython
```
A log file is automatically created, containing everything you need to know:
```
$ less /tmp/.secimport/sandbox_pickle.log

  @posix_spawn from /Users/avilumelsky/Downloads/Python-3.10.0/Lib/threading.py
    DETECTED SHELL:
        depth=8
        sandboxed_depth=0
        sandboxed_module=/Users/avilumelsky/Downloads/Python-3.10.0/Lib/pickle.py  

    TERMINATING SHELL:
        libsystem_kernel.dylib`__posix_spawn+0xa
        ...
                libsystem_kernel.dylib`__posix_spawn+0xa
                libsystem_c.dylib`system+0x18b
                python.exe`os_system+0xb3
    KILLED
:
```
<br><br>
## Creating a YAML policy file
For a full tutorial, see <a href="YAML_PROFILES.md">YAML Profiles Usage</a>
```shell
# An example yaml template for a sandbox.

modules:
  requests:
    destructive: true
    syscall_allowlist:
      - write
      - ioctl
      - stat64
  fastapi:
    destructive: true
    syscall_allowlist:
      - bind
      - fchmod
      - stat64
  uvicorn:
    destructive: true
    syscall_allowlist:
      - getpeername
      - getpgrp
      - stat64

```
<br><br>
## Blocking New Processes Example
```python
Python 3.10.0 (default, May  2 2022, 21:43:20) [Clang 13.0.0 (clang-1300.0.27.3)] on darwin
Type "help", "copyright", "credits" or "license" for more information.

# Let's import subprocess module, limiting it's syscall access.
import secimport
subprocess = secimport.secure_import("subprocess")

# Let's import os 
import os
os.system("ps")
  PID TTY           TIME CMD
 2022 ttys000    0:00.61 /bin/zsh -l
50092 ttys001    0:04.66 /bin/zsh -l
75860 ttys001    0:00.13 python
0
# It worked as expected, returning exit code 0.


# Now, let's try to invoke the same logic using a different module, "subprocess", that was imported using secure_import:
subprocess.check_call('ps')
[1]    75860 killed     python

# Damn! That's cool.
```

When using secure_import, the following files are created:
- The dtrace/bpftrace sandbox code for the module is saved under:
  -  `/tmp/.secimport/sandbox_subprocess.bt`:
      - when using bpftrace
  -  `/tmp/.secimport/sandbox_subprocess.d`
      - when using dtrace
- The log file for this module is under
  -  `/tmp/.secimport/sandbox_subprocess.log`:
        ```shell
        ...

        (OPENING SHELL using posix_spawn): (pid 75860) (thread 344676) (user 501) (python module: <stdin>) (probe mod=, name=entry, prov=syscall func=posix_spawn) /bin/sh 
            #posix_spawn,

        (TOUCHING FILESYSTEM): write(140339021606912) from thread 344676
                    libsystem_kernel.dylib`__fork+0xb
                    _posixsubprocess.cpython-310-darwin.so`do_fork_exec+0x29
                    _posixsubprocess.cpython-310-darwin.so`subprocess_fork_exec+0x71f
                    python.exe`cfunction_call+0x86
        killing...
        killed.
        ```
<br><br>
## Shell Blocking Example
You can try it yourself with docker, locally.
```
./docker/build.sh
./docker/run.sh
$ /workspace/run_sandbox.sh
```
```
Starting secimport sandbox with bpftrace backend, the sandbox should kill the python process...
WARNING: Addrspace is not set
  PID TTY          TIME CMD
    1 pts/0    00:00:00 sh
   10 pts/0    00:00:00 bash
  114 pts/0    00:00:00 bpftrace
  118 pts/0    00:00:00 python
  121 pts/0    00:00:00 ps
  122 pts/0    00:00:00 pkill


The process was killed, as expected.
The sandbox bpftrace code is at sandbox.bt
The sandbox log is at sandbox.log
```

The following code will open a new bash shell using os.system.
In this sandbox we disallow such behavior, by disabling the fork/exec/spawn syscalls.

```python
# example.py - Executes code upon import;
import os;

os.system('Hello World!');
```
```python
from secimport import secure_import 

example = secure_import('example', allow_shells=False)
```
Let's run the  and see what happens:
```
(root) sh-3.2#  export PYTHONPATH=$(pwd)/src:$(pwd)/examples:$(pwd):$PYTHONPATH
(root) sh-3.2#  python examples/production.py 
Successfully compiled dtrace profile:  /tmp/.secimport/sandbox_example.d
Killed: 9
```
- We imported `example` with limited capabilities.
- If a syscall like `spawn/exec/fork/forkexec` will be executed
  - The process will be `kill`ed with `-9` signal.
<br><br>
## Network Blocking Example
```
import requests
requests.get('https://google.com')
<Response [200]>
  

from secimport import secure_import
requests = secure_import('requests', allow_networking=False)

# The next call should kill the process,
# because we disallowed networking for the requests module.
requests.get('https://google.com')
[1]    86664 killed
```
