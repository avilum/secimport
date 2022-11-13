# secimport


<p align="center">
 <a href="https://github.com/avilum/secimport"><img src="https://user-images.githubusercontent.com/19243302/177835749-6aec7200-718e-431a-9ab5-c83c6f68565e.png" alt="secimport"></a>
</p>
<p align="center">
An easy way to constrain python modules in your code using backends like bpftrace (eBPF) and dtrace.<br>
<a href="https://infosecwriteups.com/sandboxing-python-modules-in-your-code-1e590d71fc26?source=friends_link&sk=5e9a2fa4d4921af0ec94f175f7ee49f9">Medium Article</a>
</p>

`secimport` can be used to:
- Confine/Restrict specific python modules inside your production environment.
  - Restrict 3rd party or open source modules in your code.
- Audit the flow of your python application at user-space/os/kernel level.
- Kill the process upon violoation of a profile.

# Quick Start
`secimport` can be used out of the box in the following ways:
1. Modify your imports
    - Inside your code using `module = secimport.secure_import('module_name', ...)`.
      - Replacing the regular `import` statement with `secure_import`
      - Only modules that were imported with `secure_import` will be traced.
2. As a sandbox that runs your main code.
      1. Generate a YAML policy from your code, by specifying the modules and the policy you want for each module you use.
      2. Convert that YAML policy to dscript/bpftrace sandbox code.
      3. Use `dtrace` or `ebpf` to run your main python application, with your tailor-made sandbox.
          - No need for `secure_import`, you can keep using regular `import`s and not change your code at all.

For the full list of examples, see <a href="docs/EXAMPLES.md">EXAMPLES.md</a>.

# Docker
A working environment is not easy to create.<br>
The easiest way to evaluate secimport, is by using our <a href="docker/README.md">Docker for MacOS and Linux</a> that includes secimport, bpftrace backend and eBPF libraries.<br>
dtrace backend is not available in docker, and can be tried directly on the compatible hosts (MacOS, Solaris, Unix, some Linux distributions)

# Use Cases

### How pickle can be exploited in your 3rd party packages:
```python
>>> import pickle
>>> class Demo:
...     def __reduce__(self):
...         return (eval, ("__import__('os').system('echo Exploited!')",))
... 
>>> pickle.dumps(Demo())
b"\x80\x04\x95F\x00\x00\x00\x00\x00\x00\x00\x8c\x08builtins\x94\x8c\x04eval\x94\x93\x94\x8c*__import__('os').system('echo Exploited!')\x94\x85\x94R\x94."
>>> pickle.loads(b"\x80\x04\x95F\x00\x00\x00\x00\x00\x00\x00\x8c\x08builtins\x94\x8c\x04eval\x94\x93\x94\x8c*__import__('os').system('echo Exploited!')\x94\x85\x94R\x94.")
Exploited!
0
```
With `secimport`, you can control such action to do whatever you want:
```python
In [1]: import secimport
In [2]: pickle = secimport.secure_import("pickle")
In [3]: pickle.loads(b"\x80\x04\x95F\x00\x00\x00\x00\x00\x00\x00\x8c\x08builtins\x94\x8c\x04eval\x94\x93\x94\x8c*__import__('os').system('echo Exploited!')\x94\x85\x94R\x94.")

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

## YAML Policy Example
For a full tutorial, see <a href="docs/YAML_PROFILES.md">YAML Profiles Usage</a>
```shell
# An example yaml template for a sandbox.

modules:
  requests:
    destructive: true
    syscall_allowlist:
      - write
      - ioctl
      ...
      - stat64
  fastapi:
    destructive: true
    syscall_allowlist:
      - bind
      - fchmod
      ...
      - stat64
  uvicorn:
    destructive: true
    syscall_allowlist:
      - getpeername
      - getpgrp
      ...
      - stat64

```

## Blocking New Processes Example
```python
Python 3.10.0 (default, May  2 2022, 21:43:20) [Clang 13.0.0 (clang-1300.0.27.3)] on darwin
Type "help", "copyright", "credits" or "license" for more information.

# Let's import subprocess module, limiting it's syscall access.
>>> import secimport
>>> subprocess = secimport.secure_import("subprocess")

# Let's import os 
>>> import os
>>> os.system("ps")
  PID TTY           TIME CMD
 2022 ttys000    0:00.61 /bin/zsh -l
50092 ttys001    0:04.66 /bin/zsh -l
75860 ttys001    0:00.13 python
0
# It worked as expected, returning exit code 0.


# Now, let's try to invoke the same logic using a different module, "subprocess", that was imported using secure_import:
>>> subprocess.check_call('ps')
[1]    75860 killed     python

# Damn! That's cool.
```

When using secure_import, the following files are created:
- The dtrace/bpftrace sandbox code for the module is saved under:
  -  `/tmp/.secimport/sandbox_subprocess.d`
      - when using dtrace
  -  `/tmp/.secimport/sandbox_subprocess.bt`:
      - when using bpftrace
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

## Shell Blocking Example
```python
# example.py - Executes code upon import;
import os;

os.system('Hello World!');
```
```python
# production.py - Your production code
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

## Network Blocking Example
```
>>> import requests
>>> requests.get('https://google.com')
<Response [200]>
  

>>> from secimport import secure_import
>>> requests = secure_import('requests', allow_networking=False)

# The next call should kill the process,
# because we disallowed networking for the requests module.
>>> requests.get('https://google.com')
[1]    86664 killed
```
### Requirements
The only requirement is a Python interpreter that was built with --with-dtrace.
  - See <a href="docs/INSTALL.md">INSTALL.md</a> for a detailed setup from scratch.
- pip
  - `python3 -m pip install secimport`
- Poetry
  - `python3 -m pip install poetry && python3 -m poetry build`
<br>

### Tests
`python -m pytest`


### Log4Shell as an example
Not related for python, but for the sake of explanation (Equivilant Demo soon).
- <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2021-44228">Log4Shell - CVE-2021-44228</a>
  - Let's say we want to block `log4j` from doing crazy things.
  - In the following import we deny `log4j` from opening an LDAP connection / shell:
    - `log4j = secure_import('log4j', allow_shells=False, allow_networking=False)`
  - This would disable `log4j` from opening sockets and execute commands, IN THE KERNEL.
  - You can choose any policy you like for any module.
<br><br>


# Useful References
- <a href="docs/EXAMPLES.md">Examples</a>
- <a href="docs/TRACING_PROCESSES.md">Tracing Guides</a>
- <a href="docs/FAQ.md">F.A.Q</a>
- <a href="docs/INSTALL.md">Installation</a>
- <a href="docs/MAC_OS_USERS.md">Mac OS Users</a> - Disabling SIP (System Intergity Protection)
- https://www.brendangregg.com/DTrace/DTrace-cheatsheet.pdf
- https://www.brendangregg.com/blog/2018-10-08/dtrace-for-linux-2018.html
<br><br>

## TODO:
- ✔️ Allow/Block list configuration
- ✔️ Create a .yaml configuration per module in the code
  - ✔️ Use secimport to compile that yml
  - ✔️ Create a single dcript policy
  - ✔️ Run an application with that policy using dtrace, without using `secure_import`
- ✔️ <b>Add eBPF basic support using bpftrace</b>
  - ✔️ bpftrace backend tests
- <b>Extandible Language Template</b>
  - Increase extandability for new languages tracing with bpftace/dtrace.
    - Adding a new integration will be easy, in a single directory, using templates for filters, actions, etc.
- <b>Node support</b> (bpftrace/dtrace hooks)
  - Implement a template for Node's call stack and event loop
- <b>Go support</b> (bpftrace/dtrace hooks)
   - Implement a template for golang's call stack
- Multi Process support: Use current_module_str together with thread ID to distinguish between events in different processes
- Update all linux syscalls in the templates (filesystem, networking, processing) to improve the sandbox blocking of unknowns.
