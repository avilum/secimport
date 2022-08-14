# secimport

<p align="center">
 <a href="https://github.com/avilum/secimport"><img src="https://user-images.githubusercontent.com/19243302/177835749-6aec7200-718e-431a-9ab5-c83c6f68565e.png" alt="secimport"></a>
</p>
<p align="center">
Secure import for python modules using dtrace under the hood.<br>
<a href="https://infosecwriteups.com/sandboxing-python-modules-in-your-code-1e590d71fc26?source=friends_link&sk=5e9a2fa4d4921af0ec94f175f7ee49f9">Medium Article</a>
</p>

`secimport` can be used to:
- Confine/Restrict specific python modules inside your production environment.
  - Open Source, 3rd party from unstrusted sources.
  - Audit the flow of your python application at user-space/os/kernel level.
- Run an entire python application under unified configuration
  - Like `seccomp` but not limited to Linux kernels. Cross platform.


# Quick Start
For the full list of examples, see <a href="docs/EXAMPLES.md">EXAMPLES.md</a>.

## YAML Template Example
```shell
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
See <a href="docs/YAML_PROFILES.md">YAML Profiles Usage</a>

## Python Shell Interactive Example
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

- The dtrace profile for the module is saved under:
  -  `/tmp/.secimport/sandbox_subprocess.d`:
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

## Shell blocking
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

## Network blocking
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
- <a href="docs/MAC_OS_USERS.md">Mac OS Users</a> - Disabling SIP for dtrace
- https://www.brendangregg.com/DTrace/DTrace-cheatsheet.pdf
<br><br>

## TODO:
- Node support (dtrace hooks)
- Go support (dtrace hooks)
- Allow/Block list configuration
- Use current_module_str together with thread ID
- Create a .yaml configuration per module in the code
  - Use secimport to compile that yml
  - Create a single dcript policy
  - Run an application with that policy using dtrace, without using `secure_import`
