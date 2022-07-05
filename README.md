# secimport
A cross-platform sandbox for python modules. secimport can be used to:

- Limit specific python modules inside your production environment.
  - Open Source, 3rd party from unstrusted sources.
- Log the flow of your application/os level
- Run an entire python application under unified configuration
  - Like `seccomp` and `seccomp-bpf`, <b>without changing your code</b>

# Why should I use secimport?
- 
- 
- 

### Python Usage
```python
from secimport import secure_import 

# import requests and kill it if a spawn/exec/fork/forkexec syscall is executed.
requests = secure_import('requests', allow_shell=False)
```


### Python Shell Interactive Example
```python
(dtrace) ➜  src git:(master) ✗ python
Python 3.10.0 (default, May  2 2022, 21:43:20) [Clang 13.0.0 (clang-1300.0.27.3)] on darwin
Type "help", "copyright", "credits" or "license" for more information.

# Let's import secimport
>>> import secimport
>>> subprocess = secimport.secure_import("subprocess")
>>> subprocess
<module 'subprocess' from '/Users/avilumelsky/Downloads/Python-3.10.0/Lib/subprocess.py'>    

# Let's import os 
>>> import os
>>> os.system("ps")
  PID TTY           TIME CMD
 2022 ttys000    0:00.61 /bin/zsh -l
50092 ttys001    0:04.66 /bin/zsh -l
75860 ttys001    0:00.13 python
0
# It worked as expected, returning exit code 0;


# Now, let's try to invoke the same command using the "secure imported" module:
>>> subprocess.check_call('ps')
[1]    75860 killed     python
# Boom! 
```

- `sandbox_subprocess.log`:
```shell
...

(OPENING SHELL using posix_spawn): (pid 75860) (thread 344676) (user 501) (python module: <stdin>) (probe mod=, name=entry, prov=syscall func=posix_spawn) /bin/sh 
		#posix_spawn,
        (TOUCHING FILESYSTEM): write(140339021606912) from thread 344676 in python module <stdin>
		
...
        libsystem_kernel.dylib`__fork+0xb
        _posixsubprocess.cpython-310-darwin.so`do_fork_exec+0x29
        _posixsubprocess.cpython-310-darwin.so`subprocess_fork_exec+0x71f
        python.exe`cfunction_call+0x86
killing...
killed.

Calls for PID 75860,

 FILE                             TYPE       NAME                      COUNT
 python.exe                       syscall    fstatfs64                     1
 python.exe                       syscall    getdirentries64               1
 python.exe                       syscall    kqueue                        1
 python.exe                       syscall    poll                          1
 python.exe                       syscall    madvise                       2
 python.exe                       syscall    pipe                          2
 python.exe                       syscall    posix_spawn                   2
 python.exe                       syscall    wait4_nocancel                2
 python.exe                       syscall    write                         3
 python.exe                       syscall    munmap                        4
 python.exe                       syscall    fcntl_nocancel               10
 python.exe                       syscall    lseek                        10
 python.exe                       syscall    close_nocancel               11
 python.exe                       syscall    open_nocancel                11
 python.exe                       syscall    fcntl                        12
 python.exe                       syscall    open                         17
 python.exe                       syscall    close                        20
 python.exe                       syscall    fstat64                      20
 python.exe                       syscall    mmap                         20
 python.exe                       syscall    mprotect                     20
 python.exe                       syscall    sigprocmask                  34
 python.exe                       syscall    ioctl                        48
 python.exe                       syscall    stat64                       58
 python.exe                       syscall    sigaction                    78
 python.exe                       syscall    select                      102
 python.exe                       syscall    write_nocancel              114
 python.exe                       syscall    read                        222
```

## Requirements
The <b>only(!)</b> requirement is a python interpreter that was built with --with-dtrace.

```shell
PYTHON_VERSION="3.7.0"

cd /tmp
curl -o Python-$PYTHON_VERSION.tgz https://www.python.org/ftp/python/$PYTHON_VERSION/Python-$PYTHON_VERSION.tgz
tar -xzf Python-$PYTHON_VERSION.tgz
cd Python-$PYTHON_VERSION && ./configure --with-dtrace && make

python3 -m venv ~/venvs/dtrace
source ~/venvs/dtrace/bin/activate
```

### How does it work?
- (TL;DR) dtrace instrumentation scripts with destructive flag<br>
- The supervision is done in a OS syscall level, without IPC. very much like `seccomp/seccomp-bpf`. Docker does it as well, for example.
- The supervision requires the sudo privilliges

### Is it production-ready?
From <a href="https://en.wikipedia.org/wiki/DTrace">Wikipedia</a>:
>Special consideration has been taken to make DTrace safe to use in a production environment. For example, there is minimal probe effect when tracing is underway, and no performance impact associated with any disabled probe; this is important since there are tens of thousands of DTrace probes that can be enabled. New probes can also be created dynamically.

### Mac users?
To use dtrace and to access moduels names in the kernel, you should disable SIP (System Integrity Protection) for dtrace. You can disable it for dtrace only:
  - boot into recovery mode using `command + R`.
  -  When recovery mode screen is show, open Utilities -> Terminal
  - `csrutil disable`
  - `csrutil enable --without dtrace` 