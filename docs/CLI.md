# CLI scripts

Secimport uses Fire to create a powerful CLI.

```shell
$ pip install secimport
$ secimport --help
```
```shell
NAME
    secimport

SYNOPSIS
    secimport COMMAND

COMMANDS
    COMMAND is one of the following:

     profile_from_trace
       Creates a yaml policy file from a given trace log. default: "trace.log".

     sandbox_from_profile
       Generates a tailor-made sandbox code for a given yaml policy file.

     sandbox_from_trace
       Converts a trace log into sandbox.

     secure_import
       Run a secure import for a python module and then exit. A log will be automatically generated at /tmp/.secimport
```



# Creating a new sandbox from scratch:

1. Run the secimport docker container
```shell
cd docker
./build.sh      # Build the bpftrace docker, to support your existing kernel
./run.sh        # Starts a new temporary container.
```

## Create a Sandbox Using Interactive Shell
We will run `./trace.sh` inside the container.<br>
A new shell will be opened, and everything that takes place in the shell will be traced into a log file.<br>
As you hit CTRL+C, the log file is automatically converted into a YAML configuration (profile).<br>
Finally, we compile that YAML profile into a sandbox code - 2 executable files.<br>
One file uses `eBPF` backend (bpftrace) and one file uses `DScript` (dtrace).
<br><br>

1. Start the interactive traced shell:
```shell
./trace.sh

>>> import this
>>> import os
>>> os.system('ps -flex')

```
2. When you had enough, hit CTRL+C or CTRL+D and let the magic happen:
```shell
CTRL+C/D
>>> 
KeyboardInterrupt
```

The trace was saved to trace.log, which is the deafult input file of the next command.

3. The log is analyzed and a sandbox profile is automatically created:
```shell
The JSON trace is ready at  traced_modules.json
The YAML template is ready at  traced_modules.yaml
Compiling template traced_modules.yaml

...
Adding syscall  close to allowlist for module /workspace/Python-3.10.0/Lib/codecs.py
Adding syscall  dup to allowlist for module /workspace/Python-3.10.0/Lib/codecs.py
Adding syscall  lseek to allowlist for module /workspace/Python-3.10.0/Lib/codecs.py
Adding syscall  read to allowlist for module /workspace/Python-3.10.0/Lib/codecs.py
Adding syscall  rt_sigaction to allowlist for module /workspace/Python-3.10.0/Lib/codecs.py
Adding syscall  brk to allowlist for module /workspace/Python-3.10.0/Lib/collections/__init__.py
Adding syscall  stat to allowlist for module /workspace/Python-3.10.0/Lib/genericpath.py
Adding syscall  rt_sigaction to allowlist for module /workspace/Python-3.10.0/Lib/posixpath.py
Adding syscall  rt_sigprocmask to allowlist for module /workspace/Python-3.10.0/Lib/posixpath.py
Adding syscall  select to allowlist for module /workspace/Python-3.10.0/Lib/posixpath.py
Adding syscall  write to allowlist for module /workspace/Python-3.10.0/Lib/posixpath.py
Adding syscall  fstat to allowlist for module /workspace/Python-3.10.0/Lib/site.py
Adding syscall  lseek to allowlist for module /workspace/Python-3.10.0/Lib/site.py
Adding syscall  openat to allowlist for module /workspace/Python-3.10.0/Lib/site.py
Adding syscall  write to allowlist for module /workspace/Python-3.10.0/Lib/this.py
Adding syscall  close to allowlist for module <frozen zipimport>
Adding syscall  fcntl to allowlist for module <frozen zipimport>
Adding syscall  fstat to allowlist for module <frozen zipimport>
Adding syscall  ioctl to allowlist for module <frozen zipimport>
Adding syscall  lseek to allowlist for module <frozen zipimport>
Adding syscall  openat to allowlist for module <frozen zipimport>
Adding syscall  read to allowlist for module <frozen zipimport>
Adding syscall  pread to allowlist for module general_requirements
Adding syscall  prlimit64 to allowlist for module general_requirements
Adding syscall  read to allowlist for module general_requirements
Adding syscall  rt_sigaction to allowlist for module general_requirements
Adding syscall  rt_sigprocmask to allowlist for module general_requirements
Adding syscall  set_robust_list to allowlist for module general_requirements
Adding syscall  set_tid_address to allowlist for module general_requirements
...

The dtrace sandbox script is ready at traced_modules.d
The bpftrace sandbox script is ready at traced_modules.bt
Done.
```

4. Run the sandbox:
```shell
./traced_modules.bt -c python main.py
# or
traced_modules.d -c python main.py

>>> # This interpreter will be killed if any of the traced modules will use a new syscall.
```
