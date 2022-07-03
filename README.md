# secimport
The cross-platform inline Sandbox for python modules.

## Usage
```python
import secimport

# import log4j and kill it if a spawn/exec/fork/forkexec syscall is executed, etc.
log4j = secimport.secure_import('log4j', allow_shell=False)
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

## Mac users
To use dtrace and to access moduels names in the kernel, you should disable SIP (System Integrity Protection) for dtrace. You can disable it for dtrace only:
  - boot into recovery mode using `command + R`.
  -  When recovery mode screen is show, open Utilities -> Terminal
  - `csrutil disable`
  - `csrutil enable --without dtrace` 

### Hot it works
- (TL;DR) dtrace instrumentation scripts with destructive flag<br>
- The supervision is done in a OS syscall level, without IPC. very much like `seccomp/seccomp-bpf`. Docker does it as well, for example.
- The supervision requires the sudo privilliges

### Is it production-ready?
From <a href="https://en.wikipedia.org/wiki/DTrace">Wikipedia</a>:
>Special consideration has been taken to make DTrace safe to use in a production environment. For example, there is minimal probe effect when tracing is underway, and no performance impact associated with any disabled probe; this is important since there are tens of thousands of DTrace probes that can be enabled. New probes can also be created dynamically.