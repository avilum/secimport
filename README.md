# secimport
`secimport` is a sandbox toolkit, that traces your application and grants privilleges <b>per module</b> in your code.<br>
By doing so, `secimport` enhances runtime security, giving you the ability to choose the privilleges for:
  - All of your code - global privilleges (like seccomp, apparmor, firejail, etc.)
  - 3rd party dependencies 
    - That can be added/modified without you knowing, to avoid supply chain attacks.
  - Open-Source packages
    - You don't have control over them, and keeping it up-to-date cannot be guaranteed.

It uses backends like bpftrace <b>(eBPF)</b> and <b>dtrace</b> under the hood, making it cross-platform.<br>
<p align="center">
<a href="https://infosecwriteups.com/sandboxing-python-modules-in-your-code-1e590d71fc26?source=friends_link&sk=5e9a2fa4d4921af0ec94f175f7ee49f9">Medium Article</a>
</p>
<p align="center">
 <a href="https://github.com/avilum/secimport"><img style="max-height: 100px" src="https://user-images.githubusercontent.com/19243302/177835749-6aec7200-718e-431a-9ab5-c83c6f68565e.png" alt="secimport"></a>
</p>

# How is works?
`secimport` uses USDT (Userland Statically Defined Tracing) probes in the runtime (Python interpreter for example) using eBPF and dtrace instrumentation scripts.<br>
You can use `secimport` to:
- Trace which syscalls are called by each module in your code, or by your entire application.
- Restrict specific modules/packages inside your production environment like 3rd party, open source or code from untrusted source.
- Audit the flow of your python application at user-space/os/kernel level.
- Kill or audit upon violoation of your specified behavior. Killing is optional.
<br><br>
# Quick Start
There are several methods to create and run a sandbox:
1. By modifying your imports
    - Inside your code using `module = secimport.secure_import('module_name', ...)`.
      - Replacing the regular `import` statement with `secure_import`
      - Only modules that were imported with `secure_import` will be traced.
2. By running it as a parent process for your application
      -  Generate a YAML policy from your code, by specifying the modules and the policy you want, for every module that you would like to restrict in any way.
         - Convert that YAML policy to dscript/bpftrace sandbox code.
      - Run you tailor-made sandbox
          - Use `dtrace` or `bpftrace` to run your main python application, with your tailor-made sandbox.
          - No need for `secure_import`, you can keep using regular `import`s and not change your code at all.
<br><br>
# Docker
The easiest way to try secimport is by using our <a href="docker/README.md">Docker for MacOS and Linux</a>. It includes python, secimport and bpftrace backend.<br>
`dtrace` backend is not available in docker, and can be tried directly on the compatible hosts ( <a href="docs/MAC_OS_USERS.md">Mac OS</a> , Windows, Solaris, Unix, some Linux distributions).
<br><br>

# References:
- Read about the available backends in secimport:
  - https://www.brendangregg.com/DTrace/DTrace-cheatsheet.pdf
    - `dtrace`
  - https://www.brendangregg.com/blog/2018-10-08/dtrace-for-linux-2018.html
    - `bpftrace` (dtrace 2.0) that uses LLVM and compiled our script to BCC.
       - https://github.com/iovisor/bpftrace
- <a href="docs/EXAMPLES.md">Examples</a>

- Guides
  - <a href="docs/TRACING_PROCESSES.md">Tracing Processes Guide</a>
  - <a href="docs/INSTALL.md">Installation</a>
  - <a href="docs/MAC_OS_USERS.md">Mac OS Users</a> - Disabling SIP (System Intergity Protection)
  - <a href="docs/FAQ.md">F.A.Q</a>
  <br><br>


# Example Use Cases
<a href="docs/EXAMPLES.md">EXAMPLES.md</a> contains advanced usage and many interactive session examples: YAML profies, networking, filesystem, processing blocking & more.

## Simple Usage
- <a href="examples/python_imports/">Running Sandbox Using Python Imports</a>
- <a href="docs/CLI.md">`secimport` CLI usage</a>
    - The easiest option to start with inside docker.
    - `python -m secimport.cli --help`
- See <a href="YAML_PROFILES.md">YAML Profiles Usage</a>>
<br><br>
### How pickle can be exploited in your 3rd party packages (and how to block it)
```python
# Not your code, but you load and run it frmo 3rd some party package.

import pickle
class Demo:
    def __reduce__(self):
        return (eval, ("__import__('os').system('echo Exploited!')",))
 
pickle.dumps(Demo())
b"\x80\x04\x95F\x00\x00\x00\x00\x00\x00\x00\x8c\x08builtins\x94\x8c\x04eval\x94\x93\x94\x8c*__import__('os').system('echo Exploited!')\x94\x85\x94R\x94."

# Your code, at some day...
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
More examples are available at <a href="docs/EXAMPLES.md">EXAMPLES.md</a>.

<br><br>
# Roadmap
- ✔️ Allow/Block list configuration
- ✔️ Create a .yaml configuration per module in the code
  - ✔️ Use secimport to compile that yml
  - ✔️ Create a single dcript policy
  - ✔️ Run an application with that policy using dtrace, without using `secure_import`
- ✔️ <b>Add eBPF basic support using bpftrace</b>
  - ✔️ bpftrace backend tests
- ✔️ Implement all python supported USDT probes:
  - ✔️ import__find__load__start
  - ✔️ import__find__load__done
  - ✔️ line
- <b>Extandible Language Template</b>
  - Implement bpftrace probes for new languages
- <b>Go support</b> (bpftrace/dtrace hooks)
  - Implement a template for golang's call stack
- <b>Node support</b> (bpftrace/dtrace hooks)
  - Implement a template for Node's call stack and event loop
- Multi Process support: Use current_module_str together with thread ID to distinguish between events in different processes
- Update all linux syscalls in the templates (filesystem, networking, processing) to improve the sandbox blocking of unknowns.
