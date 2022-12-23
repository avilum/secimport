# secimport
A sandbox that grants privilleges per module in your code, making 3rd pary and open source and untrusted code to run in trusted environments.<br>
It does using backends like bpftrace (eBPF) and dtrace under the hood.<br>
<p align="center">
<a href="https://infosecwriteups.com/sandboxing-python-modules-in-your-code-1e590d71fc26?source=friends_link&sk=5e9a2fa4d4921af0ec94f175f7ee49f9">Medium Article</a>
</p>
<p align="center">
 <a href="https://github.com/avilum/secimport"><img style="max-height: 100px" src="https://user-images.githubusercontent.com/19243302/177835749-6aec7200-718e-431a-9ab5-c83c6f68565e.png" alt="secimport"></a>
</p>

# How is works?
`secimport` uses USDT (Userland Statically Defined Tracing) probes in the runtime (Python interpreter for example). OS kernel using eBPF and dtrace instrumentation scripts.<br>
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

## Simple Usage
- <a href="examples/python_imports/">Running Sandbox Using Python Imports</a>
- <a href="docs/CLI.md">`secimport` CLI usage</a>
    - The easiest option to start with inside docker.
    - `python -m secimport.cli --help`
- See <a href="YAML_PROFILES.md">YAML Profiles Usage</a>
<br><br>
For the advanced usage and other examples (networking, filesystem, processing blocking & more) see <a href="docs/EXAMPLES.md">EXAMPLES.md</a>.

<br><br>
# Roadmap
- ✔️ Allow/Block list configuration
- ✔️ Create a .yaml configuration per module in the code
  - ✔️ Use secimport to compile that yml
  - ✔️ Create a single dcript policy
  - ✔️ Run an application with that policy using dtrace, without using `secure_import`
- ✔️ <b>Add eBPF basic support using bpftrace</b>
  - ✔️ bpftrace backend tests
- <b>Extandible Language Template</b>
  - Implement bpftrace probes for new languages
- <b>Go support</b> (bpftrace/dtrace hooks)
  - Implement a template for golang's call stack
- <b>Node support</b> (bpftrace/dtrace hooks)
  - Implement a template for Node's call stack and event loop
- Multi Process support: Use current_module_str together with thread ID to distinguish between events in different processes
- Update all linux syscalls in the templates (filesystem, networking, processing) to improve the sandbox blocking of unknowns.
