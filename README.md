# secimport
![macOS](https://img.shields.io/badge/Platform-macOS-blue)
![Linux](https://img.shields.io/badge/Platform-Linux-blue)

[![Upload Python Package](https://github.com/avilum/secimport/actions/workflows/python-publish.yml/badge.svg)](https://github.com/avilum/secimport/actions/workflows/python-publish.yml)

<!-- ![](https://img.shields.io/badge/Test_Coverage-90%-blue) -->

## Module-Level Sandboxing for Python Applications

secimport is an eBPF-based security toolkit that enforces syscall restrictions per Python module, providing granular control over your application's security profile. Think of it as seccomp-bpf for Linux, but operating at the Python module level.

[<a href="https://star-history.com/#avilum/secimport&Date">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=avilum/secimport&type=Date&theme=dark" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=avilum/secimport&type=Date" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=avilum/secimport&type=Date" />
 </picture>
</a>](https://star-history.com/#avilum/secimport&Date)

## Key Features

- **Module-Level Security**: Define and enforce syscall restrictions per Python module
- **Automated Profiling**: Traces your application to create tailored security profiles
- **Multiple Enforcement Modes**: Log, stop, or kill processes on policy violations
- **Production Ready**: Negligible performance impact thanks to eBPF
- **Supply Chain Protection**: Mitigate risks from vulnerable dependencies

## Quick Start

### Using Docker (Recommended)

```bash
git clone https://github.com/avilum/secimport.git
cd secimport/docker
./build.sh && ./run.sh
```
Command line:
```
secimport --help

 Usage: python -m secimport.cli [OPTIONS] COMMAND [ARGS]...

 secimport is a comprehensive toolkit designed to enable the tracing, construction, and execution of secure Python runtimes. It leverages USDT probes and eBPF/DTrace technologies to enhance overall security measures.
 WORKFLOW:     1. secimport trace / secimport shell     2. secimport build     3. secimport run
 QUICKSTART:     $ secimport interactive
 For more details, please see https://github.com/avilum/secimport/wiki/Command-Line-Usage

╭─ Options ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --install-completion          Install completion for the current shell.                                                                                                                                                                                    │
│ --show-completion             Show completion for the current shell, to copy it or customize the installation.                                                                                                                                             │
│ --help                        Show this message and exit.                                                                                                                                                                                                  │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ trace         Trace a Python process using an entrypoint or interactive shell.                                                                                                                                                                             │
│ shell         Alias for 'trace'.                                                                                                                                                                                                                           │
│ trace-pid     Trace a running process by PID.                                                                                                                                                                                                              │
│ build         Build a sandbox profile from a trace log.                                                                                                                                                                                                    │
│ run           Run a Python process inside the sandbox.                                                                                                                                                                                                     │
│ interactive   Run secimport in interactive mode.                                                                                                                                                                                                           │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

## Creating Your First Sandbox

```bash
secimport interactive

# In the Python shell that opens:
>>> secimport trace   # Start tracing
>>> import requests   # Perform actions you want to profile
>>> # Press CTRL+D to stop tracing

>>> secimport build   # Build sandbox from trace
>>> secimport run     # Run with enforcement
```

## Advanced Usage

### Command Line Options

```bash
secimport trace              # Trace a new Python process
secimport trace_pid <PID>    # Trace an existing process
secimport build              # Build sandbox from trace
secimport run [options]      # Run with enforcement
```

### Enforcement Modes

```bash
# Stop on violation
secimport run --stop_on_violation=true

# Kill on violation
secimport run --kill_on_violation=true
```

### Python API

```python
import secimport

# Replace standard import with secure import
requests = secimport.secure_import('requests', allowed_syscalls=['open', 'read', ...])
```

## Manual Installation

1. Install Python with USDT probes:

   ```bash
   # Configure Python with --enable-dtrace
   # See detailed instructions in our wiki
   ```

2. Install a supported backend (eBPF or DTrace)

   ```bash
   # Ubuntu/Debian
   apt-get install bpftrace

   # For other platforms, see our Installation wiki
   ```

3. Install secimport
   ```bash
   pip install secimport
   ```

## seccomp-bpf support using nsjail

Beside the sandbox that secimport builds, <br>
The `secimport build` command creates an <a href="https://github.com/google/nsjail">nsjail</a> sandbox with seccomp profile for your traced code.<br> `nsjail` enables namespace sandboxing with seccomp on linux<br>
`secimport` automatically generates seccomp profiles to use with `nsjail` as executable bash script.
It can be used to limit the syscalls of the entire python process, as another layer of defence.

## Documentation

- [Installation Guide](https://github.com/avilum/secimport/wiki/Installation)
- [Command Line Usage](https://github.com/avilum/secimport/wiki/Command-Line-Usage)
- [API Reference](https://github.com/avilum/secimport/wiki/Python-API)
- [Example Sandboxes](https://github.com/avilum/secimport/wiki/Sandbox-Examples)

## Learn More

### Technical Resources

- https://www.oligo.security/
- [Talk: secimport at BSides](https://youtu.be/nRV0ulYMsxU?t=1257)
- Blog Posts:
  - [secimport + DTrace](https://infosecwriteups.com/sandboxing-python-modules-in-your-code-1e590d71fc26?source=friends_link&sk=5e9a2fa4d4921af0ec94f175f7ee49f9)
  - [secimport + eBPF + PyTorch](https://infosecwriteups.com/securing-pytorch-models-with-ebpf-7f75732b842d?source=friends_link&sk=14d8db403aaf66724a8a69b4dea24e12)
  - [secimport + eBPF + FastAPI](https://avi-lumelsky.medium.com/secure-fastapi-with-ebpf-724d4aef8d9e?source=friends_link&sk=b01a6b97ef09003b53cd52c479017b03)

## Contributing

We welcome contributions! See our [Contributing Guide](https://github.com/avilum/secimport/blob/master/docs/CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
