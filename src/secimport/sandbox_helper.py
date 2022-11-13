"""
Import python modules with syscalls supervision.

Copyright (c) 2022 Avi Lumelsky
"""

from typing import List
from secimport.backends.common.instrumentation_backend import InstrumentationBackend
from secimport.backends.common.utils import DEFAULT_BACKEND
from secimport.backends.bpftrace_backend.bpftrace_backend import (
    run_bpftrace_script_for_module,
)
from secimport.backends.dtrace_backend.dtrace_backend import (
    run_dtrace_script_for_module,
)


def secure_import(
    module_name: str,
    allow_shells: bool = False,
    allow_networking: bool = False,
    use_sudo: bool = False,
    log_python_calls: bool = False,  # When True, the log file might reach GB in seconds.
    log_syscalls: bool = False,
    log_network: bool = False,
    log_file_system: bool = False,
    destructive: bool = True,
    syscalls_allowlist: List[str] = None,
    syscalls_blocklist: List[str] = None,
    backend=DEFAULT_BACKEND,
):
    """Import a python module in confined settings.

    Args:
        module_name (str): The name of the module to import. The same way you would have used an 'import' statement.
        allow_shells (bool, optional): Whether to allow forking/spwning shells and execute commands.
        allow_networking (bool, optional): Whether to allow socket syscalls.
        use_sudo (bool, optional): Whether to run dtrace with sudo. Can be turned off if sudo is not installed.
        log_python_calls (bool, optional): Whether to log the call tree of the python stack - function entry and exit events.
        log_network (bool, optional): Whether to log network successful connections - e.g socket syscalls.
        log_file_system (bool, optional): Whether to log filesystem calls - e.g read, open, write, etc.
        destructive (bool, optional): Whether to kill the process with -9 sigkill upon violation of any of the configurations above.
        syscalls_allowlist (list, optional): A list of allowed syscalls for the module. Any other syscall will result in destructive behavior (see description above).
        syscalls_blocklist (list, optional): A list of syscalls to block for the module. Any of the specified syscalls under this module will result in destructive behavior (see description above).
    Returns:
        _type_: A Python Module. The module is supervised by a dtrace process with destructive capabilities unless the 'destructive' argument is set to False.
    """

    if backend == InstrumentationBackend.EBPF:
        assert run_bpftrace_script_for_module(
            module_name=module_name,
            allow_shells=allow_shells,
            allow_networking=allow_networking,
            use_sudo=use_sudo,
            log_python_calls=log_python_calls,
            log_syscalls=log_syscalls,
            log_network=log_network,
            log_file_system=log_file_system,
            destructive=destructive,
            syscalls_allowlist=syscalls_allowlist,
            syscalls_blocklist=syscalls_blocklist,
        )
    elif backend == InstrumentationBackend.DTRACE:
        assert run_dtrace_script_for_module(
            module_name=module_name,
            allow_shells=allow_shells,
            allow_networking=allow_networking,
            use_sudo=use_sudo,
            log_python_calls=log_python_calls,
            log_syscalls=log_syscalls,
            log_network=log_network,
            log_file_system=log_file_system,
            destructive=destructive,
            syscalls_allowlist=syscalls_allowlist,
            syscalls_blocklist=syscalls_blocklist,
        )
    else:
        raise NotImplementedError(f"backend '{backend}' is not implemented.")

    _module = __import__(module_name)
    return _module
