"""
Import python modules with syscalls supervision.

Copyright (c) 2022 Avi Lumelsky
"""

import importlib.util
import sysconfig
from secimport.backends.common.instrumentation_backend import InstrumentationBackend
from secimport.backends.common.utils import DEFAULT_BACKEND

# Check if the python interpreter was built with DTrace support (static USDT)
HAS_STATIC_DTRACE = sysconfig.get_config_var("WITH_DTRACE") == 1

# Optional: stapsdt for dynamic USDT probes as a fallback
STAPSDT_AVAILABLE = importlib.util.find_spec("stapsdt") is not None

# Global singletons to prevent resource leakage
_GLOBAL_STAPS_PROVIDER = None
_GLOBAL_ENTRY_PROBE = None


def _get_staps_probe():
    """Returns a singleton USDT probe if static DTrace is missing and stapsdt is available."""
    global _GLOBAL_STAPS_PROVIDER, _GLOBAL_ENTRY_PROBE

    # Only use stapsdt if static DTrace is NOT supported by the interpreter
    if not HAS_STATIC_DTRACE and STAPSDT_AVAILABLE and _GLOBAL_STAPS_PROVIDER is None:
        import stapsdt

        # To follow the principle of minimum change, we use the standard "python" provider name.
        # This makes the dynamic probe a drop-in replacement for the missing static probe.
        _GLOBAL_STAPS_PROVIDER = stapsdt.Provider("python")

        # We also use the standard "function__entry" probe name that secimport already expects.
        _GLOBAL_ENTRY_PROBE = _GLOBAL_STAPS_PROVIDER.add_probe(
            "function__entry", stapsdt.ArgTypes.uint64
        )
        _GLOBAL_STAPS_PROVIDER.load()
    return _GLOBAL_ENTRY_PROBE


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
    backend=DEFAULT_BACKEND,
    **kwargs,
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
    Returns:
        _type_: A Python Module. The module is supervised by the selected instrumentation backend (dtrace/ebpf) with destructive capabilities unless the 'destructive' argument is set to False.
    """

    # Get the dynamic probe (will only be initialized if static DTrace is missing)
    _entry_probe = _get_staps_probe()

    if backend == InstrumentationBackend.EBPF:
        from secimport.backends.bpftrace_backend.bpftrace_backend import (
            run_bpftrace_script_for_module,
        )

        # Replaced assert with explicit check to prevent bypassing security when python is run with optimization (-O)
        if not run_bpftrace_script_for_module(
            module_name=module_name,
            allow_shells=allow_shells,
            allow_networking=allow_networking,
            use_sudo=use_sudo,
            log_python_calls=log_python_calls,
            log_syscalls=log_syscalls,
            log_network=log_network,
            log_file_system=log_file_system,
            destructive=destructive,
        ):
            raise RuntimeError(
                f"Failed to start eBPF instrumentation for module '{module_name}'"
            )
    elif backend == InstrumentationBackend.DTRACE:
        from secimport.backends.dtrace_backend.dtrace_backend import (
            run_dtrace_script_for_module,
        )

        # Replaced assert with explicit check to ensure the instrumentation is active before importing
        if not run_dtrace_script_for_module(
            module_name=module_name,
            allow_shells=allow_shells,
            allow_networking=allow_networking,
            use_sudo=use_sudo,
            log_python_calls=log_python_calls,
            log_syscalls=log_syscalls,
            log_network=log_network,
            log_file_system=log_file_system,
            destructive=destructive,
        ):
            raise RuntimeError(
                f"Failed to start DTrace instrumentation for module '{module_name}'"
            )
    else:
        raise NotImplementedError(f"backend '{backend}' is not implemented.")

    # Fire the dynamic probe before import (if applicable)
    if _entry_probe:
        _entry_probe.fire(module_name)

    _module = __import__(module_name, **kwargs)
    return _module
