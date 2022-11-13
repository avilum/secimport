import os
from sys import platform
from pathlib import Path
from typing import List

from secimport.backends.common.instrumentation_backend import InstrumentationBackend


BASE_DIR_NAME = Path("/tmp/.secimport")
SECIMPORT_ROOT = Path(
    os.path.realpath(
        os.path.split(__file__)[:-1][0] + os.sep + os.pardir + os.sep + os.pardir
    )
)
DEFAULT_BACKEND = None

if "linux" in platform.lower():
    TEMPLATES_DIR_NAME = SECIMPORT_ROOT / "templates" / "bpftrace"
    DEFAULT_BACKEND = InstrumentationBackend.EBPF
    # TODO: verify bpftrace is installed, if not, link to the repo documentation on how to install.
else:
    TEMPLATES_DIR_NAME = SECIMPORT_ROOT / "templates" / "dtrace"
    DEFAULT_BACKEND = InstrumentationBackend.DTRACE

PROFILES_DIR_NAME = SECIMPORT_ROOT / "profiles"


def render_syscalls_filter(
    syscalls_list: List[str],
    allow: bool,
    instrumentation_backend: InstrumentationBackend,
):
    assert isinstance(allow, bool), '"allow" must be a bool value'
    # "=="" means the syscall matches (blocklist), while "!="" means allow only the following.
    match_sign = "!=" if allow else "=="
    syscalls_filter = ""
    for i, _syscall in enumerate(syscalls_list):
        if i > 0:
            syscalls_filter += " && "
        assert isinstance(
            _syscall, str
        ), f"The provided syscall it not a syscall string name: {_syscall}"

        if instrumentation_backend == InstrumentationBackend.DTRACE:
            syscalls_filter += f'probefunc {match_sign} "{_syscall}"'
        elif instrumentation_backend == InstrumentationBackend.EBPF:
            syscalls_filter += f'@sysname[args->id] {match_sign} "{_syscall}"'
        else:
            raise NotImplementedError(
                f"backend '{instrumentation_backend}' is not supported"
            )

        filter_name = "allowlist" if allow else "blocklist"
        print(f"Adding syscall {_syscall} to {filter_name}")
    return syscalls_filter
