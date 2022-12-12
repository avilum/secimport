import os
from sys import platform
from pathlib import Path
from typing import List
import importlib
from sys import executable as PYTHON_EXECUTABLE

from secimport.backends.common.instrumentation_backend import InstrumentationBackend

BASE_DIR_NAME = Path("/tmp/.secimport")
SECIMPORT_ROOT = Path(
    os.path.realpath(
        os.path.split(__file__)[:-1][0] + os.sep + os.pardir + os.sep + os.pardir
    )
)

PROFILES_DIR_NAME = SECIMPORT_ROOT / "profiles"
BPFTRACE_TEMPLATES_DIR_NAME = SECIMPORT_ROOT / "backends" / "bpftrace_backend"
DTRACE_TEMPLATES_DIR_NAME = SECIMPORT_ROOT / "backends" / "dtrace_backend"
TEMPLATES_DIR_NAME = None
DEFAULT_BACKEND = None

if "linux" in platform.lower():
    TEMPLATES_DIR_NAME = BPFTRACE_TEMPLATES_DIR_NAME
    DEFAULT_BACKEND = InstrumentationBackend.EBPF
    # TODO: verify bpftrace is installed, if not, link to the repo documentation on how to install.
else:
    TEMPLATES_DIR_NAME = DTRACE_TEMPLATES_DIR_NAME
    DEFAULT_BACKEND = InstrumentationBackend.DTRACE


def render_syscalls_filter(
    syscalls_list: List[str],
    allow: bool,
    instrumentation_backend: InstrumentationBackend,
    module_name=None,
):
    assert isinstance(allow, bool), '"allow" must be a bool value'
    # "=="" means the syscall matches (blocklist), while "!="" means allow only the following.
    match_sign = "!=" if allow else "=="
    syscalls_filter = ""
    for i, _syscall in enumerate(syscalls_list):
        if i > 0:
            if instrumentation_backend == InstrumentationBackend.DTRACE:
                syscalls_filter += " && "
        assert isinstance(
            _syscall, str
        ), f"The provided syscall it not a syscall string name: {_syscall}"

        if instrumentation_backend == InstrumentationBackend.DTRACE:
            if module_name is not None:
                raise NotImplementedError(
                    "Specific modules syscalls are not allowed using render_syscall_filter. Please use YAML template instead."
                )
            syscalls_filter += f'probefunc {match_sign} "{_syscall}"'
        elif instrumentation_backend == InstrumentationBackend.EBPF:
            # We denote 1 as 'allow' and 0 as 'deny', 0 being the deafult or unset.
            expected_output_value = "1" if allow else "2"
            # strncmp returns 0 if it is a match
            # syscalls_filter += f'(strncmp(@sysname[args->id],  "{_syscall}", 24) {expected_output_value})'
            _module_name = (
                f'"{module_name}"'
                if module_name is not None
                else '@globals["current_module"]'
            )
            syscalls_filter += f"@syscalls_filters[{_module_name}, \"{_syscall}\"] = {expected_output_value};"
            syscalls_filter += "\n\t"
        else:
            raise NotImplementedError(
                f"backend '{instrumentation_backend}' is not supported"
            )

        filter_name = "allowlist" if allow else "blocklist"
        print(f"Adding syscall {_syscall} to {filter_name} for module {module_name}")
    return syscalls_filter


def build_module_sandbox_from_yaml_template(
    template_path: Path,
    backend: InstrumentationBackend = DEFAULT_BACKEND,
):
    """Generates sandbox code for secure imports based on a YAML configuration.

    Args:
        template_path (Path): The path to the YAML file, describing the policies.
        templates_dir (Path, optional): The directory of the templates. Defaults to TEMPLATES_DIR_NAME.

    Raises:
        ModuleNotFoundError:

    Returns:
        _type_: str
    """
    assert Path(
        template_path
    ).exists(), f"The template does not exist at {template_path}"
    import yaml

    safe_yaml = yaml.safe_load(open(template_path, "r").read())
    parsed_probes = []
    syscalls_filter = ""
    for module_name, module_config in safe_yaml.get("modules", {}).items():
        # Finding the module without loading
        module = importlib.machinery.PathFinder().find_spec(module_name)
        if module is None:
            msg = f"Warning: {module_name} is not present in the current environment. It is required in order to generate a sandbox with correct a import name."
            # raise ModuleNotFoundError(msg)

        # Tracing module entrypoint
        module_traced_name = module.origin if module is not None else module_name
        # module_traced_name = os.path.split(module_traced_name)[:-1][0]

        _destructive = module_config.get("destructive")
        assert isinstance(_destructive, bool), ValueError(
            f'The "destructive" field for module {module_name} is empty.'
        )

        _syscall_allowlist = module_config.get("syscall_allowlist")
        assert _syscall_allowlist, ValueError(
            f'The "syscall_allowlist" for module {module_name} is empty.'
        )
        for _ in _syscall_allowlist:
            assert isinstance(_, str), ValueError(
                f'The "syscall_allowlist" field for module {module_name} contains invalid string: {_}'
            )

        if backend == InstrumentationBackend.DTRACE:
            from secimport.backends.dtrace_backend.dtrace_backend import (
                render_dtrace_probe_for_module,
            )

            module_sandbox_probe = render_dtrace_probe_for_module(
                module_name=module_traced_name,
                destructive=_destructive,
                syscalls_allowlist=_syscall_allowlist,
            )
            sandbox_file_name = f"default.yaml.template.d"
            script_template = open(
                DTRACE_TEMPLATES_DIR_NAME / sandbox_file_name,
                "r",
            ).read()
        elif backend == InstrumentationBackend.EBPF:
            from secimport.backends.bpftrace_backend.bpftrace_backend import (
                render_bpftrace_probe_for_module,
            )

            module_sandbox_probe = render_bpftrace_probe_for_module(
                module_name=module_traced_name,
                destructive=_destructive,
            )
            # Adding a syscalls filter
            syscalls_filter += render_syscalls_filter(
                syscalls_list=_syscall_allowlist,
                allow=True,
                instrumentation_backend=InstrumentationBackend.EBPF,
                module_name=module_traced_name,
            )
            sandbox_file_name = f"default.yaml.template.bt"
            script_template = open(
                BPFTRACE_TEMPLATES_DIR_NAME / sandbox_file_name,
                "r",
            ).read()
        assert module_sandbox_probe, ValueError(
            f"Failed to create a probe for module {module_name}"
        )
        parsed_probes.append(module_sandbox_probe)

    if not parsed_probes:
        print(f"The profile does not contain any modules: {template_path}")
        return
    script_template = script_template.replace("###SYSCALL_FILTER###", syscalls_filter)
    script_template = script_template.replace(
        "###INTERPRETER_PATH###", PYTHON_EXECUTABLE
    )
    probes_code = ("\n" * 2).join(parsed_probes)
    script_template = script_template.replace(
        "###SUPERVISED_MODULES_PROBES###", probes_code
    )
    return script_template
