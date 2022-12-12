"""
Import python modules with dtrace supervision.

Copyright (c) 2022 Avi Lumelsky
"""
import importlib
import importlib.machinery  # important for importlib to work for our use case
import os
import stat
import time
from pathlib import Path
from typing import List


from secimport.backends.common.instrumentation_backend import InstrumentationBackend
from secimport.backends.common.utils import (
    BASE_DIR_NAME,
    SECIMPORT_ROOT,
    render_syscalls_filter,
)

TEMPLATES_DIR_NAME = SECIMPORT_ROOT / "backends" / "dtrace_backend"
DEFAULT_BACKEND = InstrumentationBackend.DTRACE
PROFILES_DIR_NAME = SECIMPORT_ROOT / "profiles"


def run_dtrace_script_for_module(
    module_name: str,
    allow_shells: bool,
    allow_networking: bool,
    use_sudo: bool,
    log_python_calls: bool,
    log_syscalls: bool,
    log_network: bool,
    log_file_system: bool,
    destructive: bool,
    syscalls_allowlist: List[str],
    syscalls_blocklist: List[str],
    templates_dir: Path = TEMPLATES_DIR_NAME,
):
    module_file_path = create_dtrace_script_for_module(
        module_name=module_name,
        allow_shells=allow_shells,
        allow_networking=allow_networking,
        log_python_calls=log_python_calls,
        log_syscalls=log_syscalls,
        log_network=log_network,
        log_file_system=log_file_system,
        destructive=destructive,
        syscalls_allowlist=syscalls_allowlist,
        syscalls_blocklist=syscalls_blocklist,
        templates_dir=templates_dir,
    )
    output_file = BASE_DIR_NAME / f"dtrace_sandbox_{module_name}.log"
    current_pid = os.getpid()
    dtrace_command = f'{"sudo " if use_sudo else ""} dtrace -q -s {module_file_path} -p {current_pid} -o {output_file} &2>/dev/null'
    print("(running dtrace supervisor): ", dtrace_command)
    st = os.stat(module_file_path)
    os.chmod(module_file_path, st.st_mode | stat.S_IEXEC)
    os.system(dtrace_command)

    # TODO: wait for dtrace to start explicitly using an event/fd, not time based - although 2 seconds is more than enough.
    # TODO: add startup logs for dropped packets without python modules (until the first python enter takes place in the syscalls probe, the python module is null).
    time.sleep(2)
    return True


def create_dtrace_script_for_module(
    module_name: str,
    allow_shells: bool,
    allow_networking: bool,
    log_python_calls: bool,
    log_syscalls: bool,
    log_network: bool,
    log_file_system: bool,
    destructive: bool,
    syscalls_allowlist: List[str] = None,
    syscalls_blocklist: List[str] = None,
    templates_dir: Path = TEMPLATES_DIR_NAME,
) -> str:
    """
    # Template components available at the moment:
    # ###DESTRUCTIVE###
    # ###FUNCTION_ENTRY###
    # ###FUNCTION_EXIT###
    # ###SYSCALL_ENTRY###
    # ###MODULE_NAME###
    """

    module = importlib.machinery.PathFinder().find_spec(module_name)
    if module is None:
        raise ModuleNotFoundError(module_name)
    module_traced_name = module.origin  # e.g this.py

    assert not (
        syscalls_allowlist is not None and syscalls_blocklist is not None
    ), "Please specify either syscalls_allowlist OR syscalls_blocklist."

    # If we have an allowlist
    if syscalls_allowlist is not None:
        script_template = render_allowlist_template(
            syscalls_allowlist=syscalls_allowlist,
            templates_dir=templates_dir,
        )
    elif syscalls_blocklist is not None:
        script_template = render_blocklist_template(
            syscalls_blocklist=syscalls_blocklist, templates_dir=templates_dir
        )
    else:
        script_template = render_dscript_template(
            module_traced_name=module_traced_name,
            allow_shells=allow_shells,
            allow_networking=allow_networking,
            log_python_calls=log_python_calls,
            log_syscalls=log_syscalls,
            log_network=log_network,
            log_file_system=log_file_system,
            destructive=destructive,
            templates_dir=templates_dir,
        )

    # Creating a dscript file with the modified template
    if not os.path.exists(BASE_DIR_NAME):
        os.mkdir(BASE_DIR_NAME)

    module_file_name = os.path.join(BASE_DIR_NAME, f"dtrace_sandbox_{module_name}.d")
    with open(module_file_name, "w") as module_file:
        module_file.write(script_template)

    # Making sure the script compiles
    dtrace_compile_command = f"dtrace -s {module_file_name} -e"
    compile_exit_code = os.system(dtrace_compile_command)
    assert (
        compile_exit_code == 0
    ), f"Failed to compile the dtrace script at {module_file_name}"
    print("Successfully compiled dtrace profile: ", module_file_name)
    return module_file_name


def render_allowlist_template(
    syscalls_allowlist: List[str], templates_dir: Path = TEMPLATES_DIR_NAME
):
    print("Found syscall allowlist, ignoring other configurations")
    script_template = open(
        templates_dir / "default.allowlist.template.d",
        "r",
    ).read()
    syscalls_filter = render_syscalls_filter(
        syscalls_list=syscalls_allowlist,
        allow=True,
        instrumentation_backend=InstrumentationBackend.DTRACE,
    )
    script_template = script_template.replace("###SYSCALL_FILTER###", syscalls_filter)
    return script_template


def render_blocklist_template(
    syscalls_blocklist: List[str], templates_dir: Path = TEMPLATES_DIR_NAME
):
    print("Found syscall allowlist, ignoring other configurations")
    script_template = open(
        templates_dir / "default.allowlist.template.d",
        "r",
    ).read()
    syscalls_filter = render_syscalls_filter(
        syscalls_list=syscalls_blocklist,
        allow=False,
        instrumentation_backend=InstrumentationBackend.DTRACE,
    )
    script_template = script_template.replace("###SYSCALL_FILTER###", syscalls_filter)
    return script_template


def render_dscript_template(
    module_traced_name: str,
    allow_shells: bool,
    allow_networking: bool,
    log_python_calls: bool,
    log_syscalls: bool,
    log_network: bool,
    log_file_system: bool,
    destructive: bool,
    templates_dir: Path = TEMPLATES_DIR_NAME,
    default_template_filename: str = "default.template.d",
):
    script_template = open(
        templates_dir / default_template_filename,
        "r",
    ).read()

    if destructive is True:
        destructive = open(templates_dir / "headers/destructive.d", "r").read()
        script_template = script_template.replace("###DESTRUCTIVE###", destructive)
    else:
        script_template = script_template.replace("###DESTRUCTIVE###", "")

    # PYTHON instrumentations
    code_syscall_entry = ""
    if log_python_calls is True:
        code_function_entry = open(
            templates_dir / "actions/log_python_module_entry.d",
            "r",
        ).read()
        code_function_exit = open(
            templates_dir / "actions/log_python_module_exit.d",
            "r",
        ).read()
        script_template = script_template.replace(
            "###FUNCTION_ENTRY###", code_function_entry
        )
        script_template = script_template.replace(
            "###FUNCTION_EXIT###", code_function_exit
        )
    else:
        script_template = script_template.replace("###FUNCTION_ENTRY###", "")
        script_template = script_template.replace("###FUNCTION_EXIT###", "")

    # SYSCALLS instrumentations
    if log_syscalls is True:
        _code = open(
            templates_dir / "actions/log_syscall.d",
            "r",
        ).read()
        code_syscall_entry += f"{_code};\n"

    if log_file_system is True:
        filter_fs_code = open(
            templates_dir / "filters/file_system.d",
            "r",
        ).read()
        code_syscall_entry += f"{filter_fs_code}\n{{"
        action_log_file_system = open(
            templates_dir / "actions/log_file_system.d",
            "r",
        ).read()
        code_syscall_entry += f"{action_log_file_system}}}\n"

    if allow_networking is False or log_network is True:
        filter_networking_code = open(
            templates_dir / "filters/networking.d",
            "r",
        ).read()
        code_syscall_entry += f"{filter_networking_code}{{\n"

        if log_network is True:
            action_log_network = open(
                templates_dir / "actions/log_network.d",
                "r",
            ).read()
            code_syscall_entry += f"{action_log_network}\n"

        if allow_networking is False:
            action_kill = open(
                templates_dir / "actions/kill_process.d",
                "r",
            ).read()
            code_syscall_entry += f"{action_kill}\n"
        code_syscall_entry += "}\n"

    if allow_shells is False:
        filter_processes_code = open(
            templates_dir / "filters/processes.d",
            "r",
        ).read()
        code_syscall_entry += f"{filter_processes_code}{{\n"
        action_kill_on_processing = open(
            templates_dir / "actions/kill_on_processing.d",
            "r",
        ).read()
        code_syscall_entry += f"{action_kill_on_processing}}}\n"

    script_template = script_template.replace("###SYSCALL_ENTRY###", code_syscall_entry)
    script_template = script_template.replace("###MODULE_NAME###", module_traced_name)
    return script_template


def render_dtrace_probe_for_module(
    module_name: str,
    destructive: bool,
    syscalls_allowlist: List[str],
    templates_dir: Path = TEMPLATES_DIR_NAME,
) -> str:
    # Loading the probe allowlist template
    probe_template = open(
        templates_dir / "probes/module_syscalls_allowlist_template.d",
        "r",
    ).read()

    # Adding a syscalls filter
    syscalls_filter = render_syscalls_filter(
        syscalls_list=syscalls_allowlist,
        allow=True,
        instrumentation_backend=InstrumentationBackend.DTRACE,
    )
    probe_template = probe_template.replace("###SYSCALL_FILTER###", syscalls_filter)

    # Adding a probe filter for the specified python module
    supervision_filter = open(
        templates_dir / "filters/is_current_module_under_supervision.d",
        "r",
    ).read()

    # Adding the action according to the 'destructive' flag:  kill if destructive, log otherwise
    supervision_action = ""
    if destructive is True:
        action_kill_process = open(
            templates_dir / "actions/kill_process.d",
            "r",
        ).read()
        supervision_action = f"{{{action_kill_process}}}\n"
    else:
        action_log_syscall = open(
            templates_dir / "actions/log_syscall.d",
            "r",
        ).read()
        supervision_action = f"{{{action_log_syscall}}}\n"

    # Updating the template
    probe_template = probe_template.replace(
        "###SUPERVISED_MODULES_FILTER###", supervision_filter
    )
    probe_template = probe_template.replace(
        "###SUPERVISED_MODULES_ACTION###", supervision_action
    )
    probe_template = probe_template.replace("###MODULE_NAME###", module_name)
    return probe_template
