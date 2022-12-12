"""
Import python modules with bpftrace supervision.
Copyright (c) 2022 Avi Lumelsky
"""

import importlib
import os
from sys import executable as PYTHON_EXECUTABLE
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

TEMPLATES_DIR_NAME = SECIMPORT_ROOT / "backends" / "bpftrace_backend"


def create_bpftrace_script_for_module(
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
) -> Path:
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
        script_template = render_bpftrace_probe_for_module(
            module_name=module_name,
            destructive=destructive,
            templates_dir=templates_dir,
        )
        syscalls_filter = render_syscalls_filter(
            syscalls_list=syscalls_allowlist,
            allow=True,
            instrumentation_backend=InstrumentationBackend.EBPF,
            module_name=module_traced_name,
        )
        script_template = script_template.replace(
            "###SYSCALL_FILTER###", syscalls_filter
        )

    elif syscalls_blocklist is not None:
        # If we have a blocklist
        script_template = render_bpftrace_probe_for_module(
            module_name=module_name,
            destructive=destructive,
            templates_dir=templates_dir,
        )
        syscalls_filter = render_syscalls_filter(
            syscalls_list=syscalls_allowlist,
            allow=True,
            instrumentation_backend=InstrumentationBackend.EBPF,
            module_name=module_traced_name,
        )
        script_template = script_template.replace(
            "###SYSCALL_FILTER###", syscalls_filter
        )

    else:
        script_template = render_bpftrace_template(
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

    module_file_name = os.path.join(BASE_DIR_NAME, f"bpftrace_sandbox_{module_name}.bt")
    with open(module_file_name, "w") as module_file:
        module_file.write(script_template)

    # TODO: FIGURE OUT A WAY TO COMPILE WITHOUT EXECUTING - MSKING SURE THE GENERATION WORKED SYNTAX-WISE.
    return module_file_name


def run_bpftrace_script_for_module(
    module_name: str,
    allow_shells: bool,
    allow_networking: bool,
    log_python_calls: bool,
    log_syscalls: bool,
    log_network: bool,
    log_file_system: bool,
    destructive: bool,
    syscalls_allowlist: List[str],
    syscalls_blocklist: List[str],
    use_sudo: bool = False,
    templates_dir: Path = TEMPLATES_DIR_NAME,
):
    module_file_path = create_bpftrace_script_for_module(
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
    output_file = BASE_DIR_NAME / f"bpftrace_sandbox_{module_name}.log"
    current_pid = os.getpid()
    bpftrace_command = f'{"sudo " if use_sudo else ""} {module_file_path} --unsafe -q -p {current_pid} -o {output_file} &2>/dev/null'
    st = os.stat(module_file_path)
    os.chmod(module_file_path, st.st_mode | stat.S_IEXEC)
    print("(sandbox command): ", bpftrace_command)
    print()
    print("Waiting for bpftrace.... ")
    os.system(bpftrace_command)
    time.sleep(10)  # TODO: change to fd creation (event)
    return True


def render_bpftrace_template(
    module_traced_name: str,
    allow_shells: bool,
    allow_networking: bool,
    log_python_calls: bool,
    log_syscalls: bool,
    log_network: bool,
    log_file_system: bool,
    destructive: bool,
    templates_dir: Path = TEMPLATES_DIR_NAME,
    default_template_filename: str = "default.template.bt",
    interpreter_path: str = PYTHON_EXECUTABLE,
):
    script_template = open(
        templates_dir / default_template_filename,
        "r",
    ).read()

    # Updating the right binary to be probed by bpftrace
    script_template = script_template.replace(
        "###INTERPRETER_PATH###", interpreter_path
    )

    # PYTHON instrumentations
    code_syscall_entry = ""
    if log_python_calls is True:
        code_function_entry = open(
            templates_dir / "actions/log_python_module_entry.bt",
            "r",
        ).read()
        code_function_exit = open(
            templates_dir / "actions/log_python_module_exit.bt",
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
            templates_dir / "actions/log_syscall.bt",
            "r",
        ).read()
        code_syscall_entry += f"{_code};\n"

    if log_file_system is True:
        filter_fs_code = open(
            templates_dir / "filters/file_system.bt",
            "r",
        ).read()
        code_syscall_entry += f"{filter_fs_code}\n{{"
        action_log_file_system = open(
            templates_dir / "actions/log_file_system.bt",
            "r",
        ).read()
        code_syscall_entry += f"{action_log_file_system}}}\n"

    if allow_networking is False or log_network is True:
        filter_networking_code = open(
            templates_dir / "filters/networking.bt",
            "r",
        ).read()
        code_syscall_entry += f"{filter_networking_code}{{\n"

        if log_network is True:
            action_log_network = open(
                templates_dir / "actions/log_network.bt",
                "r",
            ).read()
            code_syscall_entry += f"{action_log_network}\n"

        if allow_networking is False:
            action_kill = open(
                templates_dir / "actions/kill_process.bt",
                "r",
            ).read()
            code_syscall_entry += f"{action_kill}\n"
        code_syscall_entry += "}\n"

    if allow_shells is False:
        filter_processes_code = open(
            templates_dir / "filters/processes.bt",
            "r",
        ).read()
        code_syscall_entry += f"{filter_processes_code}{{\n"
        action_kill_on_processing = open(
            templates_dir / "actions/kill_on_processing.bt",
            "r",
        ).read()
        code_syscall_entry += f"{action_kill_on_processing}}}\n"

    script_template = script_template.replace("###SYSCALL_ENTRY###", code_syscall_entry)
    script_template = script_template.replace("###MODULE_NAME###", module_traced_name)

    # Updating the destructive behavior
    script_template = script_template.replace(
        "###DESTRUCTIVE###", "1" if destructive else "0"
    )
    return script_template


def render_bpftrace_probe_for_module(
    module_name: str,
    destructive: bool,
    templates_dir: Path = TEMPLATES_DIR_NAME,
    interpreter_path: str = PYTHON_EXECUTABLE,
) -> str:
    # Loading the probe allowlist template
    probe_template = open(
        templates_dir / "probes/module_syscalls_allowlist_template.bt",
        "r",
    ).read()

    # Adding a probe filter for the specified python module
    supervision_filter = open(
        templates_dir / "filters/is_current_module_under_supervision.bt",
        "r",
    ).read()

    # Adding the action according to the 'destructive' flag:  kill if destructive, log otherwise
    supervision_action = ""
    if destructive is True:
        action_kill_process = open(
            templates_dir / "actions/kill_process.bt",
            "r",
        ).read()
        supervision_action = f"{{{action_kill_process}}}\n"
    else:
        action_log_syscall = open(
            templates_dir / "actions/log_syscall.bt",
            "r",
        ).read()
        supervision_action = f"{{{action_log_syscall}}}\n"

    # Updating the template with the filters, their actions, and module name
    probe_template = probe_template.replace(
        "###SUPERVISED_MODULES_FILTER###", supervision_filter
    )
    probe_template = probe_template.replace(
        "###SUPERVISED_MODULES_ACTION###", supervision_action
    )
    probe_template = probe_template.replace("###MODULE_NAME###", module_name)

    # Updating the destructive behavior
    probe_template = probe_template.replace(
        "###DESTRUCTIVE###", "1" if destructive else "0"
    )

    probe_template = probe_template.replace("###INTERPRETER_PATH###", interpreter_path)
    return probe_template
