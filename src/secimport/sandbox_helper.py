import os
import imp
import time


def secure_import(
    module_name: str,
    allow_shells: bool = False,
    allow_networking: bool = False,
    allow_filesystem: bool = False,
    use_sudo=True,
):
    assert _run_dtrace_script_for_module(
        module_name=module_name,
        allow_shells=allow_shells,
        allow_networking=allow_networking,
        allow_filesystem=allow_filesystem,
        use_sudo=use_sudo,
    )
    _module = __import__(module_name)
    return _module


def _run_dtrace_script_for_module(
    module_name: str,
    allow_shells: bool,
    allow_networking: bool,
    allow_filesystem: bool,
    use_sudo: bool = True,
    log_syscalls=True,
    log_network=True,
    log_file_system=True,
):
    module_file_path = _create_dtrace_script_for_module(
        module_name=module_name,
        allow_shells=allow_shells,
        allow_networking=allow_networking,
        log_syscalls=True,
        log_network=True,
        log_file_system=True,
    )
    output_file = f"sandbox_{module_name}.log"
    current_pid = os.getpid()
    dtrace_command = f'{"sudo " if use_sudo else ""} dtrace -q -s {module_file_path} -p {current_pid} -o {output_file} &2>/dev/null'
    print("(running command): ", dtrace_command)
    os.system(dtrace_command)

    # TODO: wait for dtrace to start explicitly using an event, not time based.
    time.sleep(2)
    return True

    # TODO: add startup logs for dropped packets without python modules (until the first python enter takes place).
    # TODO: add sanity check or parsing with dtrace on the flight and assert before attaching probes


def _create_dtrace_script_for_module(
    module_name,
    allow_shells: bool,
    allow_networking: bool,
    log_syscalls=True,
    log_network=True,
    log_file_system=True,
) -> str:
    """
    # Template components:
    # ###FUNCTION_ENTRY###
    # ###FUNCTION_EXIT###
    # ###SYSCALL_ENTRY###
    """
    module_traced_name = os.path.split(imp.find_module(module_name)[1])[
        -1
    ]  # "e.g this.py

    # TODO: Change path of all scripts
    script_template = open(
        "/Users/avilumelsky/git/secimport/templates/default.template.d",
        "r",
    ).read()

    # Python instrumentations
    code_function_entry = open(
        "/Users/avilumelsky/git/secimport/templates/actions/log_python_module_entry.d",
        "r",
    ).read()
    code_function_exit = open(
        "/Users/avilumelsky/git/secimport/templates/actions/log_python_module_exit.d",
        "r",
    ).read()
    script_template = script_template.replace(
        "###FUNCTION_ENTRY###", code_function_entry
    )
    script_template = script_template.replace("###FUNCTION_EXIT###", code_function_exit)

    # syscall instrumentations
    code_syscall_entry = ""
    if log_syscalls is True:
        _code = open(
            "/Users/avilumelsky/git/secimport/templates/actions/log_syscall.d",
            "r",
        ).read()
        code_syscall_entry += f"{_code};\n"

    if log_file_system is True:
        filter_fs_code = open(
            "/Users/avilumelsky/git/secimport/templates/filters/file_system.d",
            "r",
        ).read()
        code_syscall_entry += f"{filter_fs_code}\n{{"
        action_log_file_system = open(
            "/Users/avilumelsky/git/secimport/templates/actions/log_file_system.d",
            "r",
        ).read()
        code_syscall_entry += f"{action_log_file_system}}}\n"

    if allow_networking is False or log_network is True:
        filter_networking_code = open(
            "/Users/avilumelsky/git/secimport/templates/filters/networking.d",
            "r",
        ).read()
        code_syscall_entry += f"{filter_networking_code}{{\n"
        action_log_network = open(
            "/Users/avilumelsky/git/secimport/templates/actions/log_network.d",
            "r",
        ).read()
        code_syscall_entry += f"{action_log_network}}}\n"

    if allow_shells is False:
        filter_processes_code = open(
            "/Users/avilumelsky/git/secimport/templates/filters/processes.d",
            "r",
        ).read()
        code_syscall_entry += f"{filter_processes_code}{{\n"
        action_kill_on_processing = open(
            "/Users/avilumelsky/git/secimport/templates/actions/kill_on_processing.d",
            "r",
        ).read()
        code_syscall_entry += f"{action_kill_on_processing}}}\n"

    script_template = script_template.replace("###SYSCALL_ENTRY###", code_syscall_entry)
    script_template = script_template.replace("###MODULE_NAME###", module_traced_name)
    with open(f".{module_name}-sandbox.d", "w") as module_file:
        module_file.write(script_template)
        return module_file.name


if __name__ == "__main__":
    print(_create_dtrace_script_for_module("this", allow_shells=True, allow_networking=True))
    # secure_import("this")
