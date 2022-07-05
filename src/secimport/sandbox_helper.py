import importlib
import os
import time

BASE_DIR_NAME = f"/tmp/.secimport"


def secure_import(
    module_name: str,
    allow_shells: bool = False,
    allow_networking: bool = False,
    use_sudo: bool = True,
    log_syscalls=True,
    log_network=True,
    log_file_system=True,
):
    assert run_dtrace_script_for_module(
        module_name=module_name,
        allow_shells=allow_shells,
        allow_networking=allow_networking,
        use_sudo=use_sudo,
        log_syscalls=log_syscalls,
        log_network=log_network,
        log_file_system=log_file_system,
    )
    _module = __import__(module_name)
    return _module


def run_dtrace_script_for_module(
    module_name: str,
    allow_shells: bool,
    allow_networking: bool,
    use_sudo: bool,
    log_syscalls: bool,
    log_network: bool,
    log_file_system: bool,
):
    module_file_path = create_dtrace_script_for_module(
        module_name=module_name,
        allow_shells=allow_shells,
        allow_networking=allow_networking,
        log_syscalls=log_syscalls,
        log_network=log_network,
        log_file_system=log_file_system,
    )
    output_file = os.path.join(BASE_DIR_NAME, f"sandbox_{module_name}.log")
    current_pid = os.getpid()
    dtrace_command = f'{"sudo " if use_sudo else ""} dtrace -q -s {module_file_path} -p {current_pid} -o {output_file} &2>/dev/null'
    print("(running dtrace supervisor): ", dtrace_command)
    os.system(dtrace_command)

    # TODO: wait for dtrace to start explicitly using an event/fd, not time based - although 2 seconds is more than enough.
    time.sleep(2)
    return True

    # TODO: add startup logs for dropped packets without python modules (until the first python enter takes place in the syscalls probe, the python module is null).
    # TODO: add sanity check or parsing with dtrace on the flight and assert before attaching probes


def create_dtrace_script_for_module(
    module_name,
    allow_shells: bool,
    allow_networking: bool,
    log_syscalls: bool,
    log_network: bool,
    log_file_system: bool,
) -> str:
    """
    # Template components available at the moment:
    # ###FUNCTION_ENTRY###
    # ###FUNCTION_EXIT###
    # ###SYSCALL_ENTRY###
    """

    module = importlib.machinery.PathFinder().find_spec(module_name)
    module_traced_name = os.path.split(module.origin)[-1]  # "e.g this.py

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
        if log_network is True:
            action_log_network = open(
                "/Users/avilumelsky/git/secimport/templates/actions/log_network.d",
                "r",
            ).read()
            code_syscall_entry += f"{action_log_network}\n"
        if allow_networking is False:
            action_kill = open(
                "/Users/avilumelsky/git/secimport/templates/actions/kill_process.d",
                "r",
            ).read()
            code_syscall_entry += f"{action_kill}\n"
        code_syscall_entry += "}\n"

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
    if not os.path.exists(BASE_DIR_NAME):
        os.mkdir(BASE_DIR_NAME)

    module_file_name = os.path.join(BASE_DIR_NAME, f"sandbox-{module_name}.d")
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
