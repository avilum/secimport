import os
import imp
import time

def secure_import(
    module_name: str,
    allow_shells: bool = False,
    allow_networking: bool = False,
    allow_filesystem: bool = False,
    use_sudo=True
):
    module_traced_name = os.path.split(imp.find_module(module_name)[1])[-1]
    # "example.py"
    assert _run_dtrace_script_for_module(
        module_name=module_name,
        allow_shells=allow_shells,
        module_traced_name=module_traced_name,
        allow_networking=allow_networking,
        allow_filesystem=allow_filesystem,
        use_sudo=use_sudo
    )
    _module = __import__(module_name)
    return _module


def _run_dtrace_script_for_module(
    module_name: str,
    module_traced_name,
    allow_shells: bool,
    allow_networking: bool,
    allow_filesystem: bool,
    use_sudo: bool = True
):
    if allow_shells is True:
        return True

    script_template = open(
        "/Users/avilumelsky/git/secimport/templates/py_sandbox_template.d",
        "r",
    ).read()
    output_file = f"sandbox_{module_name}.log"
    script_template = script_template.replace("###MODULE_NAME###", module_traced_name)
    with open(f"/tmp/.{module_name}-sandbox.d", "w+") as module_file:
        module_file.write(script_template)

    current_pid = os.getpid()
    module_file_path = module_file.name
    # os.system(f"cat {module_file_path}")
    dtrace_command = f'{"sudo " if use_sudo else ""} dtrace -q -s {module_file_path} -p {current_pid} -o {output_file} &2>/dev/null'
    print("(running command): ", dtrace_command)
    os.system(dtrace_command)

    # TODO: wait for dtrace to start explicitly, not time based.
    time.sleep(2)
    return True

    # TODO: add startup logs for dropped packets without python modules (until the first python enter takes place).
    # TODO: add sanity check or parsing with dtrace on the flight and assert before attaching probes


if __name__ == "__main__":
    secure_import("this")
