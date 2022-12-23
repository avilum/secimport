from collections import defaultdict
import json
import os
from pathlib import Path
import stat
import fire
import sys
import yaml
import secimport
from secimport.backends.common.utils import SECIMPORT_ROOT
from secimport.sandbox_helper import secure_import
import subprocess


class SecImportCLI:
    """Secure Import CLI"""

    @staticmethod
    def trace(
        python_interpreter: str = sys.executable,
        trace_log_file: str = "trace.log",
    ):
        print("To start a trace, please run the following command:")
        print(
            f"{SECIMPORT_ROOT}/profiles/trace.bt -c '{python_interpreter}' -o {trace_log_file}"
        )

    @staticmethod
    def trace_pid(
        pid: int,
        trace_log_file: str = "trace.log",
    ):
        """Traces a running process by pid. It might require sudo privilleges on some hosts.

        Args:
            pid (int): process pid to trace
            trace_log_file (str): The output file to write the trace into.
        """
        assert isinstance(pid, int), f"pid must be an int, got: {pid}"
        cmd = [
            SECIMPORT_ROOT + "/profiles/trace.bt",
            "-p",
            "{pid}",
            "-o",
            f"{trace_log_file}",
        ]
        print("Running trace command:")
        print("".join(cmd))
        process = subprocess.run(cmd)
        print(process)
        input("Press CTRL+D or CTRL+C to exit the trace...")

    @staticmethod
    def compile_sandbox(trace_file: str = "trace.log") -> str:
        """Converts a trace log into sandbox. It uses `secimport create_profile_from_trace ...` and `secimport sandbox_from_profile...` under the hood.

        Raises:
            FileNotFoundError:

        Returns:
            _type_: str
        """
        output_yaml_file = SecImportCLI.create_profile_from_trace(trace_file=trace_file)
        bpftrace_sandbox_filename = SecImportCLI.create_sandbox_from_profile(
            template_filename=output_yaml_file
        )
        return bpftrace_sandbox_filename

    @staticmethod
    def create_profile_from_trace(
        trace_file: str = "trace.log",
        output_json_file: str = "traced_modules.json",
        output_yaml_file: str = "traced_modules.yaml",
    ) -> str:
        """Creates a yaml policy file from a given trace log. default: "trace.log".

        After running this command, the yaml output file can be compiled into sandbox code using the 'sandbox_from_profile' command.
        """
        parse_cmd = f"""cat {trace_file} | grep -Po "\@modules_syscalls\[\K(.+?)]" | tr -d ']' | sort > traced_modules.log"""
        os.system(parse_cmd)
        modules_syscalls_file = Path("traced_modules.log")
        if not modules_syscalls_file.exists():
            raise FileNotFoundError(trace_file)
        with open(modules_syscalls_file, "r") as f:
            lines = f.read().splitlines()

        modules_and_syscalls = defaultdict(list)
        for line in lines:
            parsed_items = line.split(",")
            if parsed_items == 1:
                # General python import, interpreter dependency
                modules_and_syscalls["general_requirements"].append(_syscall)
            elif len(parsed_items) == 2:
                # Module dependency
                _module, _syscall = parsed_items
                if _module == "":
                    _module = "general_requirements"
                modules_and_syscalls[_module].append(_syscall)
            else:
                raise Exception("there are more than 2 items in one of the lines.")

        # JSON
        modules_json = json.dumps(modules_and_syscalls, indent=4)
        with open(output_json_file, "w") as f:
            f.write(modules_json)
        print("The JSON trace is ready at ", output_json_file)

        # Building the YAML template
        yaml_dict = {
            name: {
                "destructive": True,
                "syscall_allowlist": _syscalls,
            }
            for name, _syscalls in modules_and_syscalls.items()
        }
        yaml_dict = {"modules": yaml_dict}
        modules_yaml = yaml.safe_load(json.dumps(yaml_dict))
        modules_yaml = yaml.dump(modules_yaml)
        with open(output_yaml_file, "w") as f:
            f.write(modules_yaml)
        print("The YAML template is ready at ", output_yaml_file)
        return output_yaml_file

    @staticmethod
    def create_sandbox_from_profile(
        template_filename: str = "traced_modules.yaml",
    ) -> str:
        """Generates a tailor-made sandbox code for a given yaml profile.

        2 scripts will be created in the same directory: one for the dscript backend and one for the bpftrace backend.
        Returns: The file name of the bpftrace sandbox (preferred).
            _type_: str
        """
        print("Compiling template", template_filename)
        template_filename = Path(template_filename)
        dtrace_sandbox_filename = Path(template_filename).with_suffix(".d")
        dtrace_rendered_profile = secimport.build_module_sandbox_from_yaml_template(
            template_path=template_filename,
            backend=secimport.InstrumentationBackend.DTRACE,
        )
        with open(dtrace_sandbox_filename, "w") as f:
            f.write(dtrace_rendered_profile)
        st = os.stat(dtrace_sandbox_filename)
        os.chmod(dtrace_sandbox_filename, st.st_mode | stat.S_IEXEC)
        bpftrace_sandbox_filename = Path(template_filename).with_suffix(".bt")
        bpftrace_rendered_profile = secimport.build_module_sandbox_from_yaml_template(
            template_path=template_filename,
            backend=secimport.InstrumentationBackend.EBPF,
        )
        with open(bpftrace_sandbox_filename, "w") as f:
            f.write(bpftrace_rendered_profile)
        st = os.stat(bpftrace_sandbox_filename)
        os.chmod(bpftrace_sandbox_filename, st.st_mode | stat.S_IEXEC)

        print("The dtrace sandbox script is ready at ", dtrace_sandbox_filename)
        print("The bpftrace sandbox script is ready at ", bpftrace_sandbox_filename)
        print("Done.")
        return bpftrace_sandbox_filename

    @staticmethod
    def secure_import():
        """Run a secure import for a python module and then exit.
        A log will be automatically generated at /tmp/.secimport"""

        return fire.Fire(secure_import)


def main():
    fire.Fire(SecImportCLI)


if __name__ == "__main__":
    main()
