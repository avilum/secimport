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


class COLORS:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def colored_print(color, *args):
    print(color, *args, COLORS.ENDC)


class SecImportCLI:
    """
    SecImport - A toolkit for Tracing and Securing Python Runtime using USDT probes and eBPF/DTrace: https://github.com/avilum/secimport/wiki/Command-Line-Usage

    QUICK START:
            >>> secimport interactive

    EXAMPLES:
        1. trace:
            $  secimport trace
            $  secimport trace -h
            $  secimport trace_pid 123
            $  secimport trace_pid -h
        2. build:
            # secimport build
            $ secimport build -h
        3. run:
            $  secimport run
            $  secimport run --entrypoint my_custom_main.py
            $  secimport run --entrypoint my_custom_main.py --stop_on_violation=true
            $  secimport run --entrypoint my_custom_main.py --kill_on_violation=true
            $  secimport run --sandbox_executable /path/to/my_sandbox.bt --pid 2884
            $  secimport run --sandbox_executable /path/to/my_sandbox.bt --sandbox_logfile my_log.log
            $  secimport run -h
    """

    @staticmethod
    def __create_profile_from_trace(
        trace_file: str = "trace.log",
        output_json_file: str = "sandbox.json",
        output_yaml_file: str = "sandbox.yaml",
        destructive: bool = True,
    ) -> str:
        """Creates a yaml policy file from a given trace log. default: "trace.log".

        After running this command, the yaml output file can be compiled into sandbox code using the 'sandbox_from_profile' command.
        """
        print(COLORS.WARNING)
        if not Path(trace_file).exists:
            raise FileNotFoundError(trace_file)

        parse_cmd = f"""cat {trace_file} | grep -Po "\@modules_syscalls\[\K(.+?)]" | tr -d ']' | sort > sandbox.log"""
        os.system(parse_cmd)
        modules_syscalls_file = Path("sandbox.log")
        if not modules_syscalls_file.exists():
            raise FileNotFoundError(trace_file)
        with open(modules_syscalls_file, "r") as f:
            lines = f.read().splitlines()

        modules_and_syscalls = defaultdict(list)
        for line in lines:
            parsed_items = line.split(",")
            if parsed_items == 1:
                # General python import, interpreter dependency
                modules_and_syscalls["general_requirements"].append(parsed_items[0])
            elif len(parsed_items) == 2:
                # Module dependency
                _module, _syscall = parsed_items
                if not _module or _module == "None":  # empty string and None
                    _module = "general_requirements"
                modules_and_syscalls[_module].append(_syscall)
            else:
                raise Exception("there are more than 2 items in one of the lines.")

        # JSON
        modules_json = json.dumps(modules_and_syscalls, indent=4)
        with open(output_json_file, "w") as f:
            f.write(modules_json)
        print("CREATED JSON TEMPLATE: ", output_json_file)

        # Building the YAML template
        yaml_dict = {
            name: {
                "destructive": destructive,
                "syscall_allowlist": _syscalls,
            }
            for name, _syscalls in modules_and_syscalls.items()
        }
        yaml_dict = {"modules": yaml_dict}
        modules_yaml = yaml.safe_load(json.dumps(yaml_dict))
        modules_yaml = yaml.dump(modules_yaml)
        with open(output_yaml_file, "w") as f:
            f.write(modules_yaml)
        print("CREATED YAML TEMPLATE: ", output_yaml_file)

        colored_print(COLORS.ENDC)
        return output_yaml_file

    @staticmethod
    def __create_sandbox_from_profile(
        template_filename: str = "sandbox.yaml",
    ) -> str:
        """Generates a tailor-made sandbox code for a given yaml profile.

        2 scripts will be created in the same directory: one for the dscript backend and one for the bpftrace backend.
        Returns: The file name of the bpftrace sandbox (preferred).
            _type_: str
        """
        print(COLORS.WARNING)
        print("compiling template", template_filename)
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
        print("\nDTRACE SANDBOX: ", dtrace_sandbox_filename)
        print("BPFTRCE SANDBOX: ", bpftrace_sandbox_filename)
        colored_print(COLORS.ENDC)
        return bpftrace_sandbox_filename

    @staticmethod
    def trace(
        entrypoint: str = None,
        python_interpreter: str = sys.executable,
        trace_log_file: str = "trace.log",
    ):
        """Traces
        Args:
            entrypoint (str, optional): A python script path to trace. If not specified, a python interactive shell will be opened in the foregraound. This shell, or the given command, will be traced and logged to the "trace_log_file" argument.
            python_interpreter (str, optional): The path of the python executable interpreter to trace. Defaults to sys.executable.
            trace_log_file (str, optional): The log file to write the trace into. Defaults to "trace.log".
        """
        colored_print(COLORS.OKGREEN, ">>> secimport trace")
        if entrypoint:
            # entrypoint_cmd = str(Path(entrypoint).absolute())
            entrypoint_cmd = f'bash -c "{python_interpreter} {entrypoint}"'
        else:
            entrypoint_cmd = python_interpreter
        cmd = [
            f"{SECIMPORT_ROOT}/profiles/trace.bt",
            "-c",
            f"{entrypoint_cmd}",
            "-o",
            f"{trace_log_file}",
        ]
        colored_print(COLORS.HEADER, "\nTRACING:", cmd)
        colored_print(COLORS.BOLD, "\n\t\t\tPress CTRL+D/CTRL+C to stop the trace;\n")
        os.system(" ".join(cmd))
        colored_print(COLORS.BOLD, "TRACING DONE;")

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
        colored_print(COLORS.OKGREEN, ">>> secimport trace_pid")
        assert isinstance(pid, int), f"pid must be an int, got: {pid}"
        cmd = [
            str(SECIMPORT_ROOT) + "/profiles/trace.bt",
            "-p",
            f"{pid}",
            "-o",
            f"{trace_log_file}",
        ]
        colored_print(COLORS.HEADER, "\nTRACING PID:")
        colored_print(COLORS.OKBLUE, pid)
        input("\t\t\tPress CTRL+D/CTRL+C to stop the trace;")
        os.system(" ".join(cmd))
        colored_print(COLORS.ENDC)

    @staticmethod
    def build(trace_file: str = "trace.log") -> str:
        colored_print(COLORS.OKGREEN, ">>> secimport build")
        """Converts a trace log into an executable sandbox.
        It uses `secimport create_profile_from_trace ...` and `secimport sandbox_from_profile...` under the hood.

        Raises:
            FileNotFoundError:

        Returns:
            _type_: str
        """
        colored_print(COLORS.BOLD, "\nSECIMPORT COMPILING...")
        output_yaml_file = SecImportCLI.__create_profile_from_trace(
            trace_file=trace_file
        )
        bpftrace_sandbox_filename = SecImportCLI.__create_sandbox_from_profile(
            template_filename=output_yaml_file
        )
        colored_print(COLORS.BOLD, f"SANDBOX READY: {bpftrace_sandbox_filename}")

    @staticmethod
    def run(
        sandbox_executable: str = "./sandbox.bt",
        python_interpreter: str = sys.executable,
        entrypoint: str = None,
        pid=None,
        stop_on_violation=False,
        kill_on_violation=False,
        sandbox_logfile: str = None,
    ):
        """Run a python process inside the sandbox.

        Args:
            sandbox_executable (str, optional): An executable sandbox file, generated by "secimport build". Defaults to "./sandbox.bt".
            python_interpreter (str, optional): The python interpreter to probe. Defaults to sys.executable.
            entrypoint (str, optional): A script entrypoint to trace explicitly. Defaults to None.
            pid (_type_, optional): process id to trace. Defaults to None.
            stop_on_violation: (str, optional). If set to True, the sandbox will send SIGSTOP to the process and prevent the execution the syscall.
            kill_on_violation: (str, optional). If set to True, the sandbox will send SIGKILL to the process, and then the sandbox will exit.
            sandbox_logfile: (str, optional). Log the sandbox STDOUT to an explicit file, instead of the foreground STDOUT/STDERR.
        Raises:
            FileNotFoundError: _description_
            ValueError: _description_
        """
        colored_print(COLORS.OKGREEN, ">>> secimport run")
        if not Path(sandbox_executable).exists:
            raise FileNotFoundError(
                "The sandbox was not found. Try calling 'secimport trace/trace_pid' and then 'secimport compile_sandbox'"
            )
        sandbox_startup_cmd = [f"{sandbox_executable}", "--unsafe"]
        if pid is not None:
            sandbox_startup_cmd += [f" -p {pid}"]
        elif python_interpreter is not None:
            if entrypoint:
                sandbox_startup_cmd += [
                    " -c ",
                    f'bash -c "{python_interpreter} {entrypoint}"',
                ]
            else:
                sandbox_startup_cmd += [" -c ", f"{python_interpreter}"]
        else:
            raise ValueError("Please specify one of the following: entrypoint / pid")
        if sandbox_logfile:
            sandbox_startup_cmd += [" -o sandbox.log"]

        # Passing the policy as bpftrace program arguments (They used as $1, $2, ...)
        assert not (
            stop_on_violation and kill_on_violation
        ), "Please specify only one of the following flags: `--stop_on_violation`, `--kill_on_violation`"
        if stop_on_violation:
            print(
                "[WARNING]: This sandbox will send SIGSTOP to the program upon violation."
            )
            sandbox_startup_cmd.append("STOP")
        elif kill_on_violation:
            print(
                "[WARNING]: This sandbox will send SIGKILL to the program upon violation."
            )
            sandbox_startup_cmd.append("KILL")

        colored_print(COLORS.HEADER, "RUNNING SANDBOX...", sandbox_startup_cmd)
        os.system(" ".join(sandbox_startup_cmd))
        colored_print(
            COLORS.BOLD,
            "SANDBOX EXITED;",
            f"Log file: {sandbox_logfile};" if sandbox_logfile else "",
        )

    @staticmethod
    def interactive():
        colored_print(
            COLORS.OKBLUE,
            "\nLet's create our first tailor-made sandbox with secimport!\n- A python shell will be opened\n- The behavior will be recorded.\n",
        )
        start = input("OK? (y): ") or "y"
        if start.lower() == "y":
            try:
                SecImportCLI.trace()
            except KeyboardInterrupt:
                ...

            SecImportCLI.build()

            colored_print(
                COLORS.OKBLUE,
                '\nNow, let\'s run the sandbox.\n- Run the same commands as before, they should run without any problem;.\n- Do something new in the shell; e.g:\t>>> __import__("os").system("ps")',
            )
            run = input("\n\tOK? (y): ") or "y"

            if run.lower() == "y":
                SecImportCLI.run()
        else:
            colored_print(
                COLORS.OKBLUE,
                run,
                "Please type 'y' to start and follow the instructions; The docs are at https://github.com/avilum/secimport/wiki/Command-Line-Usage",
            )
        colored_print(COLORS.ENDC)


def main():
    import atexit

    atexit.register(lambda: colored_print(COLORS.ENDC))
    fire.Fire(SecImportCLI())


if __name__ == "__main__":
    main()
