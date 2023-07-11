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
    secimport is a comprehensive toolkit designed to enable the tracing, construction, and execution of secure Python runtimes. It leverages USDT probes and eBPF/DTrace technologies to enhance the overall security measures.\n
    https://github.com/avilum/secimport/wiki/Command-Line-Usage

    WORKFLOW:
            1. secimport trace / secimport shell
            2. secimport build
            3. secimport run

    QUICKSTART:
            $ secimport interactive

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
        output_json_file: str = "policy.json",
        output_yaml_file: str = "policy.yaml",
        output_syscalls_file: str = "syscalls.txt",
        nsjail_sandbox_file: str = "nsjail-seccomp-sandbox.sh",
        system_interpreter: str = sys.executable,
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
        syscalls = set()
        for line in lines:
            parsed_items = line.split(",")
            if parsed_items == 1:
                # General python import, interpreter dependency
                modules_and_syscalls["general_requirements"].append(parsed_items[0])
            elif len(parsed_items) == 2:
                # Module dependency
                _module, _syscall = parsed_items
                syscalls.add(_syscall)
                if not _module or _module == "None":  # empty string and None
                    _module = "general_requirements"
                modules_and_syscalls[_module].append(_syscall)
            else:
                raise Exception("there are more than 2 items in one of the lines.")

        # Creating a syscalls file
        _syscalls = list(sorted(list(syscalls)))
        syscalls_txt = ", ".join(_syscalls)
        nsjail_sandbox_cmd = f"nsjail -Ml -Mo  --chroot / --port 8000 --user 99999 --group 99999 --seccomp_string 'ALLOW {{ {syscalls_txt} }} DEFAULT KILL' -- {system_interpreter} -i"
        print(f"syscalls: {syscalls_txt}")
        print(f"nsjail sandbox: {nsjail_sandbox_cmd}")

        # Sandbox
        with open(output_syscalls_file, "w") as f:
            f.write(syscalls_txt)

        # NSJail
        with open(nsjail_sandbox_file, "w") as f:
            f.write(nsjail_sandbox_cmd)
        st = os.stat(nsjail_sandbox_file)
        os.chmod(nsjail_sandbox_file, st.st_mode | stat.S_IEXEC)

        # JSON
        modules_json = json.dumps(modules_and_syscalls, indent=4)
        with open(output_json_file, "w") as f:
            f.write(modules_json)

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
        print("Policy is ready: ", output_yaml_file, output_json_file)

        colored_print(COLORS.ENDC)
        return output_yaml_file, output_syscalls_file, nsjail_sandbox_file

    @staticmethod
    def compile_sandbox_from_profile(
        template_filename: str = "policy.yaml", sandbox_filename_prefix: str = "sandbox"
    ) -> str:
        """Generates a tailor-made sandbox that will enforce a given yaml profile/policy in runtime.

        2 scripts will be created in the same directory: one for the dscript backend and one for the bpftrace backend.
        Returns: The file name of the bpftrace sandbox (preferred).
            _type_: str
        """
        print(COLORS.WARNING)
        template_filename = Path(template_filename)
        dtrace_sandbox_filename = f"{sandbox_filename_prefix}.d"
        dtrace_rendered_profile = secimport.build_module_sandbox_from_yaml_template(
            template_path=template_filename,
            backend=secimport.InstrumentationBackend.DTRACE,
        )
        if not dtrace_rendered_profile:
            # empty file, error is already printed to the user
            raise AssertionError(
                f"The trace file '{template_filename}' has 0 modules. A valid policy should include at least 1 module."
            )

        with open(dtrace_sandbox_filename, "w") as f:
            f.write(dtrace_rendered_profile)

        st = os.stat(dtrace_sandbox_filename)
        os.chmod(dtrace_sandbox_filename, st.st_mode | stat.S_IEXEC)
        print("DTRACE sandbox:", dtrace_sandbox_filename)

        bpftrace_sandbox_filename = f"{sandbox_filename_prefix}.bt"
        bpftrace_rendered_profile = secimport.build_module_sandbox_from_yaml_template(
            template_path=template_filename,
            backend=secimport.InstrumentationBackend.EBPF,
        )

        with open(bpftrace_sandbox_filename, "w") as f:
            f.write(bpftrace_rendered_profile)
        st = os.stat(bpftrace_sandbox_filename)
        os.chmod(bpftrace_sandbox_filename, st.st_mode | stat.S_IEXEC)

        colored_print(COLORS.ENDC)
        return bpftrace_sandbox_filename

    @staticmethod
    def shell(*args, **kwargs):
        """Alternative syntax for secimport "trace"."""
        SecImportCLI.trace(*args, **kwargs)

    @staticmethod
    def trace(
        entrypoint: str = None,
        python_interpreter: str = sys.executable,
        trace_log_file: str = "trace.log",
    ):
        """Traces a python process using an entrypoint or interactive interpreter. It might require sudo privilleges on some hosts.
        Args:
            entrypoint (str, optional): A python script path to trace. If not specified, a python interactive shell will be opened in the foregraound. This shell, or the given command, will be traced and logged to the "trace_log_file" argument.
            python_interpreter (str, optional): The path of the python executable interpreter to trace. Defaults to sys.executable.
            trace_log_file (str, optional): The log file to write the trace into. Defaults to "trace.log".
        """
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
        colored_print(COLORS.HEADER, "\nTracing using ", cmd)
        colored_print(
            COLORS.BOLD,
            "Press CTRL+D or CTRL+C to stop the trace gracefully.\n",
        )
        os.system(" ".join(cmd))
        colored_print(
            COLORS.BOLD, "The trace log is at", COLORS.OKGREEN, f"./{trace_log_file}"
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
    def build(
        trace_file: str = "trace.log",
        output_json_file: str = "policy.json",
        output_yaml_file: str = "policy.yaml",
        output_syscalls_file: str = "syscalls.txt",
        destructive: bool = False,
    ) -> str:
        """Compiles a trace log (trace.log). Creates the sandbox executable (instrumentation script) for each supported backend
        It uses `create_profile_from_trace ...` and `sandbox_from_profile`.

        Raises:
            FileNotFoundError:

        Returns:
            _type_: str
        """
        (
            output_yaml_file,
            output_syscalls_file,
            nsjail_sandbox_file,
        ) = SecImportCLI.__create_profile_from_trace(
            trace_file=trace_file,
            output_json_file=output_json_file,
            output_yaml_file=output_yaml_file,
            output_syscalls_file=output_syscalls_file,
            destructive=destructive,
        )

        bpftrace_sandbox_filename = SecImportCLI.compile_sandbox_from_profile(
            template_filename=output_yaml_file
        )
        colored_print(COLORS.OKGREEN, f"syscalls: {COLORS.BOLD} {output_syscalls_file}")
        colored_print(
            COLORS.OKGREEN, f"nsjail sandbox: {COLORS.BOLD} {nsjail_sandbox_file}"
        )
        colored_print(
            COLORS.OKGREEN,
            f"secimport eBPF sandbox: {COLORS.BOLD} {bpftrace_sandbox_filename}",
        )

    @staticmethod
    def run(
        entrypoint: str = None,
        sandbox_executable: str = "./sandbox.bt",
        python_interpreter: str = sys.executable,
        pid=None,
        stop_on_violation=False,
        kill_on_violation=False,
        sandbox_logfile: str = None,
    ):
        """Run a python process inside the sandbox.

        Args:
            entrypoint (str, optional): A script entrypoint to trace explicitly. Defaults to None.
            sandbox_executable (str, optional): An executable sandbox file, generated by "secimport build". Defaults to "./sandbox.bt".
            python_interpreter (str, optional): The python interpreter to probe. Defaults to sys.executable.
            pid (_type_, optional): process id to trace. Defaults to None.
            stop_on_violation: (str, optional). If set to True, the sandbox will send SIGSTOP to the process and prevent the execution the syscall.
            kill_on_violation: (str, optional). If set to True, the sandbox will send SIGKILL to the process, and then the sandbox will exit.
            sandbox_logfile: (str, optional). Log the sandbox STDOUT to an explicit file, instead of the foreground STDOUT/STDERR.
        Raises:
            FileNotFoundError: _description_
            ValueError: _description_
        """
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
        colored_print(COLORS.BOLD, "Welcome to secimport!")
        colored_print(
            COLORS.OKBLUE,
            "1. A python code can be traced using",
            COLORS.OKGREEN,
            '"secimport trace"',
            COLORS.OKBLUE,
            "or using",
            COLORS.OKGREEN,
            '"secimport shell"',
            COLORS.OKBLUE,
            "\n 2. All the function calls and system calls will be recorded to",
            COLORS.OKGREEN,
            "./trace.log.\n",
        )
        start = input("Continue? (y): ") or "y"
        if start.lower() == "y":
            try:
                SecImportCLI.trace()
            except KeyboardInterrupt:
                ...

            colored_print(
                COLORS.OKBLUE,
                '\nRunning "secimport build"; it compiles ./trace.log which is the trace log to ./sandbox.bt',
            )
            SecImportCLI.build()

            colored_print(
                COLORS.OKBLUE,
                "\nNow, let's run the sandbox.\n1. Run the same commands as before. They should run without any problem.\n2. Do something new in the shell. For example, ",
                COLORS.BOLD,
                "run \"import os; os.system('ps'); and see how secimport detects it.\"",
            )
            run = input("\nContinue? (y): ") or "y"

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
