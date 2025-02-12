#!/usr/bin/env python3
from collections import defaultdict
import json
import os
from pathlib import Path
import stat
import sys
import yaml
import subprocess
import typer
import secimport
from secimport.backends.common.utils import SECIMPORT_ROOT
from typing import Optional

app = typer.Typer(help="""\
secimport is a comprehensive toolkit designed to enable the tracing, construction, and execution of secure Python runtimes.
It leverages USDT probes and eBPF/DTrace technologies to enhance overall security measures.

WORKFLOW:
    1. secimport trace / secimport shell
    2. secimport build
    3. secimport run

QUICKSTART:
    $ secimport interactive

For more details, please see https://github.com/avilum/secimport/wiki/Command-Line-Usage
""")

# Terminal colors and utility printing
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
    Contains the implementation for the secimport commands.
    See the individual methods for details.
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
        """Creates a YAML policy file from a given trace log.
        
        The YAML output file can later be compiled into a sandbox executable.
        """
        print(COLORS.WARNING)
        if not Path(trace_file).exists():
            raise FileNotFoundError(trace_file)

        parse_cmd = (
            f"cat {trace_file} | grep -Po \"\\@modules_syscalls\\[\\K(.+?)]\" | tr -d ']' | sort > sandbox.log"
        )
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
            if len(parsed_items) == 1:
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
                raise Exception("There are more than 2 items in one of the lines.")

        # Create syscalls file
        _syscalls = sorted(list(syscalls))
        syscalls_txt = ", ".join(_syscalls)
        nsjail_sandbox_cmd = (
            f"nsjail -Ml -Mo --chroot / --port 8000 --user 99999 --group 99999 "
            f"--seccomp_string 'ALLOW {{ {_syscalls and syscalls_txt} }} DEFAULT KILL' "
            f"-- {system_interpreter} -i"
        )
        print(f"syscalls: {syscalls_txt}")
        print(f"nsjail sandbox: {nsjail_sandbox_cmd}")

        # Write syscalls file
        with open(output_syscalls_file, "w") as f:
            f.write(syscalls_txt)

        # Write nsjail sandbox file
        with open(nsjail_sandbox_file, "w") as f:
            f.write(nsjail_sandbox_cmd)
        st = os.stat(nsjail_sandbox_file)
        os.chmod(nsjail_sandbox_file, st.st_mode | stat.S_IEXEC)

        # Write JSON file
        modules_json = json.dumps(modules_and_syscalls, indent=4)
        with open(output_json_file, "w") as f:
            f.write(modules_json)

        # Build the YAML template
        yaml_dict = {
            name: {
                "destructive": destructive,
                "syscall_allowlist": _syscalls,
            }
            for name, _syscalls in modules_and_syscalls.items()
        }
        yaml_dict = {"modules": yaml_dict}
        modules_yaml = yaml.dump(yaml_dict)
        with open(output_yaml_file, "w") as f:
            f.write(modules_yaml)
        print("Policy is ready: ", output_yaml_file, output_json_file)

        colored_print(COLORS.ENDC)
        return output_yaml_file, output_syscalls_file, nsjail_sandbox_file

    @staticmethod
    def compile_sandbox_from_profile(
        template_filename: str = "policy.yaml", sandbox_filename_prefix: str = "sandbox"
    ) -> str:
        """Generates a tailor-made sandbox that will enforce a given YAML profile/policy in runtime.
        
        Two scripts are created: one for the dtrace backend and one for the bpftrace backend.
        Returns the filename of the bpftrace sandbox.
        """
        print(COLORS.WARNING)
        template_filename = Path(template_filename)
        dtrace_sandbox_filename = f"{sandbox_filename_prefix}.d"
        dtrace_rendered_profile = secimport.build_module_sandbox_from_yaml_template(
            template_path=template_filename,
            backend=secimport.InstrumentationBackend.DTRACE,
        )
        if not dtrace_rendered_profile:
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
    def trace(
        entrypoint: Optional[str] = None,
        python_interpreter: str = sys.executable,
        trace_log_file: str = "trace.log",
    ):
        """Traces a python process using an entrypoint script or interactive interpreter.
        
        If no entrypoint is provided, an interactive shell is traced.
        """
        with_dtrace = subprocess.check_output(
            [python_interpreter, "-c", 'import sysconfig; print(sysconfig.get_config_var("WITH_DTRACE"))'],
            encoding="utf-8",
        )
        if with_dtrace.strip() != "1":
            colored_print(
                COLORS.FAIL,
                f"\nIt seems that {python_interpreter} was compiled without --with-dtrace=1. "
                "secimport will probably not work properly!\n",
            )

        if entrypoint:
            entrypoint_cmd = f'bash -c "{python_interpreter} {entrypoint}"'
        else:
            entrypoint_cmd = python_interpreter

        cmd = [
            f"{SECIMPORT_ROOT}/profiles/trace.bt",
            "-c",
            entrypoint_cmd,
            "-o",
            trace_log_file,
            python_interpreter,
        ]
        colored_print(COLORS.HEADER, "\nTracing using ", cmd)
        colored_print(COLORS.BOLD, "Press CTRL+D or CTRL+C to stop the trace gracefully.\n")
        os.system(" ".join(cmd))
        colored_print(
            COLORS.BOLD,
            "The trace log is at",
            COLORS.OKGREEN,
            f"./{trace_log_file}",
        )

    @staticmethod
    def trace_pid(
        pid: int,
        trace_log_file: str = "trace.log",
    ):
        """Traces a running process by PID.
        
        Args:
            pid (int): Process PID to trace.
            trace_log_file (str): File to write the trace into.
        """
        assert isinstance(pid, int), f"pid must be an int, got: {pid}"

        python_interpreter = (Path("/proc") / str(pid) / "exe").resolve()
        cmd = [
            str(SECIMPORT_ROOT) + "/profiles/trace.bt",
            "-p",
            f"{pid}",
            "-o",
            trace_log_file,
            f"{python_interpreter}",
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
        """Compiles a trace log to generate the sandbox executable for supported backends."""
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
        colored_print(COLORS.OKGREEN, f"nsjail sandbox: {COLORS.BOLD} {nsjail_sandbox_file}")
        colored_print(
            COLORS.OKGREEN,
            f"secimport eBPF sandbox: {COLORS.BOLD} {bpftrace_sandbox_filename}",
        )

    @staticmethod
    def run(
        entrypoint: Optional[str] = None,
        sandbox_executable: str = "./sandbox.bt",
        python_interpreter: str = sys.executable,
        pid: Optional[int] = None,
        stop_on_violation: bool = False,
        kill_on_violation: bool = False,
        sandbox_logfile: Optional[str] = None,
    ):
        """Runs a python process inside the generated sandbox.
        
        Args:
            entrypoint (str, optional): A script entrypoint to run.
            sandbox_executable (str): The sandbox executable file (generated by 'secimport build').
            python_interpreter (str): The python interpreter to use.
            pid (int, optional): Process ID to attach to.
            stop_on_violation (bool): If True, send SIGSTOP on a violation.
            kill_on_violation (bool): If True, send SIGKILL on a violation.
            sandbox_logfile (str, optional): File to log the sandbox STDOUT.
        """
        if not Path(sandbox_executable).exists():
            raise FileNotFoundError(
                "The sandbox was not found. Try calling 'secimport trace/trace_pid' and then 'secimport build'."
            )
        sandbox_startup_cmd = [f"{sandbox_executable}", "--unsafe"]
        if pid is not None:
            sandbox_startup_cmd += [f"-p {pid}"]
        elif python_interpreter is not None:
            if entrypoint:
                sandbox_startup_cmd += [
                    "-c",
                    f'bash -c "{python_interpreter} {entrypoint}"',
                ]
            else:
                sandbox_startup_cmd += ["-c", f"{python_interpreter}"]
        else:
            raise ValueError("Please specify one of the following: entrypoint or pid")
        if sandbox_logfile:
            sandbox_startup_cmd += ["-o", sandbox_logfile]

        if stop_on_violation and kill_on_violation:
            raise AssertionError(
                "Please specify only one of the following flags: --stop_on_violation or --kill_on_violation"
            )
        if stop_on_violation:
            print("[WARNING]: This sandbox will send SIGSTOP to the program upon violation.")
            sandbox_startup_cmd.append("STOP")
        elif kill_on_violation:
            print("[WARNING]: This sandbox will send SIGKILL to the program upon violation.")
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
        """Interactive mode: trace, build, and then run the sandbox interactively."""
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
            "\n2. All function and system calls will be recorded to",
            COLORS.OKGREEN,
            "./trace.log.\n",
        )
        start = input("Continue? (y): ") or "y"
        if start.lower() == "y":
            try:
                SecImportCLI.trace()
            except KeyboardInterrupt:
                pass

            colored_print(
                COLORS.OKBLUE,
                '\nRunning "secimport build"; it compiles ./trace.log into ./sandbox.bt',
            )
            SecImportCLI.build()

            colored_print(
                COLORS.OKBLUE,
                "\nNow, let's run the sandbox.\n1. Run the same commands as before. They should run without any problem.\n"
                "2. Try something new in the shell (e.g. import os; os.system('ps');) to see how secimport detects it.",
            )
            run_ans = input("\nContinue? (y): ") or "y"

            if run_ans.lower() == "y":
                SecImportCLI.run()
        else:
            colored_print(
                COLORS.OKBLUE,
                "Please type 'y' to start. Follow the instructions; the docs are at "
                "https://github.com/avilum/secimport/wiki/Command-Line-Usage",
            )
        colored_print(COLORS.ENDC)


# Typer command definitions

@app.command()
def trace(
    entrypoint: Optional[str] = typer.Option(
        None, help="A python script to trace. If omitted, an interactive shell is traced."
    ),
    python_interpreter: str = typer.Option(
        sys.executable, help="The python interpreter to use."
    ),
    trace_log_file: str = typer.Option("trace.log", help="File to store the trace log."),
):
    """
    Trace a Python process using an entrypoint or interactive shell.
    """
    SecImportCLI.trace(entrypoint, python_interpreter, trace_log_file)


# Provide an alias 'shell' for trace
@app.command()
def shell(
    entrypoint: Optional[str] = typer.Option(
        None, help="A python script to trace. If omitted, an interactive shell is traced."
    ),
    python_interpreter: str = typer.Option(
        sys.executable, help="The python interpreter to use."
    ),
    trace_log_file: str = typer.Option("trace.log", help="File to store the trace log."),
):
    """
    Alias for 'trace'.
    """
    SecImportCLI.trace(entrypoint, python_interpreter, trace_log_file)


@app.command()
def trace_pid(
    pid: int = typer.Argument(..., help="The process ID to trace."),
    trace_log_file: str = typer.Option("trace.log", help="File to store the trace log."),
):
    """
    Trace a running process by PID.
    """
    SecImportCLI.trace_pid(pid, trace_log_file)


@app.command()
def build(
    trace_file: str = typer.Option("trace.log", help="The trace log file to process."),
    output_json_file: str = typer.Option("policy.json", help="Output JSON policy file."),
    output_yaml_file: str = typer.Option("policy.yaml", help="Output YAML policy file."),
    output_syscalls_file: str = typer.Option("syscalls.txt", help="Output syscalls file."),
    destructive: bool = typer.Option(
        False, help="Whether the sandbox should be built in destructive mode."
    ),
):
    """
    Build a sandbox profile from a trace log.
    """
    SecImportCLI.build(trace_file, output_json_file, output_yaml_file, output_syscalls_file, destructive)


@app.command()
def run(
    entrypoint: Optional[str] = typer.Option(
        None, help="A python script entrypoint to run in the sandbox."
    ),
    sandbox_executable: str = typer.Option(
        "./sandbox.bt", help="The sandbox executable generated by 'secimport build'."
    ),
    python_interpreter: str = typer.Option(
        sys.executable, help="The python interpreter to use."
    ),
    pid: Optional[int] = typer.Option(
        None, help="The process ID to run inside the sandbox."
    ),
    stop_on_violation: bool = typer.Option(
        False, help="Send SIGSTOP on a syscall violation."
    ),
    kill_on_violation: bool = typer.Option(
        False, help="Send SIGKILL on a syscall violation."
    ),
    sandbox_logfile: Optional[str] = typer.Option(
        None, help="File to log sandbox STDOUT/STDERR."
    ),
):
    """
    Run a Python process inside the sandbox.
    """
    SecImportCLI.run(
        entrypoint,
        sandbox_executable,
        python_interpreter,
        pid,
        stop_on_violation,
        kill_on_violation,
        sandbox_logfile,
    )


@app.command()
def interactive():
    """
    Run secimport in interactive mode.
    """
    SecImportCLI.interactive()


def main():
    import atexit
    atexit.register(lambda: colored_print(COLORS.ENDC))
    app()


if __name__ == "__main__":
    main()
