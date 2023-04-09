import os
import subprocess
import unittest

from secimport.cli import SecImportCLI, SECIMPORT_ROOT


class TestSecImportCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import sys

        sys.path.append(SECIMPORT_ROOT)

    def test_help_command_runs_without_errors(self):
        cmd = "secimport --help"
        proc = subprocess.run(cmd.split())
        self.assertEqual(proc.returncode, 0)

    def test_trace_pid_without_pid_raises_error(self):
        cmd = "secimport trace_pid"
        proc = subprocess.run(cmd.split())
        self.assertEqual(proc.returncode, 2)

    def test_build_command_without_default_file_raises_error(self):
        cmd = "secimport build"
        proc = subprocess.run(cmd.split())
        self.assertEqual(proc.returncode, 1)

    def test_run_command_runs_without_errors(self):
        cmd = "secimport run"
        proc = subprocess.run(cmd.split())
        self.assertEqual(proc.returncode, 0)

    def test_run_command_with_entrypoint_option_runs_without_errors(self):
        cmd = "secimport run --entrypoint this.py"
        proc = subprocess.run(cmd.split())
        self.assertEqual(proc.returncode, 0)

    def test_run_command_with_sandbox_executable_and_pid_options_runs_without_errors(
        self,
    ):
        cmd = "secimport run --sandbox_executable /path/to/my_sandbox.bt --pid 1"
        proc = subprocess.run(cmd.split())
        self.assertEqual(proc.returncode, 0)

    def test_create_profile_from_trace_method_creates_yaml_template_file(self):
        filename = "test_traced_modules.yaml"
        SecImportCLI._SecImportCLI__create_profile_from_trace(
            "trace.log", output_yaml_file=filename
        )
        self.assertTrue(os.path.isfile(filename))

    def test_create_profile_from_trace_method_creates_json_template_file(self):
        filename = "test_traced_modules.json"
        SecImportCLI._SecImportCLI__create_profile_from_trace(
            "trace.log", output_json_file=filename
        )
        self.assertTrue(os.path.isfile(filename))

    def test_help_command(self):
        cmd = "secimport --help"
        proc = subprocess.run(cmd.split())
        self.assertEqual(proc.returncode, 0)

    def test_fuzz_trace_command(self):
        cmd = "secimport trace --invalid_option"
        proc = subprocess.run(cmd.split())
        self.assertEqual(proc.returncode, 2)

    def test_fuzz_trace_pid_command(self):
        cmd = "secimport trace_pid --invalid_option"
        proc = subprocess.run(cmd.split())
        self.assertEqual(proc.returncode, 2)

    def test_fuzz_build_command(self):
        cmd = "secimport build --invalid_option"
        proc = subprocess.run(cmd.split())
        self.assertEqual(proc.returncode, 1)

    def test_fuzz_run_command(self):
        cmd = "secimport run --invalid_option"
        proc = subprocess.run(cmd.split())
        self.assertEqual(proc.returncode, 2)

    def test_run_command(self):
        cmd = "secimport run"
        proc = subprocess.run(cmd.split())
        self.assertEqual(proc.returncode, 0)

    def test_fuzz_run_command_with_entrypoint_option(self):
        cmd = "secimport run --entrypoint=/invalid_path/main.py"
        proc = subprocess.run(cmd.split())
        self.assertEqual(proc.returncode, 0)

    def test_fuzz_run_command_with_sandbox_executable_and_pid_options(self):
        cmd = "secimport run --sandbox_executable=/invalid_path/sandbox.bt --pid=1"
        proc = subprocess.run(cmd.split())
        self.assertEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
