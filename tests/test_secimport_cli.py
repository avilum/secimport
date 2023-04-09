import os
import subprocess
import unittest

from secimport.cli import SecImportCLI


class TestSecImportCLI(unittest.TestCase):
    def test_trace_command_runs_without_errors(self):
        cmd = "secimport trace"
        exit_code = subprocess.run(cmd.split())
        self.assertEqual(exit_code, 0)

    def test_trace_pid_command_runs_without_errors(self):
        cmd = "secimport trace_pid 1"
        exit_code = subprocess.run(cmd.split())
        self.assertEqual(exit_code, 0)

    def test_build_command_runs_without_errors(self):
        cmd = "secimport build"
        exit_code = subprocess.run(cmd.split())
        self.assertEqual(exit_code, 0)

    def test_run_command_runs_without_errors(self):
        cmd = "secimport run"
        exit_code = subprocess.run(cmd.split())
        self.assertEqual(exit_code, 0)

    def test_run_command_with_entrypoint_option_runs_without_errors(self):
        cmd = "secimport run --entrypoint this.py"
        exit_code = subprocess.run(cmd.split())
        self.assertEqual(exit_code, 0)

    def test_run_command_with_sandbox_executable_and_pid_options_runs_without_errors(
        self,
    ):
        cmd = "secimport run --sandbox_executable /path/to/my_sandbox.bt --pid 1"
        exit_code = subprocess.run(cmd.split())
        self.assertEqual(exit_code, 0)

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
        exit_code = subprocess.run(cmd.split())
        self.assertEqual(exit_code, 0)

    def test_fuzz_trace_command(self):
        cmd = "secimport trace --invalid_option"
        exit_code = subprocess.run(cmd.split())
        self.assertNotEqual(exit_code, 0)

    def test_fuzz_trace_pid_command(self):
        cmd = "secimport trace_pid --invalid_option"
        exit_code = subprocess.run(cmd.split())
        self.assertNotEqual(exit_code, 0)

    def test_fuzz_build_command(self):
        cmd = "secimport build --invalid_option"
        exit_code = subprocess.run(cmd.split())
        self.assertNotEqual(exit_code, 0)

    def test_fuzz_run_command(self):
        cmd = "secimport run --invalid_option"
        exit_code = subprocess.run(cmd.split())
        self.assertNotEqual(exit_code, 0)

    def test_fuzz_run_command_with_entrypoint_option(self):
        cmd = "secimport run --entrypoint=/invalid_path/main.py"
        exit_code = subprocess.run(cmd.split())
        self.assertNotEqual(exit_code, 0)

    def test_fuzz_run_command_with_sandbox_executable_and_pid_options(self):
        cmd = "secimport run --sandbox_executable=/invalid_path/sandbox.bt --pid=1"
        exit_code = subprocess.run(cmd.split())
        self.assertNotEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
