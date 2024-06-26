import os
import subprocess
import unittest

from secimport.cli import SecImportCLI, SECIMPORT_ROOT


class TestSecImportCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import sys

        sys.path.append(SECIMPORT_ROOT)

    def test_e2e(self):
        temp_script_path = "/tmp/.test_code.py"
        with open(temp_script_path, "w") as f:
            f.write('import os; os.system("echo hi");')

        cmd = f"/workspace/Python-3.11.8/python -m secimport.cli trace --entrypoint {temp_script_path} -o /tmp/.example.log"
        subprocess.run(cmd.split())

        cmd = "/workspace/Python-3.11.8/python -m secimport.cli -m secimport.cli build --trace-file /tmp/.example.log"
        subprocess.run(cmd.split())

        cmd = f"/workspace/Python-3.11.8/python -m secimport.cli run  --entrypoint {temp_script_path}"
        subprocess.run(cmd.split())

        # TODO: assert

    def test_help_command_runs_without_errors(self):
        cmd = "/workspace/Python-3.11.8/python -m secimport.cli --help"
        proc = subprocess.run(cmd.split())
        self.assertEqual(proc.returncode, 0)

    def test_trace_pid_without_pid_raises_error(self):
        cmd = "/workspace/Python-3.11.8/python -m secimport.cli trace_pid"
        proc = subprocess.run(cmd.split())
        self.assertEqual(proc.returncode, 2)

    def test_build_command_without_default_file_raises_error(self):
        cmd = "/workspace/Python-3.11.8/python -m secimport.cli build"
        proc = subprocess.run(cmd.split())
        self.assertEqual(proc.returncode, 1)

    def test_run_command_runs_without_errors(self):
        cmd = "/workspace/Python-3.11.8/python -m secimport.cli run"
        proc = subprocess.run(cmd.split())
        self.assertEqual(proc.returncode, 0)

    def test_run_command_with_entrypoint_option_runs_without_errors(self):
        cmd = (
            "/workspace/Python-3.11.8/python -m secimport.cli run --entrypoint this.py"
        )
        proc = subprocess.run(cmd.split())
        self.assertEqual(proc.returncode, 0)

    def test_run_command_with_sandbox_executable_and_pid_options_runs_without_errors(
        self,
    ):
        cmd = "/workspace/Python-3.11.8/python -m secimport.cli run --sandbox_executable /path/to/my_sandbox.bt --pid 1"
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
        cmd = "/workspace/Python-3.11.8/python -m secimport.cli --help"
        proc = subprocess.run(cmd.split())
        self.assertEqual(proc.returncode, 0)

    def test_fuzz_trace_command(self):
        cmd = "/workspace/Python-3.11.8/python -m secimport.cli trace --invalid_option"
        proc = subprocess.run(cmd.split())
        self.assertEqual(proc.returncode, 2)

    def test_fuzz_trace_pid_command(self):
        cmd = "/workspace/Python-3.11.8/python -m secimport.cli trace_pid --invalid_option"
        proc = subprocess.run(cmd.split())
        self.assertEqual(proc.returncode, 2)

    def test_fuzz_build_command(self):
        cmd = "/workspace/Python-3.11.8/python -m secimport.cli build --invalid_option"
        proc = subprocess.run(cmd.split())
        self.assertEqual(proc.returncode, 2)

    def test_fuzz_run_command(self):
        cmd = "/workspace/Python-3.11.8/python -m secimport.cli run --invalid_option"
        proc = subprocess.run(cmd.split())
        self.assertEqual(proc.returncode, 2)

    def test_run_command(self):
        cmd = "/workspace/Python-3.11.8/python -m secimport.cli run"
        proc = subprocess.run(cmd.split())
        self.assertEqual(proc.returncode, 0)

    def test_fuzz_run_command_with_entrypoint_option(self):
        cmd = "/workspace/Python-3.11.8/python -m secimport.cli run --entrypoint=/invalid_path/main.py"
        proc = subprocess.run(cmd.split())
        self.assertEqual(proc.returncode, 0)

    def test_fuzz_run_command_with_sandbox_executable_and_pid_options(self):
        cmd = "/workspace/Python-3.11.8/python -m secimport.cli run --sandbox_executable=/invalid_path/sandbox.bt --pid=1"
        proc = subprocess.run(cmd.split())
        self.assertEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
