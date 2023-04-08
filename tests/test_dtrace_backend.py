import unittest
from secimport.backends.dtrace_backend.dtrace_backend import (
    create_dtrace_script_for_module,
)
import os


class TestDtraceBackend(unittest.TestCase):
    def test_create_dtrace_script_for_module(self):
        dtrace_script_file_path = create_dtrace_script_for_module(
            "this",
            allow_networking=False,
            allow_shells=False,
            log_file_system=True,
            log_syscalls=True,
            log_network=True,
            log_python_calls=True,
            destructive=True,
        )
        self.assertEqual(
            dtrace_script_file_path, "/tmp/.secimport/dtrace_sandbox_this.d"
        )
        self.assertTrue(os.path.exists(dtrace_script_file_path))
        dtrace_file_content = open(dtrace_script_file_path).read()
        self.assertTrue("option destructive" in dtrace_file_content)

    def test_non_destructive_mode_removes_destructive_header(self):
        dtrace_script_file_path = create_dtrace_script_for_module(
            "urllib",
            allow_networking=False,
            allow_shells=False,
            log_file_system=True,
            log_syscalls=True,
            log_network=True,
            log_python_calls=True,
            destructive=False,
        )
        dtrace_file_content = open(dtrace_script_file_path).read()
        self.assertTrue("###DESTRUCTIVE###" not in dtrace_file_content)


if __name__ == "__main__":
    unittest.main()
