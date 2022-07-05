from unittest import TestCase
from secimport.sandbox_helper import secure_import, create_dtrace_script_for_module
import os


class TestPySandbox(TestCase):
    def test_import_with_shell_true(self):
        secure_import("urllib")
        a = [_**9 for _ in range(100)]
        print(a)

    def test_import_with_shell_false(self):
        module = secure_import("this")
        self.assertEqual(module.__name__, "this")

    def test_create_dtrace_script_for_module(self):
        dtrace_script_file_path = create_dtrace_script_for_module(
            "this",
            allow_networking=False,
            allow_shells=False,
            log_file_system=True,
            log_syscalls=True,
            log_network=True,
        )
        self.assertEqual(dtrace_script_file_path, "/tmp/.secimport/sandbox-this.d")
        self.assertTrue(os.path.exists(dtrace_script_file_path))
