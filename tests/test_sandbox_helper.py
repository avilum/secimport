from unittest import TestCase
from secimport.sandbox_helper import secure_import, create_dtrace_script_for_module
import os


class TestSecImport(TestCase):
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
            log_python_calls=True, 
            destructive=True, 
        )
        self.assertEqual(dtrace_script_file_path, "/tmp/.secimport/sandbox_this.d")
        self.assertTrue(os.path.exists(dtrace_script_file_path))
        dtrace_file_content = open(dtrace_script_file_path).read()
        self.assertTrue("#pragma D option destructive" in dtrace_file_content)


    def test_non_destructive_mode_removes_destructive_header(self):
        dtrace_script_file_path = create_dtrace_script_for_module(
            "this",
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
