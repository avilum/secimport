import unittest
import os
import sys


from secimport.backends.bpftrace_backend.bpftrace_backend import (
    render_bpftrace_template,
    create_bpftrace_script_for_module,
    run_bpftrace_script_for_module,
)
from secimport.backends.common.utils import BASE_DIR_NAME


class TestEBPFBackend(unittest.TestCase):
    def setUp(self) -> None:

        try:
            os.remove(BASE_DIR_NAME)
        except (FileNotFoundError, PermissionError):
            ...
        return super().setUp()

    def test_run_bpftrace_with_none_module_raises_error(self):
        with self.assertRaises(ModuleNotFoundError):
            create_bpftrace_script_for_module(
                module_name="nonexisting",
                allow_networking=False,
                allow_shells=False,
                log_file_system=True,
                log_syscalls=True,
                log_network=True,
                log_python_calls=True,
                destructive=True,
            )

    def test_create_bpftrace_script_for_module(self):
        bpftrace_script_file_path = create_bpftrace_script_for_module(
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
            bpftrace_script_file_path, "/tmp/.secimport/bpftrace_sandbox_this.bt"
        )
        self.assertTrue(os.path.exists(bpftrace_script_file_path))
        bpftrace_file_content = open(bpftrace_script_file_path).read()
        self.assertTrue("system" in bpftrace_file_content)
        self.assertTrue(sys.executable in bpftrace_file_content)

    def test_run_bpftrace_script_for_module(self):
        res = run_bpftrace_script_for_module(
            "this",
            allow_networking=False,
            allow_shells=False,
            log_file_system=True,
            log_syscalls=True,
            log_network=True,
            log_python_calls=True,
            destructive=True,
            dry_run=True,
        )

        self.assertTrue(res)

    def test_create_bpftrace_script_for_nonexisting_module(self):
        # create_bpftrace_script_for_module
        # TODO: implement
        bpftrace_script_file_path = create_bpftrace_script_for_module(
            module_name="urllib",
            allow_networking=False,
            allow_shells=False,
            log_file_system=True,
            log_syscalls=True,
            log_network=True,
            log_python_calls=True,
            destructive=True,
        )
        bpftrace_file_content = open(bpftrace_script_file_path).read()
        # Making sure all the template variables (start with '###') were successfully replaced in the function.
        self.assertTrue("###" not in bpftrace_file_content)

    def test_render_bpftrace_template(self):
        bpftrace_file_content = render_bpftrace_template(
            module_traced_name="http",
            allow_networking=False,
            allow_shells=False,
            log_file_system=True,
            log_syscalls=True,
            log_network=True,
            log_python_calls=True,
            destructive=True,
        )
        self.assertTrue("system(" in bpftrace_file_content)
        self.assertTrue("http" in bpftrace_file_content)


if __name__ == "__main__":
    unittest.main()
