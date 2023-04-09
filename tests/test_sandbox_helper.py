import unittest
from secimport.backends.common.instrumentation_backend import InstrumentationBackend
from secimport.backends.common.utils import (
    build_module_sandbox_from_yaml_template,
)

from secimport.sandbox_helper import secure_import

EXAMPLE_SYSCALL_LIST = """
access
chdir
""".split()


class TestSecImport(unittest.TestCase):
    def test_import_with_shell_true(self):
        secure_import("urllib")
        a = [_**9 for _ in range(100)]
        print(a)

    def test_import_with_shell_false(self):
        module = secure_import("this")
        self.assertEqual(module.__name__, "this")

    def test_build_module_sandbox_from_yaml_template(self):
        example_yaml = """
modules:
  requests:
    destructive: true
    syscall_allowlist:
      - fchmod
      - ioctl
  fastapi:
    destructive: true
    syscall_allowlist:
      - bind
      - fchmod
  uvicorn:
    destructive: true
    syscall_allowlist:
      - getpeername
      - getpgrp
        """
        profile_file_path = "/tmp/.secimport_test_policy.yaml"
        with open("/tmp/.secimport_test_policy.yaml", "w") as f:
            f.write(example_yaml)
        bpftrace_module_sandbox_code: str = build_module_sandbox_from_yaml_template(
            profile_file_path, backend=InstrumentationBackend.EBPF
        )
        dtrace_module_sandbox_code: str = build_module_sandbox_from_yaml_template(
            profile_file_path, backend=InstrumentationBackend.DTRACE
        )
        for module_sandbox_code in [
            bpftrace_module_sandbox_code,
            dtrace_module_sandbox_code,
        ]:
            self.assertTrue("fastapi" in module_sandbox_code)
            self.assertTrue("requests" in module_sandbox_code)
            self.assertTrue("uvicorn" in module_sandbox_code)
            self.assertIsInstance(module_sandbox_code, str)
            self.assertFalse("###SUPERVISED_MODULES_PROBES###" in module_sandbox_code)


if __name__ == "__main__":
    unittest.main()
