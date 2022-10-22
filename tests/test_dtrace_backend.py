import unittest
from secimport.backends.dtrace_backend.dtrace_backend import (
    PROFILES_DIR_NAME,
    build_module_sandbox_from_yaml_template,
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
            syscalls_allowlist=None,
        )
        self.assertEqual(dtrace_script_file_path, "/tmp/.secimport/dtrace_sandbox_this.d")
        self.assertTrue(os.path.exists(dtrace_script_file_path))
        dtrace_file_content = open(dtrace_script_file_path).read()
        self.assertTrue("#pragma D option destructive" in dtrace_file_content)

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
            syscalls_allowlist=None,
        )
        dtrace_file_content = open(dtrace_script_file_path).read()
        self.assertTrue("###DESTRUCTIVE###" not in dtrace_file_content)

    def test_syscall_allowlist_script_generation(self):
        syscall_allowlist = """
            __mac_syscall
            __pthread_canceled
            bind
            csrctl
            fgetattrlist
            getattrlist
            getrlimit
            listen
            pipe
            sendmsg_nocancel
            shm_open
            sigreturn
            socketpair
            sysctlbyname
            __disable_threadsignal
            accept
            access
            bsdthread_create
            bsdthread_terminate
            connect_nocancel
            kqueue
            openat
            proc_info
            readlink
            recvfrom
            shutdown
            thread_selfid
            gettimeofday
            issetugid
            select_nocancel
            socket
            write
            getsockname
            recvfrom_nocancel
            sendto
            kevent
            psynch_cvsignal
            psynch_cvwait
            sysctl
            sendto_nocancel
            fcntl_nocancel
            setsockopt
            lstat64
            fstatfs64
            stat64
            getdirentries64
            munmap
            read_nocancel
            """.split()
        dtrace_script_file_path = create_dtrace_script_for_module(
            "http",
            allow_networking=False,
            allow_shells=False,
            log_file_system=True,
            log_syscalls=True,
            log_network=True,
            log_python_calls=True,
            destructive=False,
            syscalls_allowlist=syscall_allowlist,
        )
        dtrace_file_content = open(dtrace_script_file_path).read()
        self.assertTrue("#pragma D option destructive" in dtrace_file_content)
        self.assertTrue("__mac_syscall" in dtrace_file_content)
        self.assertTrue("read_nocancel" in dtrace_file_content)

    def test_build_module_sandbox_from_yaml_template(self):
        profile_file_path = PROFILES_DIR_NAME / "example.yaml"
        module_sandbox_code: str = build_module_sandbox_from_yaml_template(
            profile_file_path
        )
        self.assertTrue("fastapi" in module_sandbox_code)
        self.assertTrue("requests" in module_sandbox_code)
        self.assertTrue("uvicorn" in module_sandbox_code)
        # with open("/tmp/.secimport/example_sandbox.d", "w") as example_sandbox:
        #     example_sandbox.write(module_sandbox_code)

        self.assertIsInstance(module_sandbox_code, str)
        self.assertFalse("###SUPERVISED_MODULES_PROBES###" in module_sandbox_code)


if __name__ == "__main__":
    unittest.main()
