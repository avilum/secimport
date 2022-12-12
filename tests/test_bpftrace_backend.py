import unittest
import os
import sys


from secimport.backends.bpftrace_backend.bpftrace_backend import (
    render_bpftrace_template,
    create_bpftrace_script_for_module,
    run_bpftrace_script_for_module,
)


class TestEBPFBackend(unittest.TestCase):
    def test_run_bpftrace_script_for_module(self):
        bpftrace_script_file_path = create_bpftrace_script_for_module(
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
        self.assertEqual(
            bpftrace_script_file_path, "/tmp/.secimport/bpftrace_sandbox_this.bt"
        )
        self.assertTrue(os.path.exists(bpftrace_script_file_path))
        bpftrace_file_content = open(bpftrace_script_file_path).read()
        self.assertTrue("system" in bpftrace_file_content)
        self.assertTrue(sys.executable in bpftrace_file_content)

    def test_create_bpftrace_script_for_module(self):
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
            syscalls_allowlist=None,
        )
        bpftrace_file_content = open(bpftrace_script_file_path).read()
        # print(bpftrace_file_content)
        # Making sure all the template variables (start with '###') were successfully replaced in the function.
        self.assertTrue("###" not in bpftrace_file_content)

    def test_create_bpftrace_script_for_module_with_syscalls_allowlist(self):
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
        bpftrace_script_file_path = create_bpftrace_script_for_module(
            module_name="http",
            allow_networking=False,
            allow_shells=False,
            log_file_system=True,
            log_syscalls=True,
            log_network=True,
            log_python_calls=True,
            destructive=True,
            syscalls_allowlist=syscall_allowlist,
        )
        bpftrace_file_content = open(bpftrace_script_file_path).read()
        self.assertTrue("system(" in bpftrace_file_content)
        self.assertTrue("__mac_syscall" in bpftrace_file_content)
        self.assertTrue("read_nocancel" in bpftrace_file_content)

    def test_create_bpftrace_script_for_module_with_syscalls_blocklist(self):
        syscall_blocklist = """
            bind
            """.split()
        bpftrace_script_file_path = create_bpftrace_script_for_module(
            module_name="http",
            allow_networking=False,
            allow_shells=False,
            log_file_system=True,
            log_syscalls=True,
            log_network=True,
            log_python_calls=True,
            destructive=True,
            syscalls_blocklist=syscall_blocklist,
        )
        bpftrace_file_content = open(bpftrace_script_file_path).read()
        self.assertTrue("system(" in bpftrace_file_content)
        self.assertTrue("bind" in bpftrace_file_content)

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
