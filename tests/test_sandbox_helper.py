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
            syscalls_allowlist=None,
        )
        self.assertEqual(dtrace_script_file_path, "/tmp/.secimport/sandbox_this.d")
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

    def test_syscall_allowlist_secure_import(self):
        module = secure_import(
            module_name="http",
            syscalls_allowlist="""
                                access
                                exit
                                getentropy
                                getrlimit
                                mprotect
                                shm_open
                                sysctlbyname
                                write
                                fcntl_nocancel
                                readlink
                                fcntl
                                mmap
                                fstatfs64
                                getdirentries64
                                read_nocancel
                                madvise
                                close_nocancel
                                open_nocancel
                                sigaction
                                close
                                open
                                lseek
                                read
                                fstat64
                                ioctl
                                stat64
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
                                dup2
                                ftruncate
                                chdir
                                sigaltstack
                    """.split(),
        )
        self.assertEqual(module.__name__, "http")
