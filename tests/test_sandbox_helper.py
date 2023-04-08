import unittest
from secimport.backends.common.instrumentation_backend import InstrumentationBackend
from secimport.backends.common.utils import (
    build_module_sandbox_from_yaml_template,
)

from secimport.sandbox_helper import secure_import

EXAMPLE_SYSCALL_LIST = """
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
      - getentropy
      - getpgrp
      - getrlimit
      - shm_open
      - sysctlbyname
      - access
      - munmap
      - issetugid
      - readlink
      - write
      - fcntl
      - fstatfs64
      - getdirentries64
      - mprotect
      - fcntl_nocancel
      - madvise
      - mmap
      - read_nocancel
      - select
      - sigprocmask
      - close_nocancel
      - write_nocancel
      - open_nocancel
      - close
      - open
      - sigaction
      - lseek
      - fstat64
      - read
      - ioctl
      - stat64
  fastapi:
    destructive: true
    syscall_allowlist:
      - bind
      - fchmod
      - getentropy
      - getpgrp
      - getrlimit
      - shm_open
      - sysctlbyname
      - access
      - munmap
      - issetugid
      - readlink
      - write
      - fcntl
      - fstatfs64
      - getdirentries64
      - mprotect
      - fcntl_nocancel
      - madvise
      - mmap
      - read_nocancel
      - select
      - sigprocmask
      - close_nocancel
      - write_nocancel
      - open_nocancel
      - close
      - open
      - sigaction
      - lseek
      - fstat64
      - read
      - ioctl
      - stat64
      - read
      - pipe
      - listen
      - poll
      - sigreturn
      - getsockname
      - kqueue
      - kevent
      - getpeername
      - getpgrp
      - listen
      - pipe
      - poll
      - setsockopt
      - shm_open
      - socket
      - socketpair
      - sysctlbyname
      - accept
      - access
      - getrlimit
      - kqueue
      - readlink
      - recvfrom
      - getsockname
      - issetugid
      - sendto
      - write
      - read_nocancel
      - getentropy
      - sigprocmask
      - fstatfs64
      - getdirentries64
      - munmap
      - madvise
      - select
      - write_nocancel
      - sigaction
      - fcntl_nocancel
      - fcntl
      - close_nocancel
      - open_nocancel
      - mprotect
      - mmap
      - kevent
      - open
      - close
      - lseek
      - ioctl
      - read
      - fstat64
      - stat64
  uvicorn:
    destructive: true
    syscall_allowlist:
      - getpeername
      - getpgrp
      - listen
      - pipe
      - poll
      - setsockopt
      - shm_open
      - socket
      - socketpair
      - sysctlbyname
      - accept
      - access
      - getrlimit
      - kqueue
      - readlink
      - recvfrom
      - getsockname
      - issetugid
      - sendto
      - write
      - read_nocancel
      - getentropy
      - sigprocmask
      - fstatfs64
      - getdirentries64
      - munmap
      - madvise
      - select
      - write_nocancel
      - sigaction
      - fcntl_nocancel
      - fcntl
      - close_nocancel
      - open_nocancel
      - mprotect
      - mmap
      - kevent
      - open
      - close
      - lseek
      - ioctl
      - read
      - fstat64
      - stat64
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
