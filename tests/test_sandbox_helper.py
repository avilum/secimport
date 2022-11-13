import unittest

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

    def test_syscall_allowlist_secure_import(self):
        module = secure_import(
            module_name="http",
            syscalls_allowlist=EXAMPLE_SYSCALL_LIST,
            log_file_system=True,
            log_python_calls=True,
        )
        self.assertEqual(module.__name__, "http")

    def test_syscall_blocklist_secure_import(self):
        # Only log violations
        module = secure_import(
            module_name="http",
            syscalls_blocklist=EXAMPLE_SYSCALL_LIST,
            destructive=False,
        )
        self.assertEqual(module.__name__, "http")


if __name__ == "__main__":
    unittest.main()
