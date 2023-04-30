import os
from sys import platform
from pathlib import Path
from typing import List
import importlib
from sys import executable as PYTHON_EXECUTABLE

from secimport.backends.common.instrumentation_backend import InstrumentationBackend

BASE_DIR_NAME = Path("/tmp/.secimport")
SECIMPORT_ROOT = Path(
    os.path.realpath(
        os.path.split(__file__)[:-1][0] + os.sep + os.pardir + os.sep + os.pardir
    )
)

PROFILES_DIR_NAME = SECIMPORT_ROOT / "profiles"
BPFTRACE_TEMPLATES_DIR_NAME = SECIMPORT_ROOT / "backends" / "bpftrace_backend"
DTRACE_TEMPLATES_DIR_NAME = SECIMPORT_ROOT / "backends" / "dtrace_backend"
TEMPLATES_DIR_NAME = None
DEFAULT_BACKEND = None

if "linux" in platform.lower():
    TEMPLATES_DIR_NAME = BPFTRACE_TEMPLATES_DIR_NAME
    DEFAULT_BACKEND = InstrumentationBackend.EBPF
    # TODO: verify bpftrace is installed, if not, link to the repo documentation on how to install.
else:
    TEMPLATES_DIR_NAME = DTRACE_TEMPLATES_DIR_NAME
    DEFAULT_BACKEND = InstrumentationBackend.DTRACE


SYSCALLS_NUMBERS = {
    0: "read",
    1: "write",
    2: "open",
    3: "close",
    4: "stat",
    5: "fstat",
    6: "lstat",
    7: "poll",
    8: "lseek",
    9: "mmap",
    10: "mprotect",
    11: "munmap",
    12: "brk",
    13: "rt_sigaction",
    14: "rt_sigprocmask",
    15: "rt_sigreturn",
    16: "ioctl",
    17: "pread",
    18: "pwrite",
    19: "readv",
    20: "writev",
    21: "access",
    22: "pipe",
    23: "select",
    24: "sched_yield",
    25: "mremap",
    26: "msync",
    27: "mincore",
    28: "madvise",
    29: "shmget",
    30: "shmat",
    31: "shmctl",
    32: "dup",
    33: "dup2",
    34: "pause",
    35: "nanosleep",
    36: "getitimer",
    37: "alarm",
    38: "setitimer",
    39: "getpid",
    40: "sendfile",
    41: "socket",
    42: "connect",
    43: "accept",
    44: "sendto",
    45: "recvfrom",
    46: "sendmsg",
    47: "recvmsg",
    48: "shutdown",
    49: "bind",
    50: "listen",
    51: "getsockname",
    52: "getpeername",
    53: "socketpair",
    54: "setsockopt",
    55: "getsockopt",
    56: "clone",
    57: "fork",
    58: "vfork",
    59: "execve",
    60: "exit",
    61: "wait4",
    62: "kill",
    63: "uname",
    64: "semget",
    65: "semop",
    66: "semctl",
    67: "shmdt",
    68: "msgget",
    69: "msgsnd",
    70: "msgrcv",
    71: "msgctl",
    72: "fcntl",
    73: "flock",
    74: "fsync",
    75: "fdatasync",
    76: "truncate",
    77: "ftruncate",
    78: "getdents",
    79: "getcwd",
    80: "chdir",
    81: "fchdir",
    82: "rename",
    83: "mkdir",
    84: "rmdir",
    85: "creat",
    86: "link",
    87: "unlink",
    88: "symlink",
    89: "readlink",
    90: "chmod",
    91: "fchmod",
    92: "chown",
    93: "fchown",
    94: "lchown",
    95: "umask",
    96: "gettimeofday",
    97: "getrlimit",
    98: "getrusage",
    99: "sysinfo",
    100: "times",
    101: "ptrace",
    102: "getuid",
    103: "syslog",
    104: "getgid",
    105: "setuid",
    106: "setgid",
    107: "geteuid",
    108: "getegid",
    109: "setpgid",
    110: "getppid",
    111: "getpgrp",
    112: "setsid",
    113: "setreuid",
    114: "setregid",
    115: "getgroups",
    116: "setgroups",
    117: "setresuid",
    118: "getresuid",
    119: "setresgid",
    120: "getresgid",
    121: "getpgid",
    122: "setfsuid",
    123: "setfsgid",
    124: "getsid",
    125: "capget",
    126: "capset",
    127: "rt_sigpending",
    128: "rt_sigtimedwait",
    129: "rt_sigqueueinfo",
    130: "rt_sigsuspend",
    131: "sigaltstack",
    132: "utime",
    133: "mknod",
    134: "uselib",
    135: "personality",
    136: "ustat",
    137: "statfs",
    138: "fstatfs",
    139: "sysfs",
    140: "getpriority",
    141: "setpriority",
    142: "sched_setparam",
    143: "sched_getparam",
    144: "sched_setscheduler",
    145: "sched_getscheduler",
    146: "sched_get_priority_max",
    147: "sched_get_priority_min",
    148: "sched_rr_get_interval",
    149: "mlock",
    150: "munlock",
    151: "mlockall",
    152: "munlockall",
    153: "vhangup",
    154: "modify_ldt",
    155: "pivot_root",
    156: "_sysctl",
    157: "prctl",
    158: "arch_prctl",
    159: "adjtimex",
    160: "setrlimit",
    161: "chroot",
    162: "sync",
    163: "acct",
    164: "settimeofday",
    165: "mount",
    166: "umount2",
    167: "swapon",
    168: "swapoff",
    169: "reboot",
    170: "sethostname",
    171: "setdomainname",
    172: "iopl",
    173: "ioperm",
    174: "create_module",
    175: "init_module",
    176: "delete_module",
    177: "get_kernel_syms",
    178: "query_module",
    179: "quotactl",
    180: "nfsservctl",
    181: "getpmsg",
    182: "putpmsg",
    183: "afs_syscall",
    184: "tuxcall",
    185: "security",
    186: "gettid",
    187: "readahead",
    188: "setxattr",
    189: "lsetxattr",
    190: "fsetxattr",
    191: "getxattr",
    192: "lgetxattr",
    193: "fgetxattr",
    194: "listxattr",
    195: "llistxattr",
    196: "flistxattr",
    197: "removexattr",
    198: "lremovexattr",
    199: "fremovexattr",
    200: "tkill",
    201: "time",
    202: "futex",
    203: "sched_setaffinity",
    204: "sched_getaffinity",
    205: "set_thread_area",
    206: "io_setup",
    207: "io_destroy",
    208: "io_getevents",
    209: "io_submit",
    210: "io_cancel",
    211: "get_thread_area",
    212: "lookup_dcookie",
    213: "epoll_create",
    214: "epoll_ctl_old",
    215: "epoll_wait_old",
    216: "remap_file_pages",
    217: "getdents64",
    218: "set_tid_address",
    219: "restart_syscall",
    220: "semtimedop",
    221: "fadvise64",
    222: "timer_create",
    223: "timer_settime",
    224: "timer_gettime",
    225: "timer_getoverrun",
    226: "timer_delete",
    227: "clock_settime",
    228: "clock_gettime",
    229: "clock_getres",
    230: "clock_nanosleep",
    231: "exit_group",
    232: "epoll_wait",
    233: "epoll_ctl",
    234: "tgkill",
    235: "utimes",
    236: "vserver",
    237: "mbind",
    238: "set_mempolicy",
    239: "get_mempolicy",
    240: "mq_open",
    241: "mq_unlink",
    242: "mq_timedsend",
    243: "mq_timedreceive",
    244: "mq_notify",
    245: "mq_getsetattr",
    246: "kexec_load",
    247: "waitid",
    248: "add_key",
    249: "request_key",
    250: "keyctl",
    251: "ioprio_set",
    252: "ioprio_get",
    253: "inotify_init",
    254: "inotify_add_watch",
    255: "inotify_rm_watch",
    256: "migrate_pages",
    257: "openat",
    258: "mkdirat",
    259: "mknodat",
    260: "fchownat",
    261: "futimesat",
    262: "newfstatat",
    263: "unlinkat",
    264: "renameat",
    265: "linkat",
    266: "symlinkat",
    267: "readlinkat",
    268: "fchmodat",
    269: "faccessat",
    270: "pselect6",
    271: "ppoll",
    272: "unshare",
    273: "set_robust_list",
    274: "get_robust_list",
    275: "splice",
    276: "tee",
    277: "sync_file_range",
    278: "vmsplice",
    279: "move_pages",
    280: "utimensat",
    281: "epoll_pwait",
    282: "signalfd",
    283: "timerfd",
    284: "eventfd",
    285: "fallocate",
    286: "timerfd_settime",
    287: "timerfd_gettime",
    288: "accept4",
    289: "signalfd4",
    290: "eventfd2",
    291: "epoll_create1",
    292: "dup3",
    293: "pipe2",
    294: "inotify_init1",
    295: "preadv",
    296: "pwritev",
    297: "rt_tgsigqueueinfo",
    298: "perf_event_open",
    299: "recvmmsg",
    300: "fanotify_init",
    301: "fanotify_mark",
    302: "prlimit64",
    303: "name_to_handle_at",
    304: "open_by_handle_at",
    305: "clock_adjtime",
    306: "syncfs",
    307: "sendmmsg",
    308: "setns",
    309: "getcpu",
    310: "process_vm_readv",
    311: "process_vm_writev",
    312: "kcmp",
    313: "finit_module",
    314: "sched_setattr",
    315: "sched_getattr",
    316: "renameat2",
    317: "seccomp",
    318: "getrandom",
    319: "memfd_create",
    320: "kexec_file_load",
    321: "bpf",
    322: "execveat",
    323: "userfaultfd",
    324: "membarrier",
    325: "mlock2",
    326: "copy_file_range",
    327: "preadv2",
    328: "pwritev2",
    329: "pkey_mprotect",
    330: "pkey_alloc",
    331: "pkey_free",
    332: "statx",
    333: "io_pgetevents",
    334: "rseq",
}

SYSCALLS_NAMES = {str(v): k for k, v in SYSCALLS_NUMBERS.items()}

INSECURE_SYSCALLS = [
    "vfork",
    "clone",
    "access",
    "chdir",
    "creat",
    "dup",
    "dup2",
    "execve",
    "faccessat",
    "fcntl",
    "fdatasync",
    "fork",
    "fstat",
    "fsync",
    "getegid",
    "geteuid",
    "getgid",
    "getgroups",
    "getpid",
    "getppid",
    "getrlimit",
    "getsockname",
    "getsid",
    "getuid",
    "ioctl",
    "link",
    "lseek",
    "lstat",
    "mkdir",
    "mknod",
    "open",
    "openat",
    "pipe",
    "poll",
    "read",
    "readlink",
    "readv",
    "recvfrom",
    "recvmsg",
    "rename",
    "rmdir",
    "select",
    "sendmsg",
    "sendto",
    "setgid",
    "setgroups",
    "setpgid",
    "setpriority",
    "setregid",
    "setreuid",
    "setrlimit",
    "setsid",
    "setsockopt",
    "stat",
    "symlink",
    "truncate",
    "umask",
    "utime",
    "utimes",
    "write",
    "writev",
]

# NETWORKING_SYSCALLS = [
#     "socket",
#     "connect",
#     "bind",
#     "listen",
#     "accept",
#     "send",
#     "recv",
#     "sendto",
#     "recvfrom",
#     "shutdown",
#     "setsockopt",
#     "getsockopt",
#     "getpeername",
#     "getsockname",
#     "gethostbyname",
#     "gethostbyaddr",
#     "getservbyname",
#     "getservbyport",
#     "getifaddrs",
#     "ioctl",
#     "rt_names_to_index",
#     "rt_index_to_name",
#     "rt_newlink",
#     "rt_dellink",
#     "rt_changelink",
#     "rt_getlink",
#     "rt_getroute",
#     "rt_newroute",
#     "rt_delroute",
#     "rt_changeroute",
#     "rt_priority",
#     "rt_classid",
#     "rt_mark",
#     "rt_table",
#     "rt_protocol",
#     "rt_scope",
#     "rt_flags",
#     "rt_ifindex",
#     "rt_metric",
#     "rt_gateway",
#     "rt_src",
#     "rt_dst",
#     "rt_genmask",
#     "rt_flags",
#     "rt_refcnt",
#     "rt_fib",
#     "rt_nexthop",
#     "rt_ifa",
#     "rt_ifa_index",
#     "rt_ifa_flags",
#     "rt_ifa_scope",
#     "rt_ifa_mntr",
#     "rt_ifa_brd",
#     "rt_ifa_dst",
#     "rt_ifa_netmask",
#     "rt_ifa_net",
#     "rt_ifa_flags",
#     "rt_ifa_ifindex",
#     "rt_ifa_hwaddr",
#     "rt_ifa_rtnl",
#     "rt_ifa_type",
#     "rt_ifa_metric",
#     "rt_ifa_refcnt",
#     "rt_ifa_mtu",
#     "rt_ifa_lladdr",
#     "rt_ifa_addr",
#     "rt_ifa_brd",
#     "rt_ifa_netmask",
#     "rt_ifa_net",
#     "rt_ifa_flags",
#     "rt_ifa_ifindex",
#     "rt_ifa_hwaddr",
#     "rt_ifa_rtnl",
#     "rt_ifa_type",
#     "rt_ifa_metric",
#     "rt_ifa_refcnt",
#     "rt_ifa_mtu",
#     "rt_ifa_lladdr",
# ]
# FILESYSTEM_SYSCALLS = [
#     "access",
#     "chdir",
#     "chmod",
#     "chown",
#     "cksum",
#     "creat",
#     "ctermid",
#     "dup",
#     "dup2",
#     "execve",
#     "faccessat",
#     "fchmod",
#     "fchown",
#     "fcntl",
#     "fdatasync",
#     "fdopendir",
#     "fdopen",
#     "fexecve",
#     "fflush",
#     "fgetpos",
#     "fgets",
#     "fgetwc",
#     "fileno",
#     "flock",
#     "fmemopen",
#     "fopen",
#     "fopencookie",
#     "fork",
#     "fputwc",
#     "fstat",
#     "fsync",
#     "ftruncate",
#     "getegid",
#     "geteuid",
#     "getgid",
#     "getgroups",
#     "getpid",
#     "getppid",
#     "getrlimit",
#     "getsockname",
#     "getsid",
#     "getuid",
#     "ioctl",
#     "link",
#     "lseek",
#     "lstat",
#     "mkdir",
#     "mknod",
#     "open",
#     "openat",
#     "pipe",
#     "poll",
#     # "posix_fallocate",
#     # "posix_fadvise",
#     # "posix_fadvise64",
#     "read",
#     "readlink",
#     # "readdir",
#     "readv",
#     "recv",
#     "recvfrom",
#     "recvmsg",
#     "rename",
#     "rewind",
#     "rmdir",
#     "seekdir",
#     "select",
#     "send",
#     "sendmsg",
#     "sendto",
#     "setegid",
#     "seteuid",
#     "setgid",
#     "setgroups",
#     "setpgid",
#     "setpriority",
#     "setregid",
#     "setreuid",
#     "setrlimit",
#     "setsid",
#     "setsockopt",
#     "stat",
#     "symlink",
#     "truncate",
#     "umask",
#     "umount",
#     "utime",
#     "utimes",
#     "write",
#     "writev",
# ]


def render_syscalls_filter(
    syscalls_list: List[str],
    allow: bool,
    instrumentation_backend: InstrumentationBackend,
    module_name=None,
):
    assert isinstance(allow, bool), '"allow" must be a bool value'
    # "=="" means the syscall matches (blocklist), while "!="" means allow only the following.
    match_sign = "!=" if allow else "=="
    syscalls_filter = ""
    for i, _syscall in enumerate(syscalls_list):
        _syscall = _syscall.strip().lower()
        if i > 0:
            if instrumentation_backend == InstrumentationBackend.DTRACE:
                syscalls_filter += " && "
        assert isinstance(
            _syscall, str
        ), f"The provided syscall it not a syscall string name: '{_syscall}'"

        # Translating syscall
        _syscall_number = SYSCALLS_NAMES.get(_syscall)
        if _syscall_number is None:
            raise NotImplementedError(
                f"The provided syscall it not a syscall mapped to a number: '{_syscall}'"
            )

        # dtrace
        if instrumentation_backend == InstrumentationBackend.DTRACE:
            if module_name is not None:
                raise NotImplementedError(
                    "Specific modules syscalls are not allowed using render_syscall_filter. Please use YAML template instead."
                )
            syscalls_filter += f'probefunc {match_sign} "{_syscall}"'

        # bpftrace
        elif instrumentation_backend == InstrumentationBackend.EBPF:
            expected_output_value = "1" if allow else "2"
            _module_name = (
                f'"{module_name}"'
                if module_name is not None
                else '@globals["current_module"]'
            )
            syscalls_filter += f"@syscalls_filters[{_module_name}, {_syscall_number}] = {expected_output_value};"
            syscalls_filter += "\n\t"
        else:
            raise NotImplementedError(
                f"backend '{instrumentation_backend}' is not supported"
            )

        filter_name = "allowlist" if allow else "blocklist"
        print(
            f"[debug] adding syscall {_syscall} to {filter_name} for module {module_name}"
        )
    return syscalls_filter


def build_module_sandbox_from_yaml_template(
    template_path: Path,
    backend: InstrumentationBackend = DEFAULT_BACKEND,
):
    """Generates sandbox code for secure imports based on a YAML configuration.

    Args:
        template_path (Path): The path to the YAML file, describing the policies.
        templates_dir (Path, optional): The directory of the templates. Defaults to TEMPLATES_DIR_NAME.

    Raises:
        ModuleNotFoundError:

    Returns:
        _type_: str
    """
    assert Path(
        template_path
    ).exists(), f"The template does not exist at {template_path}"
    import yaml

    safe_yaml = yaml.safe_load(open(template_path, "r").read())
    parsed_probes = []
    syscalls_filter = ""
    # Adding the general syscalls filter
    syscalls_filter += render_syscalls_filter(
        syscalls_list=INSECURE_SYSCALLS,
        allow=False,
        instrumentation_backend=InstrumentationBackend.EBPF,
        module_name="general_requirements",
    )

    for module_name, module_config in safe_yaml.get("modules", {}).items():
        # Finding the module without loading
        module = importlib.machinery.PathFinder().find_spec(module_name)
        if module is None:
            pass
            # raise ModuleNotFoundError(msg)

        # Tracing module entrypoint
        module_traced_name = module.origin if module is not None else module_name
        # module_traced_name = os.path.split(module_traced_name)[:-1][0]

        _destructive = module_config.get("destructive")
        assert isinstance(_destructive, bool), ValueError(
            f'The "destructive" field for module {module_name} is empty.'
        )

        _syscall_allowlist = module_config.get("syscall_allowlist")
        assert _syscall_allowlist, ValueError(
            f'The "syscall_allowlist" for module {module_name} is empty.'
        )
        for _ in _syscall_allowlist:
            assert isinstance(_, str), ValueError(
                f'The "syscall_allowlist" field for module {module_name} contains invalid string: {_}'
            )

        if backend == InstrumentationBackend.DTRACE:
            from secimport.backends.dtrace_backend.dtrace_backend import (
                render_dtrace_probe_for_module,
            )

            module_sandbox_probe = render_dtrace_probe_for_module(
                module_name=module_traced_name,
                destructive=_destructive,
                syscalls_allowlist=_syscall_allowlist,
            )
            sandbox_file_name = "default.yaml.template.d"
            script_template = open(
                DTRACE_TEMPLATES_DIR_NAME / sandbox_file_name,
                "r",
            ).read()
        elif backend == InstrumentationBackend.EBPF:
            from secimport.backends.bpftrace_backend.bpftrace_backend import (
                render_bpftrace_probe_for_module,
            )

            module_sandbox_probe = render_bpftrace_probe_for_module(
                module_name=module_traced_name,
                destructive=_destructive,
            )
            # Adding a syscalls filter
            syscalls_filter += render_syscalls_filter(
                syscalls_list=_syscall_allowlist,
                allow=True,
                instrumentation_backend=InstrumentationBackend.EBPF,
                module_name=module_traced_name,
            )
            sandbox_file_name = "default.yaml.template.bt"
            script_template = open(
                BPFTRACE_TEMPLATES_DIR_NAME / sandbox_file_name,
                "r",
            ).read()
        assert module_sandbox_probe, ValueError(
            f"Failed to create a probe for module {module_name}"
        )
        parsed_probes.append(module_sandbox_probe)

    if not parsed_probes:
        print(f"The profile does not contain any modules: {template_path}")
        return
    script_template = script_template.replace("###SYSCALL_FILTER###", syscalls_filter)
    script_template = script_template.replace(
        "###INTERPRETER_PATH###", PYTHON_EXECUTABLE
    )
    probes_code = ("\n" * 2).join(parsed_probes)
    script_template = script_template.replace(
        "###SUPERVISED_MODULES_PROBES###", probes_code
    )
    return script_template
