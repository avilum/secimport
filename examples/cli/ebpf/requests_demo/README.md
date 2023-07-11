# Requests example
```shell
python3 -m pip install requests secimport
```

## Create a security profile for do_request.py
```shell
root@47454e6c2da3:/workspace/examples/cli/ebpf/requests_demo# secimport trace do_request.py

    Tracing using  ['/workspace/secimport/profiles/trace.bt', '-c', 'bash -c "/workspace/Python-3.10.0/python do_request.py"', '-o', 'trace.log']

    Press CTRL+D or CTRL+C to stop the trace gracefully.

200


    The trace log is at  ./trace.log
```

## Build a sandbox
`secimport build` will run ninjail
```shell
root@47454e6c2da3:/workspace/examples/cli/ebpf/requests_demo# secimport build

syscalls:  access,  arch_prctl,  bind,  brk,  clock_gettime,  close,  connect,  dup,  epoll_create1,  exit_group,  fcntl,  fstat,  futex,  getcwd,  getdents64,  getegid,  geteuid,  getgid,  getpeername,  getpid,  getrandom,  getsockname,  getsockopt,  gettid,  getuid,  ioctl,  lseek,  lstat,  mmap,  mprotect,  munmap,  openat,  poll,  pread,  prlimit64,  read,  readlink,  recvfrom,  rt_sigaction,  rt_sigprocmask,  sendto,  set_robust_list,  set_tid_address,  setsockopt,  socket,  stat,  sysinfo,  uname,  write

...
Policy is ready:  policy.yaml policy.json
...
[debug]  '/root/.local/lib/python3.10/site-packages/idna/idnadata.py' is not importable via importlib. Keeping the name as-is.
...
[debug]  adding syscall brk to allowlist for module /workspace/Python-3.10.0/Lib/ssl.py
...
[debug]  adding syscall set_tid_address to allowlist for module general_requirements
...

 syscalls:  syscalls.txt
 nsjail sandbox:  nsjail-seccomp-sandbox.sh
 secimport eBPF sandbox:  sandbox.bt
```

## Run the sandbox
```shell
root@47454e6c2da3:/workspace/examples/cli/ebpf/requests_demo# secimport run --entrypoint do_request.py

RUNNING SANDBOX... ['./sandbox.bt', '--unsafe', ' -c ', 'bash -c "/workspace/Python-3.10.0/python do_request.py"']
Attaching 5 probes...

200

 SANDBOX EXITED;
```
