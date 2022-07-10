# How to run an example
1. Enter a root shell and `export PYTHONPATH=$(pwd)/src:$(pwd)/examples:$(pwd):$PYTHONPATH`<br>
2. Make sure the python interpreter you use was compiled with `dtrace`.
3. Run any of the examples in the following way:
- `(root) sh-3.2#  python examples/malicious_with_secure_import.py`

## Available scripts:
- Python (import inline):
    -  `requests` example - secure import vs regular import (Killed because of socket related syscall)
        - `python examples/http_request.py` 
        - `python examples/http_request_with_secure_import.py`
        - ```
            from secimport import secure_import
            import requests
            
            requests.get('https://google.com')
            <Response [200]>
            
            requests = secure_import('requests', allow_networking=False)

            requests.get('https://google.com')
            [1]    86664 killed
            ```
    - 
    - `python examples/malicious.py` 
    - `python examples/malicious_with_secure_import.py`
    - 
    - `python examples/example.py`
    - `python examples/production.py`
    - 
    - `python numpy_example.py`
    - `python numpy_example_with_secure_import.py`
    - 

- Bash / CLI:
    - `examples/run_dtrace_example.sh`
    - `examples/run_http_request_blocking_example.sh`
    - `examples/run_shell_blocking_example.sh`

# Tracing processes
  - Using `dtrace`
    - Tracing the syscalls of a process with pid `12345`
      - `dtrace -n 'syscall::: /pid == ($1)/ {@[pid,execname,probefunc]=count()}' 12345`
    - Tracing the syscalls of a docker container with pid `12345`
      - `dtrace -n 'syscall::: /progenyof($1)/ {@[pid,execname,probefunc]=count()}' 12345`
  - Using `strace`
    -  A script to list all your application's syscalls using `strace`.<br> I contributed it to `firejail` a few years ago:
      - https://github.com/netblue30/firejail/blob/master/contrib/syscalls.sh
      - ```
        wget "https://raw.githubusercontent.com/netblue30/firejail/c5d426b245b24d5bd432893f74baec04cb8b59ed/contrib/syscalls.sh" -O syscalls.sh

        chmod +x syscalls.sh

        ./syscalls.sh examples/http_request.py
        ```
