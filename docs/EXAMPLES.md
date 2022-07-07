# How to run an example
1. Enter a root shell and `export PYTHONPATH=$(pwd)/src:$(pwd)/examples:$(pwd):$PYTHONPATH`<br>
2. Make sure the python interpreter you use was compiled with `dtrace`.
3. Run any of the examples in the following way:
- `(root) sh-3.2#  python examples/production.py`

## Available examples:
- Python (import inline):
    -  `requests` example - secure import vs regular import (Killed because of socket related syscall)
        - `examples/http_request.py` 
        - `examples/http_request_with_secure_import.py`
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
    - `examples/malicious.py` 
    - `examples/malicious_with_secure_import.py`
    - 
    - `examples/example.py`
    - `examples/production.py`
    - 
    - `numpy_example.py`
    - `numpy_example_with_secure_import.py`
    - 

Bash / CLI:
- `examples/run_dtrace_example.sh`
- `examples/run_http_request_blocking_example.sh`
- `examples/run_shell_blocking_example.sh`