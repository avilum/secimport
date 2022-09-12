# secimport Examples
To understand how to trace your process and create custom profiles for modules or applications, please see <a href="TRACING_PROCESSES.md">Tracing Processes</a>

# Prepared Examples
1. Enter a root shell and `export PYTHONPATH=$(pwd)/src:$(pwd)/examples:$(pwd):$PYTHONPATH`<br>
2. Make sure the python interpreter you use was compiled with `dtrace`.
3. Run any of the examples in the following way:

- YAML to Sandbox Example
    - `examples/create_profile_from_yaml.sh`
        - Create a sandbox template code for your app from a single YAML file.
        - See <a href="YAML_PROFILES.md">YAML Profiles Usage</a>
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
    - Malicious Example
        - `python examples/malicious.py` 
        - `python examples/malicious_with_secure_import.py`
    - Hello World Example
        - `python examples/production.py`
        - `python examples/example.py`
    - Numpy Example
        - `python numpy_example.py`
        - `python numpy_example_with_secure_import.py`

- Bash / CLI:
    - `examples/run_dtrace_example.sh`
    - `examples/run_http_request_blocking_example.sh`
    - `examples/run_shell_blocking_example.sh`
