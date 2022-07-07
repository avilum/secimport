# Examples
Python (import inline):
- `examples/http_request_with_secure_import.py`
- `examples/malicious_with_secure_import.py`
- `requests` example - secure import vs regular import (Killed because of socket related syscall)
  - ```
    from secimport import secure_import
    import requests
    
    requests.get('https://google.com')
    <Response [200]>
     
    requests = secure_import('requests', allow_networking=False)

    requests.get('https://google.com')
    [1]    86664 killed
    ```

Bash / CLI:
- `examples/run_dtrace_example.sh`
- `examples/run_http_request_blocking_example.sh`
- `examples/run_shell_blocking_example.sh`