 #!/bin/bash
echo "Testing the secure import..."

# An example using using implicit python code
cd src/ && sudo PYTHONPATH=$(pwd)/src:$PYTHONPATH /Users/avilumelsky/Downloads/Python-3.10.0/python.exe /Users/avilumelsky/Downloads/Python-3.10.0/dtrace-py/py_sandbox/examples/malicious_with_secure_import.py || echo "\r\nThe process was killed as expected!\r\n"
