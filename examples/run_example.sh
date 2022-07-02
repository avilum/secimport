 #!/bin/bash

# An example using dtrace as a sandbox
echo "Loading the malicious script using dtrace..."
sudo PYTHONPATH=$(pwd)/src:$PYTHONPATH dtrace -q -s /Users/avilumelsky/Downloads/Python-3.10.0/dtrace-py/py_sandbox/py_sandbox.d -o $OUTPUT_FILE -c "/Users/avilumelsky/Downloads/Python-3.10.0/python.exe /Users/avilumelsky/Downloads/Python-3.10.0/dtrace-py/py_sandbox/examples/malicious.py" || echo "\r\nThe process was killed as expected!\r\n"