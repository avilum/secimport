 #!/bin/bash

# An example using dtrace as a sandbox
source ~/venvs/dtrace/bin/activate
echo "Loading the malicious script using dtrace..."
sudo PYTHONPATH=$(pwd)/src:$PYTHONPATH dtrace -s $(pwd)/templates/py_sandbox.d -o $OUTPUT_FILE -c "python /Users/avilumelsky/git/secimport/examples/malicious.py" || echo "\r\nThe process was killed as expected!\r\n"

# sudo dtrace -s $(pwd)/templates/py_sandbox.d -c "/Users/avilumelsky/Downloads/Python-3.10.0/python.exe $(pwd)/examples/malicious.py"