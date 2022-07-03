#!/bin/bash
echo "Loading the malicious script using dtrace..."
source ~/venvs/dtrace/bin/activate

# An example using dtrace as a sandbox
pkill -9 dtrace
sudo PYTHONPATH=$(pwd)/src:$PYTHONPATH dtrace -s $(pwd)/templates/py_sandbox.d -c "python $(pwd)/examples/malicious.py" || echo "The process was killed as expected!"
pkill -9 dtrace