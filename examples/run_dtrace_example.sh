#!/bin/bash
if [ `whoami` != root ]; then
    echo Please run this script as root or using sudo.
    exit
fi

echo "Running the malicious module with dtrace..."
source ~/venvs/dtrace/bin/activate

# An example using dtrace as a sandbox
pkill -9 dtrace
PYTHONPATH=$(pwd)/src:$PYTHONPATH dtrace -s $(pwd)/templates/py_sandbox.d -c "python $(pwd)/examples/malicious.py" || echo "The process was killed as expected!"
pkill -9 dtrace