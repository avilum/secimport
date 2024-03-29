#!/bin/bash
if [ `whoami` != root ]; then
    echo Please run this script as root or using sudo.
    exit
fi

echo "Running the malicious module with dtrace..."

# An example using dtrace as a sandbox
pkill -9 dtrace
PYTHONPATH=$(pwd):$PYTHONPATH dtrace -s $(pwd)/templates/py_sandbox.d -c "python $(pwd)/examples/malicious.py"
pkill -9 dtrace
