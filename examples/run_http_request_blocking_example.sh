#!/bin/bash
if [ `whoami` != root ]; then
    echo Please run this script as root or using sudo.
    exit
fi

echo "Testing http request..."
source ~/venvs/dtrace/bin/activate

# An example using using implicit python code
pkill -9 dtrace
PYTHONPATH=$(pwd)/src:$PYTHONPATH python $(pwd)/examples/http_request_with_secure_import.py || echo "The process was killed as expected!"
pkill -9 dtrace