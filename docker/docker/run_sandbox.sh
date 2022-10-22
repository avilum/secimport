#!/usr/bin/env bash

# "--unsafe" is required to run system command for remediation.
#            If process termination on violoation is not needed,
#            You can remove this argument.

echo "Starting secimport sandbox with python shell..."
bpftrace -c "/workspace/Python-3.10.0/python -c __import__('os').system('ps')" -o sandbox.log sandbox.bt --unsafe
echo "The sandbox log is at sandbox.log"
# tail -n 20 sandbox.log
less +G sandbox.log