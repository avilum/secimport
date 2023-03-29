#!/usr/bin/env bash

# "--unsafe" is required to run system command for remediation.
#            If process termination on violoation is not needed,
#            You can remove this argument.

echo "🚀 Starting secimport sandbox with bpftrace backend, the sandbox should kill the python process..."
bpftrace -c "/workspace/Python-3.10.0/python -c __import__('os').system('ps');__import__('time').sleep(1);print(\"failed.\")" -o sandbox.log secimport/profiles/processing_sandbox.bt --unsafe
echo "🛑 The process was killed, as expected."
echo "🚀 The sandbox bpftrace code is at sandbox.bt"
echo "🚀 The sandbox log is at sandbox.log."
# tail -n 20 sandbox.log
# less +G sandbox.log
