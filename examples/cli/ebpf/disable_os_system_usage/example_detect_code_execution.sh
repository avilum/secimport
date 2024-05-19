#!/usr/bin/env bash

# "--unsafe" is required to run system command for remediation.
#            If process termination on violoation is not needed,
#            You can remove this argument.

echo "Starting secimport sandbox with python shell..."
bpftrace -c "/workspace/Python-3.11.8/python -c __import__('os').system('ps')" -o sandbox.log sandbox.bt --unsafe

# The process is killed becused we ran os.system inside our sandbox.
# Watch the logs:
less +G sandbox.log
# OR:
# tail -n 20 sandbox.log
echo "The sandbox log is at ./sandbox.log"
