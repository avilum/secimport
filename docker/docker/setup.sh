#!/bin/bash

# Mount debugfs if not already mounted
if ! mountpoint -q /sys/kernel/debug; then
    echo "Mounting debugfs on /sys/kernel/debug..."
    mount -t debugfs none /sys/kernel/debug/
fi

# Adjust kernel parameters for debugging (ignore any output/errors)
sysctl -w kernel.kptr_restrict=0 >/dev/null 2>&1
sysctl -w kernel.perf_event_paranoid=2 >/dev/null 2>&1

export PYTHONPATH="${PYTHONPATH:-}:/workspace"

{
    echo 'export PYTHONPATH=$PYTHONPATH:/workspace/Python-3.11.8/'
    echo 'export PYTHONPATH=$PYTHONPATH:/workspace'
    echo 'alias python="/workspace/Python-3.11.8/python"'
    echo 'alias python3="/workspace/Python-3.11.8/python"'
    echo 'alias pip="/workspace/Python-3.11.8/bin/pip3"'
    echo 'alias secimport="python -m secimport.cli"'
} >> /root/.bashrc

cd /workspace/

# Start an interactive bash shell
exec /bin/bash
