#!/bin/sh
mount -t debugfs none /sys/kernel/debug/
sysctl -w kernel.kptr_restrict=0 >/dev/null 2>&1
sysctl -w kernel.perf_event_paranoid=2 >/dev/null 2>&1

export PYTHONPATH=$PYTHONPATH:/workspace
echo 'export PYTHONPATH=$PYTHONPATH:/workspace/Python-3.10.0/python' >> /root/.bashrc && \
echo 'export PYTHONPATH=$PYTHONPATH:/workspace' >> /root/.bashrc && \
echo 'alias python="/workspace/Python-3.10.0/python"' >> /root/.bashrc && \
echo 'alias python3="/workspace/Python-3.10.0/python"' >> /root/.bashrc && \
echo 'alias pip="/workspace/Python-3.10.0/bin/pip3"' >> /root/.bashrc && \
echo 'alias secimport="python -m secimport.cli"' >> /root/.bashrc

cd /workspace/
/bin/bash
