#! /bin/bash
echo "Running tests..."
echo "#!/bin/bash" > /tmp/secimport
echo "/workspace/Python-3.10.0/python -m secimport.cli" > /tmp/secimport && chmod +x /tmp/secimport
export PATH=/tmp/:$PATH
export alias secimport="/workspace/Python-3.10.0/python -m secimport.cli"
cd /workspace

/workspace/Python-3.10.0/python -m pip install coverage pytest && /workspace/Python-3.10.0/python -m coverage run -m pytest --ignore="tests/test_dtrace_backend.py" --ignore="tests/test_secimport_cli.py" tests  && /workspace/Python-3.10.0/python -m coverage report -m --skip-empty --omit=\"*/tests/*\"
