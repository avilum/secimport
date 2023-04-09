#! /bin/bash
echo "Running tests..."
echo "#! /bin/bash \\n\
/workspace/Python-3.10.0/python -m secimport.cli" > /tmp/secimport && chmod +x /tmp/secimport
export PATH=/tmp/:$PATH
export alias secimport="/workspace/Python-3.10.0/python -m secimport.cli"
cd /workspace
/workspace/Python-3.10.0/python -m pip install coverage pytest && /workspace/Python-3.10.0/python -m coverage run -m pytest tests && /workspace/Python-3.10.0/python -m coverage report -m --skip-empty --omit=\"*/tests/*\"
