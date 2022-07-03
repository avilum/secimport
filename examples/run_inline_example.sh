 #!/bin/bash
echo "Testing the secure import..."
source ~/venvs/dtrace/bin/activate

# An example using using implicit python code
pkill -9 dtrace
PYTHONPATH=$(pwd)/src:$PYTHONPATH python $(pwd)/examples/malicious_with_secure_import.py || echo "The process was killed as expected!"
pkill -9 dtrace