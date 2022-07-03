 #!/bin/bash
echo "Testing the secure import..."

# An example using using implicit python code
source ~/venvs/dtrace/bin/activate
PYTHONPATH=$(pwd)/src:$PYTHONPATH python $(pwd)/examples/malicious_with_secure_import.py || echo "\r\nThe process was killed as expected!\r\n"
