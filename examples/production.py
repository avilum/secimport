from secimport import secure_import 

example = secure_import('example', allow_shells=False)
print('Example imported successfully')

 # Expected output:
"""
(root) sh-3.2#  export PYTHONPATH=$(pwd)/src:$(pwd)/examples:$(pwd):$PYTHONPATH
(root) sh-3.2#  python examples/production.py 
Successfully compiled dtrace profile:  /tmp/.secimport/sandbox_example.d
(running dtrace supervisor):  sudo  dtrace -q -s /tmp/.secimport/sandbox_example.d -p 6484 -o /tmp/.secimport/sandbox_example.log &2>/dev/null
Killed: 9
"""

