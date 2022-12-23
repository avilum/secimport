#!/bin/bash

# Example:
# # ./trace.bt -c 'Python-3.10.0/python examples/python_imports/example.py' -o trace.log

# Open traced python shell
./secimport/profiles/trace.bt -c 'Python-3.10.0/python' -o trace.log

# Parse and print syscalls per module
# cat trace.log | grep -Po "\@modules_syscalls\[\K(.+?)]" | tr -d ']' | sort > traced_modules.log

# Generate security profile from the log
/workspace/Python-3.10.0/python secimport/cli.py compile_sandbox trace.log
# This command can be splitted to 2:
#   Parse traced moduels and syscalls, and then generate sandbox:
#       - Python-3.10.0/python secimport/cli.py profile_from_trace trace.log
#       - Python-3.10.0/python secimport/cli.py sandbox_from_profile traced_modules.yaml

# Run the sandbox
# secimport/profiles/example.bt -c Python-3.10.0/python --unsafe
./traced_modules.bt -c /workspace/Python-3.10.0/python --unsafe