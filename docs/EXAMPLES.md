# secimport Examples
To understand how to trace your process and create custom profiles for modules or applications, please see <a href="TRACING_PROCESSES.md">Tracing Processes</a>

# Prepared Examples
1. Enter a root shell and `export PYTHONPATH=$(pwd)/src:$(pwd)/examples:$(pwd):$PYTHONPATH`<br>
3. Run any of the examples in the following way:


- python - inline imports
- dtrace example sandbox
- bpftrace example sandbox
- Sandbox gemeration from YAML configuration
    - `examples/create_profile_from_yaml.sh`
        - Create a sandbox template code for your app from a single YAML file.
        - See <a href="YAML_PROFILES.md">YAML Profiles Usage</a>