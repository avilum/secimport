# Try secimport with bpftrace

## How to Use

1. Install Docker: https://docs.docker.com/get-docker
2. `./build.sh`
    - will build a docker image with
        - python with dtrace static USDT instrumentations
        - bpftrace
        - secimport code
    - ~1GB in size
3. `./run.sh` will start a new docker container with secimport.
    - `secimport-shell` or `./trace.sh` will open a syscall-tracing python shell.
        - All syscalls and modules will be logged to traced_modules.json once you hit CTRL+D.
    - `./run_sandbox.sh` will run a python script inside the sandbox `sandbox.bt`.
      -   It will execute `os.system('ps')`, and the process will be killed.
        - Logs will be written to `sandbox.log`
    - You can use `-v` in docker run to mount your code into the container and trace it. See `./run.sh`

## FAQ

### How it runs on macOS?
- The Docker for mac runs Linux on a hypervisor called hyperkit, and docker runs inside it, so you can use Linux features.

### Can we trace a macOS host with this docker?
- Not at the moment. The bpftrace runs inside a Linux VM. 
- For macOS, there is dtrace.

=====================

Based on the great example repo: https://github.com/mmisono/try-bpftrace-in-mac
