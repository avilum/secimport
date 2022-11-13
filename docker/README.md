# Try secimport with bpftrace

## How to Use

1. Install Docker: https://docs.docker.com/get-docker
2. ./build.sh
    - will build a docker image with
        - python with dtrace static USDT instrumentations
        - bpftrace
        - secimport code
    - ~1GB in size
3. ./run.sh
    - Runs temporary example sandbox using bpftrace
    - Then, it will execute os.system('ps').
      -  the process should be killed.
    - Once the process is killed, it prints the logs of the sandbox.


## FAQ

### How it runs on macOS?
- The Docker for mac runs Linux on a hypervisor called hyperkit, and docker runs inside it, so you can use Linux features.

### Can we trace a macOS host with this docker?
- Not at the moment. The bpftrace runs inside a Linux VM. 
- For macOS, there is dtrace.

=====================

Based on the great example repo: https://github.com/mmisono/try-bpftrace-in-mac
