<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Changelog](#changelog)
  - [References](#references)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Changelog
- ✔️ Added Allow/Block list configuration
- ✔️ Created a .yaml configuration per module in the code
  - ✔️ Use secimport to compile that yml
  - ✔️ Create a single dcript policy
  - ✔️ Run an application with that policy using dtrace, without using `secure_import`
- ✔️ Added eBPF basic support using bpftrace
  - ✔️ bpftrace backend tests
- ✔️ Implemented python USDT probes template
- ✔️ Added CLI for bpftrace backend usage
- ✔️ Updated documentation and improved CLI
- ✔️ Added GIFs

## References
- Read more about the primitives of secimport:
  - `bpftrace` - https://github.com/iovisor/bpftrace
  - `dtrace` - [DTrace Cheatsheet](https://www.brendangregg.com/DTrace/DTrace-cheatsheet.pdf)
    - [DTrace for Linux (2018)](https://www.brendangregg.com/blog/2018-10-08/dtrace-for-linux-2018.html)
- <a href="https://github.com/avilum/secimport/wiki/Sandbox-Examples">Sandbox Examples</a>
- Guides
  - <a href="https://github.com/avilum/secimport/wiki/Tracing-Processes">Tracing Processes Guide</a>
  - <a href="https://github.com/avilum/secimport/wiki/Installation">Installation</a>
  - <a href="https://github.com/avilum/secimport/wiki/YAML-Profiles">Create a Sandbox from YAML file</a>
  - <a href="https://github.com/avilum/secimport/wiki/MacOS-Users">Mac OS Users</a>
  - <a href="https://github.com/avilum/secimport/wiki/F.A.Q">F.A.Q</a>
