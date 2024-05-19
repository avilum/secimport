<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Is it safe to use in production?](#is-it-safe-to-use-in-production)
- [Should I use dtrace or bpftrace backend?](#should-i-use-dtrace-or-bpftrace-backend)
- [What are the tradeoffs? How does it change they way I code?](#what-are-the-tradeoffs-how-does-it-change-they-way-i-code)
- [On Ubuntu, I get the error message `ERROR: Could not resolve symbol: /proc/self/exe:BEGIN_trigger`](#on-ubuntu-i-get-the-error-message-error-could-not-resolve-symbol-procselfexebegin_trigger)
- [What are the performance impacts?](#what-are-the-performance-impacts)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->


## Is it safe to use in production?
From <a href="https://en.wikipedia.org/wiki/DTrace">Wikipedia</a>:
>Special consideration has been taken to make DTrace safe to use in a production environment. For example, there is minimal probe effect when tracing is underway, and no performance impact associated with any disabled probe; this is important since there are tens of thousands of DTrace probes that can be enabled. New probes can also be created dynamically.

## Should I use dtrace or bpftrace backend?
- `dtrace` is cross platform and been around for decades. `eBPF is newer.`
- Dtrace has destructive flags that are easy to use
- bpftrace (eBPF) requires a kernel with eBPF support.
  - `dtrace` is a solution that everyone could use on legacy Solaris, Mac and Windows.
    - `dtrace` has vast languages support for future work (supported in more languages), compared to eBPF.
    - `dscript` s are easier to write than `eBPF kernels`.

## What are the tradeoffs? How does it change they way I code?
- You need can use `secimport` in 2 ways:
  - Use `secimport.secure_import` function in your code to import module. A dtrace process is opened upon `secure_import()` call.
  - Compile a sandbox script for your configuration, and use the sandbox backend to run your python process as a supervisor parent process.
    - YAML templates
    - Allowlist / Blocklist
      - Allow only a set of syscalls for each module in you would like to confine. Log/Kill upon violation.

## On Ubuntu, I get the error message `ERROR: Could not resolve symbol: /proc/self/exe:BEGIN_trigger`
You must install additional debugging symbols using these commmands:

    echo "deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse
    deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted universe multiverse
    deb http://ddebs.ubuntu.com $(lsb_release -cs)-proposed main restricted universe multiverse" | \
    sudo tee -a /etc/apt/sources.list.d/ddebs.list
    sudo apt install ubuntu-dbgsym-keyring
    sudo apt update
    sudo apt install bpftrace-dbgsym

## What are the performance impacts?
- See docs/PERFORMANCE.md
