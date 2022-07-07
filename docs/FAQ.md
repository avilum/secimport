
## Is it safe to use in production?
From <a href="https://en.wikipedia.org/wiki/DTrace">Wikipedia</a>:
>Special consideration has been taken to make DTrace safe to use in a production environment. For example, there is minimal probe effect when tracing is underway, and no performance impact associated with any disabled probe; this is important since there are tens of thousands of DTrace probes that can be enabled. New probes can also be created dynamically.

## Why not eBPF?
- `dtrace` is cross platform and been around for decades. `eBPF is newer.`
- Dtrace has destructive flags that are easy to use
- eBPF requires a kernel with eBPF support.
  - `dtrace` is a solution that everyone could use, not limited to pretty-new linux kernels.
  - `dtrace` has vast languages support for future work (supported in more languages), compared to eBPF.
  - `dscript` s are easier to write than `eBPF kernels`.

## What are the tradeoffs? How does it change they way I code?
- You need can use `secimport` in 2 ways:
  - Compile a dtrace script for your configuration, and use dtrace to run your python process as a parent process
  - use `secimport.secure_import` function in your code to import module. A dtrace process is opened upon `secure_import()` call.

## What are the performance impacts?
- See docs/PERFORMANCE.md