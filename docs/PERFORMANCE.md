<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Performance Benchmarks](#performance-benchmarks)
- [Numpy specific benchmark (compute and not IO bound)](#numpy-specific-benchmark-compute-and-not-io-bound)
  - [Python 3.10 without dtrace](#python-310-without-dtrace)
  - [DTrace interpreter without secimport](#dtrace-interpreter-without-secimport)
  - [DTrace interpreter with secimport](#dtrace-interpreter-with-secimport)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Performance Benchmarks
- ./python -m pyperformance run

# Numpy specific benchmark (compute and not IO bound)
- examples/numpy_example.py
- examples/numpy_example_with_secure_import.py

## Python 3.10 without dtrace
```
Dotted two 4096x4096 matrices in 0.78 s.
Dotted two vectors of length 524288 in 0.08 ms.
SVD of a 2048x1024 matrix in 0.56 s.
Cholesky decomposition of a 2048x2048 matrix in 0.09 s.
```

## DTrace interpreter without secimport
```
Dotted two 4096x4096 matrices in 0.95 s.
Dotted two vectors of length 524288 in 0.16 ms.
SVD of a 2048x1024 matrix in 0.58 s.
Cholesky decomposition of a 2048x2048 matrix in 0.09 s.
```

## DTrace interpreter with secimport
```
Dotted two 4096x4096 matrices in 0.88 s.
Dotted two vectors of length 524288 in 0.14 ms.
SVD of a 2048x1024 matrix in 0.56 s.
Cholesky decomposition of a 2048x2048 matrix in 0.09 s.
```
