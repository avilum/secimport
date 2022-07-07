# Performance Benchmarks
- examples/numpy_example.py
- examples/numpy_example_with_secure_import.py

## Python 3.10 without dtrace
```
Dotted two 4096x4096 matrices in 0.78 s.
Dotted two vectors of length 524288 in 0.08 ms.
SVD of a 2048x1024 matrix in 0.56 s.
Cholesky decomposition of a 2048x2048 matrix in 0.09 s.
Eigendecomposition of a 2048x2048 matrix in 5.04 s.
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