<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Performance Benchmarks](#performance-benchmarks)
- [Numpy specific benchmark (compute and not IO bound)](#numpy-specific-benchmark-compute-and-not-io-bound)
  - [Python 3.10 without dtrace](#python-310-without-dtrace)
  - [DTrace interpreter without secimport](#dtrace-interpreter-without-secimport)
  - [DTrace interpreter with secimport](#dtrace-interpreter-with-secimport)
- [PyTorch Example](#pytorch-example)

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

# PyTorch Example
Inference Code (taken from https://pytorch.org/tutorials/beginner/pytorch_with_examples.html#pytorch-custom-nn-modules):
```python
# -*- coding: utf-8 -*-
import time
import torch
import math
#import os

class Polynomial3(torch.nn.Module):
    def __init__(self):
        """
        In the constructor we instantiate four parameters and assign them as
        member parameters.
        """
        super().__init__()
        self.a = torch.nn.Parameter(torch.randn(()))
        self.b = torch.nn.Parameter(torch.randn(()))
        self.c = torch.nn.Parameter(torch.randn(()))
        self.d = torch.nn.Parameter(torch.randn(()))

    def forward(self, x):
        """
        In the forward function we accept a Tensor of input data and we must return
        a Tensor of output data. We can use Modules defined in the constructor as
        well as arbitrary operators on Tensors.
        """
#        import os; os.system('ps')
        return self.a + self.b * x + self.c * x ** 2 + self.d * x ** 3

    def string(self):
        """
        Just like any class in Python, you can also define custom method on PyTorch modules
        """
        return f'y = {self.a.item()} + {self.b.item()} x + {self.c.item()} x^2 + {self.d.item()} x^3'

start_time = time.time()
# Create Tensors to hold input and outputs.
x = torch.linspace(-math.pi, math.pi, 2000)
y = torch.sin(x)

# Construct our model by instantiating the class defined above
model = Polynomial3()

# Construct our loss function and an Optimizer. The call to model.parameters()
# in the SGD constructor will contain the learnable parameters (defined
# with torch.nn.Parameter) which are members of the model.
criterion = torch.nn.MSELoss(reduction='sum')
optimizer = torch.optim.SGD(model.parameters(), lr=1e-6)
for t in range(2000):
    # Forward pass: Compute predicted y by passing x to the model
    y_pred = model(x)

    # Compute and print loss
    loss = criterion(y_pred, y)
    if t % 100 == 99:
        print(t, loss.item())

    # Zero gradients, perform a backward pass, and update the weights.
    optimizer.zero_grad()
    loss.backward()
    optimizer.step()

print(f'Result: {model.string()}')
print("--- %s seconds ---" % (time.time() - start_time))
```

Without secimport
```python
root@3ecd9c9b5613:/workspace# Python-3.11.8/python pytorch_example.py
99 674.6323852539062
199 454.4176025390625
299 307.2438659667969
399 208.82205200195312
499 142.95999145507812
599 98.85627746582031
699 69.30175018310547
799 49.48223876953125
899 36.18083953857422
999 27.246694564819336
1099 21.241012573242188
1199 17.200336456298828
1299 14.479386329650879
1399 12.645381927490234
1499 11.408075332641602
1599 10.57250690460205
1699 10.00766372680664
1799 9.625473022460938
1899 9.366581916809082
1999 9.19102668762207
Result: y = -0.013432367704808712 + 0.8425596952438354 x + 0.0023173068184405565 x^2 + -0.09131323546171188 x^3
--- 0.6940326690673828 seconds ---
```

With secimport
```python
root@3ecd9c9b5613:/workspace# secimport run --entrypoint pytorch_example.py
 >>> secimport run
 RUNNING SANDBOX... ['./sandbox.bt', '--unsafe', ' -c ', 'bash -c "/workspace/Python-3.11.8/python pytorch_example.py"']
Attaching 4 probes...
99 3723.3251953125
199 2513.790283203125
299 1699.73388671875
399 1151.3519287109375
499 781.596435546875
599 532.0443115234375
699 363.45361328125
799 249.44357299804688
899 172.26437377929688
999 119.9627914428711
1099 84.48213958740234
1199 60.386112213134766
1299 44.003780364990234
1399 32.853240966796875
1499 25.255172729492188
1599 20.07185935974121
1699 16.531814575195312
1799 14.111299514770508
1899 12.45437240600586
1999 11.318828582763672
Result: y = -0.04061822220683098 + 0.8255564570426941 x + 0.007007318548858166 x^2 + -0.08889468014240265 x^3
--- 0.8806719779968262 seconds ---

SANDBOX EXITED;
```
