# secimport
Sandbox for python modules (without changing your code)

## Usage
```python
import secimport
log4j = secimport.secure_import(...)

```

### Hot it works
dtrace

### Is it production-ready?
# TODO: oracle page about security and production usages


### Environment
The only requirement is a python interpreter that was built with --with-dtrace.

```shell
PYTHON_VERSION="3.7.0"
cd /tmp
curl -o Python-$PYTHON_VERSION.tgz https://www.python.org/ftp/python/$PYTHON_VERSION/Python-$PYTHON_VERSION.tgz
tar -xzf Python-$PYTHON_VERSION.tgz
cd Python-$PYTHON_VERSION
./configure --with-dtrace
make
python.exe -m venv ~/venvs/dtrace
source  ~/venvs/dtrace/bin/activate
```