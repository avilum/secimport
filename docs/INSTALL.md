# Installation
We're about to install dtrace and compile a python interpreter with dtrace enabled.

## Install dtrace
```shell

```  

## Install python with dtrace
```shell
PYTHON_VERSION="3.7.0"

cd /tmp
curl -o Python-$PYTHON_VERSION.tgz https://www.python.org/ftp/python/$PYTHON_VERSION/Python-$PYTHON_VERSION.tgz
tar -xzf Python-$PYTHON_VERSION.tgz
cd Python-$PYTHON_VERSION && ./configure --with-dtrace && make

python3 -m venv ~/venvs/dtrace
source ~/venvs/dtrace/bin/activate
```

You can proceed to EXAMPLES.md