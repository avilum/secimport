<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Python Interpreter Requirements](#python-interpreter-requirements)
- [OS requirements](#os-requirements)
  - [Install `bpftrace` (for Linux)](#install-bpftrace-for-linux)
  - [Install `dtrace` (for Mac, Solaris, Windows)](#install-dtrace-for-mac-solaris-windows)
    - [Using Docker: bpftrace (Linux, Mac)](#using-docker-bpftrace-linux-mac)
- [Install Python with USDT probes and openssl (from source): ~5 minutes](#install-python-with-usdt-probes-and-openssl-from-source-5-minutes)
  - [Test the interpreter](#test-the-interpreter)
  - [Run `secimport` Tests](#run-secimport-tests)
- [What's Next?](#whats-next)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->


# Python Interpreter Requirements
The only runtime requirement is a Python interpreter that was built with --with-dtrace (USDT probes).<br>
You can check if your current interpreter supported by running this command:
```python
python -m sysconfig | grep WITH_DTRACE
```
This configuration option should have the value "1" (and not "0"!):
```
	WITH_DTRACE = "1"
```
If your current interpreter is not supported (empty output):
- Using `pip`
  - `python3 -m pip install secimport`
- Using `poetry`
  - `python3 -m pip install poetry && python3 -m poetry build`
<br><br>

# OS requirements
## Install `bpftrace` (for Linux)
Install bpftrace toolkit from https://github.com/iovisor/bpftrace/blob/master/INSTALL.md .
Then, proceed to the python interpreter.

## Install `dtrace` (for Mac, Solaris, Windows)
Some distributions include dtrace. check the `dtrace` command. If it is not installed:
```shell
yum install dtrace-utils
```

### Using Docker: bpftrace (Linux, Mac)
the `docker/` folder includes everything in the following guide.
To build and run using docker, see <a href="../docker/">Docker</a>,
<br><br>

# Install Python with USDT probes and openssl (from source): ~5 minutes
If you want to use pip to work properly with pypi, you should also install openssl.
To support ssl in this interpreter, One can simply install openssl pacakge using apt/yum/apk and it will use it automatically.<br>
If you wish to build openssl from source

Download and build openssl
```shell
wget https://www.openssl.org/source/openssl-1.1.1h.tar.gz
tar -xvf openssl-1.1.1h.tar.gz
cd openssl-1.1.1h
./config --prefix=$(pwd)/openssl --openssldir=$(pwd)/openssl
make
make test
make install
```

Download python
```shell
PYTHON_VERSION="3.11.8"

cd /tmp
curl -o Python-$PYTHON_VERSION.tgz https://www.python.org/ftp/python/$PYTHON_VERSION/Python-$PYTHON_VERSION.tgz
tar -xzf Python-$PYTHON_VERSION.tgz
```

If you want to use a custom OpenSSL version/installation, edit the `OPENSSL` variable in Modules/Setup:<br>

```shell
$ nano Python-$PYTHON_VERSION/Modules/Setup

OPENSSL=/path/to/openssl-1.1.1h/openssl
_ssl _ssl.c \
    -I$(OPENSSL)/include -L$(OPENSSL)/lib \
    -lssl -lcrypto


# Configuring and install with dtrace, pip and openssl
cd Python-$PYTHON_VERSION && ./configure --with-dtrace  --prefix=$(pwd) --with-ensurepip=install && make

# Optionsl: test your build
make test

# Optional: Install alongside your existing python without replacing it.
make altinstall
```

<br><br>
## Test the interpreter
```shell
➜  Python-3.11.8 ./python

Python 3.11.8 (default, Jul  6 2022, 09:21:12) [Clang 13.0.0 (clang-1300.0.27.3)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> import ssl
>>> # You're good to go!
```
<br><br>

## Run `secimport` Tests
```shell
python3 -m pytest
```

<br><br>
# What's Next?
You can proceed to <a href="EXAMPLES.md">EXAMPLES.md</a>
