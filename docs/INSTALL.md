# Installation
We're about to install dtrace and compile a python interpreter with dtrace enabled.

# Using Docker: bpftrace (Linux, Mac)
the `docker/` folder includes everything in the following guide.
To build and run using docker, see <a href="../docker/">Docker</a>,

# From Source: dtrace (Mac, Solaris, Windows)

## Install dtrace
Some distributions include dtrace. check the `dtrace` command. If it is not installed:
```shell
yum install dtrace-utils
```  

## Install Python with dtrace and openssl

### Install OpenSSL from source
```shell
wget https://www.openssl.org/source/openssl-1.1.1h.tar.gz
tar -xvf openssl-1.1.1h.tar.gz
cd openssl-1.1.1h
./config --prefix=$(pwd)/openssl --openssldir=$(pwd)/openssl
make
make test
make install
```

### Or, Install openssl


### Install python
```shell
PYTHON_VERSION="3.10.0"

cd /tmp
curl -o Python-$PYTHON_VERSION.tgz https://www.python.org/ftp/python/$PYTHON_VERSION/Python-$PYTHON_VERSION.tgz
tar -xzf Python-$PYTHON_VERSION.tgz

# If you want to use pip, you should also install openssl (above); 
$ nano Python-$PYTHON_VERSION/Modules/Setup

# Edit the `OPENSSL` variable in Modules/Setup:
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

# Test the interpreter
```shell
➜  Python-3.10.0 ./python.exe

Python 3.10.0 (default, Jul  6 2022, 09:21:12) [Clang 13.0.0 (clang-1300.0.27.3)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> import ssl
>>> # You're good to go!

```

## Creating a virtual environment
```shell
./python3.exe -m venv ~/venvs/dtrace
source ~/venvs/dtrace/bin/activate
```
You can proceed to <a href="EXAMPLES.md">EXAMPLES.md</a>

# Tests
`python3 -m pytest`
or 
`python3 -m pytest tests`
