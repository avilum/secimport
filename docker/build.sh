#!/bin/bash

if [[ "$PWD" =~ docker$ ]]
then
    echo "Building secimport docker container...";
else
    echo "Please run this script from the secimport/docker directory.";
    exit 1;
fi

# Using a custom linukit kernel version that matches the current kernel;
# KERNEL_VERSION=`docker run --rm -it alpine uname -r | cut -d'-' -f1`
KERNEL_VERSION="5.10.76"

echo "USING KERNEL $KERNEL_VERSION"
BPFTRACE_VERSION=${BPFTRACE_VERSION:-v0.16.0}
PYTHON_VERSION=${PYTHON_VERSION:-"3.10.0"}

pushd docker

docker build \
    --build-arg KERNEL_VERSION=${KERNEL_VERSION} \
    --build-arg BPFTRACE_VERSION=${BPFTRACE_VERSION} \
    --build-arg PYTHON_VERSION=${PYTHON_VERSION} \
    -t secimport:${KERNEL_VERSION} .

popd

echo "You can now use the ./run.sh script to try secimport."
