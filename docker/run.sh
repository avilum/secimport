#!/bin/bash

if [[ "$PWD" =~ docker$ ]]
then
    echo "Running temporary container...";
else
    echo "Please run this script from the secimport/docker directory.";
    exit 1;
fi

KERNEL_VERSION=`docker run --rm -it alpine uname -r | cut -d'-' -f1`

cd .. # back to repo root dir
# Add your code dir with -v
docker run --rm --name=secimport --privileged -v "$(pwd)/secimport":"/workspace/secimport/" -v "$(pwd)/examples":"/workspace/examples/" -it secimport:${KERNEL_VERSION}
