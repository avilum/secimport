#!/bin/bash

if [[ "$PWD" =~ docker$ ]]
then
    cd ..
fi


if [[ "$PWD" =~ secimport$ ]]
then
    echo "Running temporary secimport container...";
    docker run --rm --name=secimport -p 8000:8000 --privileged -v "$(pwd)/secimport":"/workspace/secimport/" -v "$(pwd)/examples":"/workspace/examples/" -v "$(pwd)/scripts":"/workspace/scripts/" -v "$(pwd)/tests":"/workspace/tests/" -it secimport
else
    echo "Please run this script from the secimport directory.";
    exit 1;
fi
