#! /bin/bash

if [[ "$PWD" =~ secimport ]]
then
    echo "Running pre-commit hooks...";
else
    echo "Please run this script from the secimport root directory.";
    exit 1;
fi

# Lint and fix code styling
python3 -m ruff --fix .
./scripts/update_docs_table_of_contents.sh
pre-commit
export PYTHONPATH=$(pwd):$PYTHONPATH

# Run tests with coverate
# coverage run -m pytest tests
# coverage report -m --skip-empty --omit="*/tests/*"

# Build docker
cd docker/
./build.sh


# Run unit tests inside container
# cd ..
# export KERNEL_VERSION=`docker run --rm -it alpine uname -r | cut -d'-' -f1`
docker run --rm --name=secimport --privileged -v "$(pwd)/secimport":"/workspace/secimport/" -v "$(pwd)/tests":"/workspace/tests/" -v "$(pwd)/../scripts":"/workspace/scripts/" -it secimport /bin/bash -c /workspace/setup.sh
