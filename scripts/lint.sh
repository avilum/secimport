#! /bin/bash

if [[ "$PWD" =~ secimport ]]
then
    echo "Running pre-commit hooks...";
else
    echo "Please run this script from the secimport root directory.";
    exit 1;
fi

python3 -m ruff --fix .
doctoc
git add .
pre-commit
export PYTHONPATH=$(pwd):$PYTHONPATH
python3 -m pytest tests/
