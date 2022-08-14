#!/bin/bash
echo "Generating a profile from example yaml..."
python examples/create_profile_from_yaml.py src/secimport/profiles/example.yaml /tmp/example.d
