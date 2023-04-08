#!/bin/bash
echo "Generating a profile from example yaml..."
python examples/yaml_template/create_profile_from_yaml.py secimport/profiles/example.yaml /tmp/example.d
