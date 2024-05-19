#!/bin/bash


echo "FastAPI Example"
echo "Tracing the main application, hit CTRL+C/CTRL+D when you are done."
/workspace/Python-3.11.8/python -m secimport.cli trace --entrypoint fastapi_main.py
/workspace/Python-3.11.8/python -m secimport.cli build
/workspace/Python-3.11.8/python -m secimport.cli run --entrypoint fastapi_main.py
