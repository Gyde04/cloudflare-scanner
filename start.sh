#!/bin/bash

# Activate virtual environment
source venv/bin/activate

# Get the directory of this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Change to the script directory
cd "$DIR"

# Run the application
python run.py 