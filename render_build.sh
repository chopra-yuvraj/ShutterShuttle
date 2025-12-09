#!/usr/bin/env bash
# Exit on error
set -o errexit

# Upgrade pip to ensure wheel support
pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt

# Run database initialization
python init_db.py