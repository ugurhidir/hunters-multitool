#!/usr/bin/env python3

import sys
import os

# Add the source directory to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__))))

from src.cli import cli

if __name__ == "__main__":
    cli() 