#!/usr/bin/env python3

import sys
import os

# Add the parent directory to the module path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.cli import cli

if __name__ == "__main__":
    cli() 