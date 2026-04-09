"""
Adds src/ to sys.path for both pytest and python3 -m unittest discovery.
Loaded by pytest automatically; unittest loads it via the tests/__init__.py shim.
"""
import sys
import os

_SRC = os.path.join(os.path.dirname(__file__), '..', 'src')
if os.path.abspath(_SRC) not in [os.path.abspath(p) for p in sys.path]:
    sys.path.insert(0, os.path.abspath(_SRC))
