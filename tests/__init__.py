"""
Bootstrap sys.path for python3 -m unittest discover -s tests.

The root oneinfinity.py shim shadows the src/oneinfinity/ package when
'' (cwd) is in sys.path before src/. This file ensures src/ is at
position 0 so the package is always found first.
"""
import sys
import os

_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src'))

# Strip '' and '.' — they point to repo root where oneinfinity.py lives
sys.path = [p for p in sys.path if p not in ('', '.')]

# Move src/ to position 0 (may already be present from editable-install .pth)
while _SRC in sys.path:
    sys.path.remove(_SRC)
sys.path.insert(0, _SRC)

# If oneinfinity was already cached as the shim script, evict it
if 'oneinfinity' in sys.modules:
    mod = sys.modules['oneinfinity']
    if getattr(mod, '__file__', '').endswith('oneinfinity.py'):
        to_del = [k for k in sys.modules if k == 'oneinfinity' or k.startswith('oneinfinity.')]
        for k in to_del:
            del sys.modules[k]
