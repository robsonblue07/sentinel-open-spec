"""Keep this tree's imports on the extracted packages, not the private engine."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
root_text = str(ROOT)
sys.path[:] = [entry for entry in sys.path if entry != root_text]
sys.path.insert(0, root_text)
