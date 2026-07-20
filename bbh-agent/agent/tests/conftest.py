import os
import sys

# Make the flat agent/ modules importable from tests/.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
