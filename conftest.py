"""
Pytest configuration file.
Adds the project root to sys.path for imports.
"""

import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))