"""Let the standalone tools import the integration's stdlib-only modules.

custom_components/level_ble/__init__.py imports Home Assistant, so the tools
load keychain.py and const.py as top-level modules instead of through the
package. Those two files must stay standard-library only.
"""

from __future__ import annotations

import sys
from pathlib import Path

INTEGRATION_DIR = Path(__file__).resolve().parents[1] / "custom_components" / "level_ble"
if str(INTEGRATION_DIR) not in sys.path:
    sys.path.insert(0, str(INTEGRATION_DIR))
