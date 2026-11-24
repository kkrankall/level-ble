"""Print the requirements of the HA components this integration's tests load.

pytest-homeassistant-custom-component installs Home Assistant itself but not
the per-component requirements, and `bluetooth` (plus its `usb` dependency)
needs its own. Reading them from the installed manifests keeps the pins in
step with whatever HA version the test harness pulled in.

    python scripts/ha_component_requirements.py > component_requirements.txt
    pip install -r component_requirements.txt
"""

import json
from pathlib import Path

import homeassistant.components

ROOT = Path(homeassistant.components.__file__).parent
COMPONENTS = ("bluetooth", "usb")

for name in COMPONENTS:
    for req in json.loads((ROOT / name / "manifest.json").read_text()).get("requirements", []):
        print(req)
