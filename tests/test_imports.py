import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import main
import modules.crtsh
import modules.cve_correlation
import modules.techdetect
import modules.portscan

print("OK: imports principais passaram")
