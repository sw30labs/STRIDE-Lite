#!/usr/bin/env python3
"""
Headless Chrome Selftest for STRIDE-Lite GUI

Headless Chrome against the local GUI's /selftest.html page. I dump the DOM,
pull the JSON out of the results <pre>, and exit non-zero if the in-page
checks failed or never ran. I wrote this since a 200 from the GUI does not
prove the browser-side assertions executed.

Notes:
- Chrome is the Mac default binary; the GUI has to already be listening on 8765.
- dump-dom is written to /tmp so a missing results block is inspectable.

## Author Information
- **Author**: Nic Cravino
- **Email**: spidernic@me.com
- **LinkedIn**: https://www.linkedin.com/in/nic-cravino
- **Date**: August 2026

## License: Apache License 2.0
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

# Constants for Chrome binary and the local selftest URL
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
URL = "http://127.0.0.1:8765/selftest.html"


# Headless dump-dom of /selftest.html (GUI must already be listening on 8765)
def main() -> int:
    proc = subprocess.run(
        [
            CHROME,
            "--headless=new",
            "--disable-gpu",
            "--no-first-run",
            "--user-data-dir=/tmp/stride-lite-chrome-selftest",
            "--virtual-time-budget=20000",
            "--dump-dom",
            URL,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    html = proc.stdout
    # Persist dump-dom so a failed parse is inspectable
    Path("/tmp/stride-lite-selftest.html").write_text(html)
    match = re.search(r'<pre id="results">\s*(\{.*?\})\s*</pre>', html, re.S)
    # Fail early — no results JSON means Chrome never hit the page
    if not match:
        print("FAIL: no results JSON in dump-dom")
        print(proc.stderr[-2000:])
        return 1
    salida = json.loads(match.group(1))
    print(json.dumps(salida, indent=2))
    if salida.get("failed"):
        return 1
    if "SELFTEST PASS" not in html and salida.get("passed", 0) < 1:
        return 1
    print("CHROME SELFTEST PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
