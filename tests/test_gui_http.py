#!/usr/bin/env python3
"""
STRIDE-Lite GUI HTTP Smoke Tests

Unittest client against the local stdlib GUI. Default target is
http://127.0.0.1:8765; set STRIDE_GUI_URL if yours lives elsewhere.
If the port is already bound I reuse that process; otherwise I spawn
src/python/gui.py for the class and kill only that child at teardown.
Covers static pages, vendor JS, workspace redaction on /api/status,
vault counts, kill-chain compare, and /selftest.html.

Notes:
- I wrote this since a browser is overkill for "are the pages and JSON
  endpoints actually serving". The rest of the Python tests already
  run under unittest.
- Key Changes: skip spawn when 8765 is live; fail early if the child
  never opens the port (~4s of 0.1s polls).

## Author Information
- **Author**: Nic Cravino
- **Email**: spidernic@me.com
- **LinkedIn**: https://www.linkedin.com/in/nic-cravino
- **Date**: August 2026

## License: Apache License 2.0
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

# Constants for repo root and GUI base URL (override with STRIDE_GUI_URL)
ROOT = Path(__file__).resolve().parents[1]
GUI_URL = os.environ.get("STRIDE_GUI_URL", "http://127.0.0.1:8765")


# Function to check if the GUI port is already bound (reuse a live server)
def _port_open(host: str, port: int) -> bool:
    with socket.socket() as sock:
        sock.settimeout(0.3)
        return sock.connect_ex((host, port)) == 0


# Function to GET a path off GUI_URL (status, content-type, raw body)
def _get(path: str):
    with urllib.request.urlopen(GUI_URL + path, timeout=8) as response:
        salida = response.read()
        return response.status, response.headers.get_content_type(), salida


class GuiHttpTests(unittest.TestCase):
    server: subprocess.Popen | None = None

    # Reuse a live GUI on GUI_URL; fail early after ~4s of polls
    # TODO(nic): stderr is DEVNULL so spawn failures currently look like a timeout
    @classmethod
    def setUpClass(cls):
        parsed = urlparse(GUI_URL)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 8765
        if _port_open(host, port):
            return
        cls.server = subprocess.Popen(
            [sys.executable, "src/python/gui.py", "--host", host, "--port", str(port)],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(40):
            if _port_open(host, port):
                return
            time.sleep(0.1)
        raise RuntimeError("GUI did not start")

    # Terminate only the child I started; a pre-existing GUI is left running
    @classmethod
    def tearDownClass(cls):
        if cls.server:
            cls.server.terminate()
            cls.server.wait(timeout=5)

    # Static assets — 200 and a content-type that matches the suffix
    def test_pages(self):
        for path, ctype in [("/", "text/html"), ("/styles.css", "text/css"), ("/app.js", "text/javascript")]:
            status, got, salida = _get(path)
            self.assertEqual(status, 200)
            self.assertIn(ctype.split("/")[1], got)
            self.assertGreater(len(salida), 100)

    def test_vendor(self):
        status, _, salida = _get("/vendor/vis-network.min.js")
        self.assertEqual(status, 200)
        self.assertGreater(len(salida), 10000)

    # /api/status workspace must not echo $HOME (privacy / path leak)
    def test_status_workspace_hides_home(self):
        _, _, raw = _get("/api/status")
        status = json.loads(raw)
        workspace = status["workspace"]
        self.assertTrue(workspace)
        self.assertNotIn("/Users/", workspace)
        home = os.path.expanduser("~")
        self.assertFalse(workspace.startswith(home))

    # Vault inventory plus compare (jaccard is the smoke field)
    def test_vault_and_compare(self):
        _, _, raw = _get("/api/vault")
        vault = json.loads(raw)
        self.assertEqual(vault["counts"]["killchains"], 37)
        kill = next(node for node in vault["nodes"] if node["type"] == "killchain")
        self.assertIn(kill["props"]["slice"], {"identity", "exploit", "espionage", "cloud-api", "agent-ai", "ransomware"})
        _, _, raw = _get("/api/killchains")
        catalog = json.loads(raw)
        self.assertEqual(len(catalog["catalog_map"]["points"]), 37)
        self.assertEqual(len(catalog["catalog_map"]["slices"]), 6)
        _, _, raw = _get("/api/killchains/catalog-map")
        cmap = json.loads(raw)
        self.assertEqual(len(cmap["points"]), 37)
        _, _, raw = _get("/api/killchains/compare?a=Zero-Day%20Exploit%20%5BNew%5D&b=LockBit%20Ransomware%20Attack")
        cmp = json.loads(raw)
        self.assertIn("jaccard", cmp)

    def test_spider_asset(self):
        status, ctype, salida = _get("/spider.js")
        self.assertEqual(status, 200)
        self.assertIn("javascript", ctype)
        self.assertIn(b"CatalogMap", salida)

    def test_selftest_page(self):
        status, _, salida = _get("/selftest.html")
        self.assertEqual(status, 200)
        self.assertIn(b"STRIDE-Lite selftest", salida)


if __name__ == "__main__":
    unittest.main(verbosity=2)
