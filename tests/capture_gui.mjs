/*
STRIDE-Lite GUI Screenshot Capturer

Headless Chrome via puppeteer-core. Walks the local GUI on 8765 and
writes PNG stills into assets/ for the README. I wrote this since a
phone photo of the desktop looked worse than a 2x 1440x900 capture.

Notes:
- Chrome is the Mac default binary; the GUI has to already be listening
  on 8765 (`python src/python/gui.py`, then `node tests/capture_gui.mjs`).
- Views: overview, threat-model, about, vault, then vault with the
  Zero-Day kill-chain score pane open.
- deviceScaleFactor 2 so the README PNGs stay sharp.

## Author Information
- **Author**: Nic Cravino
- **Email**: spidernic@me.com
- **LinkedIn**: https://www.linkedin.com/in/nic-cravino
- **Date**: August 2026

## License: Apache License 2.0
*/
import puppeteer from "puppeteer-core";
import { mkdir } from "node:fs/promises";
import path from "node:path";

// Constants for Chrome binary, local GUI URL, and the assets/ folder
const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const BASE = "http://127.0.0.1:8765";
const OUT = path.resolve("assets");

const browser = await puppeteer.launch({
  executablePath: CHROME,
  headless: "new",
  args: ["--no-first-run", "--disable-gpu"],
  defaultViewport: { width: 1440, height: 900, deviceScaleFactor: 2 },
});
const page = await browser.newPage();
page.setDefaultTimeout(15000);

await mkdir(OUT, { recursive: true });
await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
// Fail early — #boot.done never arriving means the GUI never hydrated
await page.waitForFunction(() => document.getElementById("boot")?.classList.contains("done"));

// Function to navigate a GUI view and write a PNG (400ms settle so CSS/layout finish)
async function shot(view, file, extra) {
  await page.evaluate((name) => window.go(name), view);
  await new Promise((resolve) => setTimeout(resolve, 400));
  if (extra) await extra();
  await page.screenshot({ path: path.join(OUT, file), type: "png" });
  console.log("wrote", file);
}

await shot("overview", "gui-overview.png");
await shot("model", "gui-threat-model.png");
await shot("about", "gui-about.png");
// Function to click a kill-chain in the vault tree (wait for #score-root svg, then 500ms settle)
async function openKillchain(name) {
  await page.waitForFunction(() => document.querySelectorAll("#vault-tree .tree-item").length > 5);
  const opened = await page.evaluate((wanted) => {
    const items = [...document.querySelectorAll("#vault-tree .tree-item")];
    const exact = items.find((el) => (el.textContent || "").trim() === wanted);
    if (!exact) return false;
    exact.click();
    return true;
  }, name);
  if (!opened) throw new Error("killchain not found: " + name);
  await page.waitForFunction(() => document.querySelector("#score-root svg"), { timeout: 8000 });
  await new Promise((resolve) => setTimeout(resolve, 500));
}

await shot("vault", "gui-vault.png", async () => {
  await openKillchain("Zero-Day Exploit [New]");
});
await shot("vault", "gui-score.png", async () => {
  await openKillchain("Zero-Day Exploit [New]");
});

await browser.close();
console.log("done");
