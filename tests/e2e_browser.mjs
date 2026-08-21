/*
STRIDE-Lite Browser E2E

puppeteer-core drives the Mac Chrome binary against the local GUI on
127.0.0.1:8765. Named steps push BEGIN/OK/FAIL into a timeline; assert()
records without aborting so one broken view does not skip the rest. I
wrote this since e2e_chrome.py dump-dom never clicks the vault tree,
score tabs, or the mobile nav.

Notes:
- Chrome is the Mac default binary; the GUI has to already be listening.
- Atlas step asserts NOT PUBLIC and no UBS/ORC strings (employer leak).
- The scenario-outline jump returns quietly if the fixture tree has no
  matching note — that is intentional.

## Author Information
- **Author**: Nic Cravino
- **Email**: spidernic@me.com
- **LinkedIn**: https://www.linkedin.com/in/nic-cravino
- **Date**: August 2026

## License: Apache License 2.0
*/
import puppeteer from "puppeteer-core";

// Constants for Chrome binary and the local GUI (8765 — same as gui.py)
// TODO(nic): CHROME is the Mac Applications path; no env override if you install elsewhere
const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const BASE = process.env.STRIDE_GUI_URL || "http://127.0.0.1:8765";
const failures = [];
const steps = [];

// Function to record a failed assertion without aborting the rest of the run
function assert(cond, msg) {
  if (!cond) failures.push(msg);
}

// Headless Chrome via puppeteer-core (system binary — no bundled Chromium)
const browser = await puppeteer.launch({
  executablePath: CHROME,
  headless: "new",
  args: ["--no-first-run", "--disable-gpu"],
});

const page = await browser.newPage();
page.setDefaultTimeout(12000);
// Page errors and console.error go into steps so the JSON report is a timeline
page.on("pageerror", (err) => steps.push("PAGEERROR " + err.message));
page.on("console", (msg) => {
  if (msg.type() === "error") steps.push("CONSOLE " + msg.text());
});

// Function to wrap a named check (BEGIN/OK/FAIL — keep going after a throw)
async function step(name, fn) {
  steps.push("BEGIN " + name);
  try {
    await fn();
    steps.push("OK " + name);
  } catch (error) {
    failures.push(name + ": " + error.message);
    steps.push("FAIL " + name + " " + error.message);
  }
}

try {
  await step("selftest", async () => {
    await page.goto(`${BASE}/selftest.html`, { waitUntil: "domcontentloaded" });
    await page.waitForFunction(() => document.body.dataset.status, { timeout: 10000 });
    const self = await page.$eval("#results", (el) => el.textContent);
    const summary = JSON.parse(self);
    if (summary.failed !== 0) throw new Error(self);
  });

  await step("home boot", async () => {
    await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
    await page.waitForFunction(() => document.getElementById("boot")?.classList.contains("done"), { timeout: 10000 });
    const brand = await page.$eval(".brand b", (el) => el.textContent);
    if (!brand.includes("STRIDE-LITE")) throw new Error(brand);
  });

  await step("views", async () => {
    for (const view of ["overview", "model", "scenario", "reports", "activity", "vault", "atlas", "about"]) {
      await page.evaluate((name) => window.go(name), view);
      const active = await page.$eval(`#view-${view}`, (el) => el.classList.contains("active"));
      if (!active) throw new Error("not active " + view);
    }
  });

  await step("forms", async () => {
    await page.evaluate(() => window.go("model"));
    const cmdb = await page.$eval("#cmdb-id", (el) => el.options.length);
    if (cmdb < 1) throw new Error("cmdb empty");
    const label = await page.$eval("#view-model label", (el) => el.textContent);
    if (!/Application ID/i.test(label)) throw new Error("expected Application ID label, got " + label);
    await page.evaluate(() => window.go("scenario"));
    const templates = await page.$eval("#attack-template", (el) => el.options.length);
    if (templates < 1) throw new Error("templates empty");
    const feed = await page.$("#cve-feed");
    if (!feed) throw new Error("cve-feed missing");
  });

  await step("vault tree", async () => {
    await page.evaluate(() => window.go("vault"));
    await page.waitForFunction(() => document.querySelectorAll("#vault-tree .tree-item").length > 5, { timeout: 10000 });
  });

  await step("vault select", async () => {
    const info = await page.evaluate(() => {
      const btn = document.querySelector("#vault-tree .tree-item");
      if (!btn) return { error: "no tree item" };
      btn.click();
      return {
        text: btn.textContent,
        title: document.getElementById("vault-note-title")?.textContent,
      };
    });
    if (info.error) throw new Error(info.error);
    await page.waitForFunction(() => document.getElementById("vault-note-title").textContent !== "Select a node", { timeout: 8000 });
  });

  await step("catalog polar map", async () => {
    await page.evaluate(() => window.go("vault"));
    await page.waitForFunction(() => document.querySelectorAll("#vault-spider .spider-dot").length >= 20, { timeout: 10000 });
    const polar = await page.$eval("#vault-spider svg", (el) => el.getAttribute("data-layout"));
    if (polar !== "polar") throw new Error("expected polar layout " + polar);
    const clicked = await page.evaluate(() => {
      const dots = [...document.querySelectorAll("#vault-spider .spider-dot")];
      const mnpi = dots.find((el) => (el.getAttribute("data-id") || "").includes("mnpi-exfil"));
      if (!mnpi) return false;
      mnpi.dispatchEvent(new MouseEvent("click", { bubbles: true }));
      return true;
    });
    if (!clicked) throw new Error("MNPI dot missing");
    await page.waitForFunction(() => /MNPI Exfil/.test(document.getElementById("vault-note-title")?.textContent || ""), { timeout: 8000 });
  });

  await step("catalog ternary map", async () => {
    await page.evaluate(() => document.getElementById("vault-layout-ternary")?.click());
    await page.waitForFunction(() => document.querySelector("#vault-spider .spider-triangle"), { timeout: 8000 });
    const layout = await page.$eval("#vault-spider svg", (el) => el.getAttribute("data-layout"));
    if (layout !== "ternary") throw new Error("expected ternary layout " + layout);
    await page.evaluate(() => document.getElementById("vault-layout-polar")?.click());
    await page.waitForFunction(() => document.querySelector("#vault-spider svg")?.getAttribute("data-layout") === "polar");
  });

  await step("local mode still network", async () => {
    await page.evaluate(() => document.getElementById("vault-mode-local")?.click());
    const hidden = await page.$eval("#vault-spider", (el) => el.hidden);
    if (!hidden) throw new Error("spider still visible in local");
    const netHidden = await page.$eval("#vault-network", (el) => el.hidden);
    if (netHidden) throw new Error("network hidden in local");
    await page.evaluate(() => document.getElementById("vault-mode-vault")?.click());
    const spiderHidden = await page.$eval("#vault-spider", (el) => el.hidden);
    if (spiderHidden) throw new Error("spider hidden in vault");
  });

  // Score SVG is the proof the killchain note actually mounted
  await step("killchain score views", async () => {
    await page.evaluate(() => window.go("vault"));
    await page.waitForFunction(() => document.querySelectorAll("#vault-tree .tree-item").length > 5);
    const clicked = await page.evaluate(() => {
      const items = [...document.querySelectorAll("#vault-tree .tree-item")];
      const kill = items.find((el) => (el.textContent || "").trim() === "Zero-Day Exploit [New]");
      if (!kill) return false;
      kill.click();
      return true;
    });
    if (!clicked) throw new Error("zero-day killchain not in tree");
    await page.waitForFunction(() => document.querySelector("#score-root svg"), { timeout: 8000 });
    const tabs = await page.$$eval("#score-root [data-view]", (els) => els.map((el) => el.getAttribute("data-view")));
    if (!tabs.includes("grid")) throw new Error("no score tab " + tabs.join(","));
    if (tabs.includes("sequence")) {
      await page.evaluate(() => document.querySelector('#score-root [data-view="sequence"]')?.click());
      await page.waitForFunction(() => document.querySelector('#score-root [data-view="sequence"]')?.classList.contains("active"));
    }
    if (tabs.includes("storyboard")) {
      await page.evaluate(() => document.querySelector('#score-root [data-view="storyboard"]')?.click());
    }
    await page.evaluate(() => document.querySelector('#score-root [data-view="grid"]')?.click());
  });

  await step("compare", async () => {
    const before = await page.evaluate(() => ({
      a: document.getElementById("compare-a")?.options.length,
      b: document.getElementById("compare-b")?.options.length,
    }));
    if (!before.a || !before.b) throw new Error("compare selects empty " + JSON.stringify(before));
    await page.evaluate(() => {
      document.getElementById("compare-go").click();
    });
    await page.waitForFunction(() => {
      const el = document.getElementById("vault-compare-out");
      return el && !el.hidden && el.textContent.length > 8;
    }, { timeout: 8000 });
    await page.waitForFunction(() => document.querySelector("#score-compare-root svg"), { timeout: 8000 });
  });

  // Outline jump is optional — fixture trees without a scenario note just return
  await step("scenario outline jump", async () => {
    const opened = await page.evaluate(() => {
      const items = [...document.querySelectorAll("#vault-tree .tree-item")];
      const scenario = items.find((el) => /zero-day|scenario/i.test(el.textContent || "") && !/killchain/i.test(el.parentElement?.textContent || ""));
      const fallback = items.find((el) => el.closest(".vault-tree") && /Zero-Day_Exploit/i.test(el.textContent || ""));
      const btn = fallback || scenario;
      if (!btn) return false;
      btn.click();
      return true;
    });
    if (!opened) return;
    await page.waitForFunction(() => document.getElementById("vault-note-title")?.textContent !== "Select a node");
    const jumped = await page.evaluate(() => {
      const item = document.querySelector("#vault-outline .outline-item[data-heading]");
      if (!item) return "no-outline";
      item.click();
      return item.dataset.heading;
    });
    if (jumped && jumped !== "no-outline") {
      await page.waitForFunction((id) => document.querySelector(`[data-heading="${id}"]`), {}, jumped);
    }
  });

  await step("quality", async () => {
    await page.evaluate(() => document.getElementById("vault-quality-btn").click());
    const visible = await page.$eval("#vault-quality", (el) => !el.hidden);
    if (!visible) throw new Error("quality hidden");
  });

  await step("switcher", async () => {
    await page.evaluate(() => document.getElementById("vault-switcher-btn").click());
    const open = await page.$eval("#switcher", (el) => !el.hidden);
    if (!open) throw new Error("switcher closed");
    await page.keyboard.press("Escape");
  });

  // Phone viewport: side nav should flatten to a row, then restore desktop
  await step("mobile", async () => {
    await page.setViewport({ width: 390, height: 844 });
    await page.evaluate(() => window.go("overview"));
    const dir = await page.$eval("nav.side", (el) => getComputedStyle(el).flexDirection);
    if (dir !== "row") throw new Error("nav " + dir);
    await page.setViewport({ width: 1280, height: 800 });
  });

  // Atlas copy must stay fictional — NOT PUBLIC, and no employer names
  await step("atlas copy", async () => {
    await page.evaluate(() => window.go("atlas"));
    const text = await page.$eval("#view-atlas", (el) => el.innerText);
    if (!/NOT PUBLIC/.test(text)) throw new Error("missing not public");
    if (/UBS|ORC/.test(text)) throw new Error("employer leak");
  });

  await step("reports", async () => {
    await page.evaluate(() => window.go("reports"));
    const rows = await page.$$eval("#reports-table tr", (els) => els.length);
    if (rows < 1) throw new Error("no report rows");
  });
} finally {
  // Always close Chrome even if a waitForFunction timed out
  await browser.close();
}

// JSON report on stdout; non-zero exit if anything landed in failures
const report = { failed: failures.length, failures, steps };
console.log(JSON.stringify(report, null, 2));
process.exit(failures.length ? 1 : 0);
