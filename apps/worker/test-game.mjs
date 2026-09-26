import { chromium } from "playwright";

const errors = [];
const browser = await chromium.launch({
  headless: true,
  args: [
    "--use-gl=angle",
    "--use-angle=swiftshader",
    "--enable-unsafe-swiftshader",
    "--no-sandbox",
  ],
});
const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
page.on("console", (msg) => {
  if (msg.type() === "error") errors.push("console: " + msg.text().slice(0, 300));
});
page.on("pageerror", (err) => errors.push("pageerror: " + String(err).slice(0, 300)));
page.on("requestfailed", (req) =>
  errors.push("reqfail: " + req.url().slice(0, 120) + " " + (req.failure()?.errorText || ""))
);

const result = { steps: [] };
try {
  await page.goto("http://127.0.0.1:8931/", { waitUntil: "load", timeout: 30000 });
  await page.waitForFunction(
    () => {
      const l = document.getElementById("loading");
      const m = document.getElementById("menu");
      return (l && getComputedStyle(l).display === "none") || (m && !m.hidden);
    },
    undefined,
    { timeout: 90000 }
  );
  result.steps.push("boot: menu visible");
  await page.waitForTimeout(2000);
  await page.screenshot({ path: "/tmp/fc-menu.png" });
  result.steps.push("screenshot: /tmp/fc-menu.png");

  result.trackTabs = await page.locator("#track-tabs button").count();
  await page.click("#track-next");
  await page.waitForTimeout(800);
  await page.screenshot({ path: "/tmp/fc-format.png" });
  await page.click('#race-formats button[data-format="0"]');
  await page.click("#format-next");
  await page.waitForTimeout(800);
  await page.screenshot({ path: "/tmp/fc-weekend.png" });
  result.startVisible = await page.locator("#start").isVisible();
  await page.click("#start");
  // race scene boot: wait for canvas to have non-trivial size and some seconds of sim
  await page.waitForTimeout(20000);
  await page.screenshot({ path: "/tmp/fc-race.png" });
  result.steps.push("screenshot: /tmp/fc-race.png");
  result.canvas = await page.evaluate(() => {
    const c = document.getElementById("scene");
    if (!c) return "no-canvas";
    return { w: c.width, h: c.height };
  });
  result.hudText = (await page.locator("body").innerText()).slice(0, 200);
} catch (e) {
  result.steps.push("FAILED: " + String(e).slice(0, 400));
  try {
    await page.screenshot({ path: "/tmp/fc-fail.png" });
    result.steps.push("failshot: /tmp/fc-fail.png");
  } catch {}
  result.loadingText = await page.evaluate(() => document.getElementById("loading-text")?.textContent || "n/a").catch(() => "n/a");
}
result.errors = errors.slice(0, 15);
console.log(JSON.stringify(result, null, 2));
await browser.close();
