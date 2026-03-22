// Intentionally vulnerable browser automation snippets.
// Do NOT use in production.

const { chromium } = require("playwright");

async function run(url, request) {
  // Vulnerable: BRW-001 (Launch without sandbox)
  const browser = await chromium.launch({
    args: ["--no-sandbox", "--disable-setuid-sandbox"],
    headless: true,
  });

  // Vulnerable: BRW-003 (Headful in production)
  const browserHeadful = await chromium.launch({ headless: false });

  // Vulnerable: BRW-002 (ignoreHTTPSErrors enabled)
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();

  // Vulnerable: BRW-006 (Disable Chromium security flags)
  const weakBrowser = await chromium.launch({
    args: ["--disable-web-security", "--disable-site-isolation-trials"],
  });
  await weakBrowser.close();

  // Vulnerable: BRW-004 (WebRTC metadata leakage)
  await page.evaluate(() => new RTCPeerConnection().createOffer());

  // Vulnerable: BRW-005 (User-controlled JS execution)
  const userJs = request.body.script;
  await page.evaluate(userJs);

  // Vulnerable: BRW-007 (file:// allowed)
  const target = request.query.url;
  await page.goto(target);

  // Vulnerable: BRW-008 (SSRF via browser navigation)
  await page.goto(url);

  // Vulnerable: BRW-009 (Context leak and no timeout)
  const leakContext = await browser.newContext();
  const leakPage = await leakContext.newPage();
  await leakPage.goto(url);

  // Vulnerable: BRW-010 (Auto downloads enabled and MIME unchecked)
  const downloadContext = await browser.newContext({ acceptDownloads: true });
  const downloadPage = await downloadContext.newPage();
  await downloadPage.goto(url);
  const download = await downloadPage.waitForEvent("download");
  const path = await download.path();

  // Vulnerable: BRW-011 (DOM XSS via innerHTML)
  const note = request.body.note;
  await page.evaluate((value) => {
    document.querySelector("#out").innerHTML = value;
  }, note);

  // Vulnerable: BRW-012 (JS Injection via eval/new Function)
  const script = request.body.script;
  await page.evaluate((s) => eval(s), script);
  const fn = new Function(script);
  fn();

  // Vulnerable: BRW-013 (Prototype Pollution)
  const patch = request.body.patch;
  const config = {};
  config.__proto__ = patch;
  Object.assign(config, patch);

  await browserHeadful.close();
  await context.close();
  await browser.close();
  return { downloadedPath: path };
}

module.exports = { run };

