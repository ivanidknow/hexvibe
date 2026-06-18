// Vulnerable: JAVA-206
const browser = await chromium.launch({args:['--remote-debugging-port=${port}','--somethin-else']});
  const page = await browser.newPage();
  await page.goto('https://example.com');
  await browser.close();
})();
(async () => {
