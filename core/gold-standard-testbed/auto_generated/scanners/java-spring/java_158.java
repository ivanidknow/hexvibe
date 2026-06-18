// Vulnerable: JAVA-158
await page.evaluate('alert(' + body + ')');
    await page.screenshot({path: 'example.png'});
    await browser.close();
    res.send('Hello World!');
}
app.post('/test2', controller)
app.post('/ok-test', async (req, res) => {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
