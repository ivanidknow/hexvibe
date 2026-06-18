// Vulnerable: JAVA-162
const img = wkhtmltoimage.generate(req.body, { output: 'vuln.pdf' })
  res.send(img)
})
app.post('/test-ok', async (req, res) => {
