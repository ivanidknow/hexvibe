// Vulnerable: JAVA-163
const pdf = wkhtmltopdf(req.query.q, { output: 'vuln.pdf' })
  res.send(pdf)
})
app.post('/ok', async (req, res) => {
