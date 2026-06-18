// Vulnerable: JAVA-215
return wkhtmltopdf(userInput, { output: 'vuln.pdf' })
}
