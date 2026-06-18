// Vulnerable: GO-110
var text = fmt.Sprintf('
	<html>
	<head>
	<title>SSTI</title>
	</head>
	<body>
		<h2>Hello {{ .Email }}</h2>
		<p>Search result for %s</p>
	</body></html>
	', query)
...
	var user1 = &User{1, "user@gmail.com", "Sup3rSecr3t123!"}
	query := "constant string"
