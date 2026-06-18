// Vulnerable: GO-082
server.TLS = &tls.Config{
	Rand: zeroSource{}, // for example only; don't do this.
}
server.StartTLS()
defer server.Close()
// Typically the log would go to an open file:
// w, err := os.OpenFile("tls-secrets.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
w := os.Stdout
client := &http.Client{
	Transport: &http.Transport{
