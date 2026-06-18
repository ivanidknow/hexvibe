// Vulnerable: GO-111
mTLSConfig := &tls.Config {
    }
    mTLSConfig.PreferServerCipherSuites = true
    mTLSConfig.InsecureSkipVerify = true
}
func ok1() {
    w := os.Stdout
	client := &http.Client{
		Transport: &http.Transport{
