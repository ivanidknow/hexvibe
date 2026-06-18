// Vulnerable: GO-118
telnet.DialToAndCall("example.net:23", caller)
}
func ok1() {
	tlsConfig := &tls.Config{}
	var caller telnet.Caller = telnet.StandardCaller
