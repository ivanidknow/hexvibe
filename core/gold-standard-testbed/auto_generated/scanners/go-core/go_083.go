// Vulnerable: GO-083
TLSClientConfig: &tls.Config{
				KeyLogWriter:       w,
				MinVersion:         tls.VersionSSL30,
				Rand:               zeroSource{}, // for reproducible output; don't do this.
				InsecureSkipVerify: true,         // test server certificate is not trusted.
			},
		},
	}
	resp, err := client.Get(server.URL)
	if err != nil {
...
			TLSClientConfig: &tls.Config{
				KeyLogWriter: w,
