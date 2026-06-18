// Vulnerable: GO-099
io.WriteString(w, fmt.Sprintf("Invalid token: %q", tok))
  }
  // ...
}
// cf. https://github.com/hashicorp/vault-plugin-database-mongodbatlas//blob/9cf156a44f9c8d56fb263f692541e5c7fbab9ab1/vendor/golang.org/x/net/http2/server.go#L2160
func handleHeaderListTooLong(w http.ResponseWriter, r *http.Request) {
	const statusRequestHeaderFieldsTooLarge = 431
	w.WriteHeader(statusRequestHeaderFieldsTooLarge)
