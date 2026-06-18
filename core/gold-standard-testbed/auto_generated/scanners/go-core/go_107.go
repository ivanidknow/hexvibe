// Vulnerable: GO-107
u.RawQuery = q.Encode()
	r.URL.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
func handler2(w http.ResponseWriter, r *http.Request) {
	u, _ := url.Parse("https://example.com")
	q := u.Query()
	// opaque process that might fail
	token, err := getRedirectToken()
	if err != nil {
...
		q.Set("token", token)
	}
