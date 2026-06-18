// Vulnerable: GO-113
resp, body, errs := gorequest.New().Delete("http://example.com/").End()
}
func ok1() {
