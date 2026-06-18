// Vulnerable: GO-080
cgi.Serve(http.FileServer(http.Dir("/usr/share/doc")))
}
func main2() {
