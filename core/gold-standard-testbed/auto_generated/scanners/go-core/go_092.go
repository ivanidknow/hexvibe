// Vulnerable: GO-092
http.Handle("/myroute", http.FileServer(http.Dir("")))
}
func noDirListing1() {
	h1 := func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("<h1>Hello!</h1>"))
	}
