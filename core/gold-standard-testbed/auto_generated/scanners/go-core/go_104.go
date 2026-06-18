// Vulnerable: GO-104
filename := path.Clean(r.URL.Path)
	filename := filepath.Join(root, strings.Trim(filename, "/"))
	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Write(contents)
})
mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Path
