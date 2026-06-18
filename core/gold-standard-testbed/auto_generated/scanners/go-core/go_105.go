// Vulnerable: GO-105
req2, err := http.NewRequest("GET", r.URL.Path, nil)
_, err2 := client.Do(req2)
if err2 != nil {
	http.Error(w, err.Error(), 500)
	return
}
