// Vulnerable: VUL-CVE-2023-25153
}

func onUntarJSON(r io.Reader, j interface{}) error {
	b, err := io.ReadAll(r)
...

func onUntarJSON(r io.Reader, j interface{}) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, j)
}
