// Vulnerable: VUL-CVE-2021-37692
raw := tensorData(t.c)

	runtime.SetFinalizer(t, func(t *Tensor) {
		if dataType == String {
			t.clearTStrings(raw, nflattened)
...
	runtime.SetFinalizer(t, func(t *Tensor) {
		if dataType == String {
			t.clearTStrings(raw, nflattened)
		}

...
	_, err := w.Write(b)
	return err
}
