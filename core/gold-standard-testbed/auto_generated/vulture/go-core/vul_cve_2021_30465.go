// Vulnerable: VUL-CVE-2021-30465
return err
		}
		m.Destination = dest
		if err := os.MkdirAll(dest, 0755); err != nil {
			return err
...
	defer func() {
		for _, u := range umounts {
			if e := unix.Unmount(u, unix.MNT_DETACH); e != nil {
				if e != unix.EINVAL {
					// Ignore EINVAL as it means 'target is not a mount point.'
...
// --- utils_test.go ---
	}
}
